/**
 * ObliWAN — a fake CLI router over real SSH, for `applyOverSsh()`.
 *
 * WHY THIS EXISTS
 * `applyOverSsh()` carried this comment since the day it was written:
 *
 *     HONESTY NOTE, LOAD-BEARING: never executed. No DrayTek, Zyxel or
 *     SonicWall exists on this machine or in this test suite. […] Treat the
 *     first real push as the first test.
 *
 * That is a bad place for the write path of three of the four brands to sit.
 * The function is not hard to be wrong about in ways a reading does not catch:
 * it drives an INTERACTIVE shell, decides a command finished by matching a
 * prompt at the end of a growing buffer, and reports `applied` / `failedAt`
 * from that. Every one of those is a place where an off-by-one silently
 * reports "12 lines applied" on a device that took 3 — and §8.3 builds a
 * rollback decision on that number.
 *
 * So: a REAL ssh2 server, a real TCP socket, a real interactive channel. Not a
 * stub of the transport — the transport, with a fake router behind it. Same
 * doctrine as `fakeRouterosServer.ts` (proves the wire) and
 * `fakeDeadmanRouter.ts` (proves the milestone).
 *
 * WHAT IT DELIBERATELY DOES NOT CLAIM
 * The prompt strings and error phrases below are plausible, not authoritative:
 * they come from documentation, exactly like the ones in `applyOverSsh()`. This
 * harness proves the FUNCTION is correct given a device that behaves like this.
 * It does not prove a Vigor behaves like this. Those are two different claims
 * and conflating them is how a green suite ships a lockout.
 */

import { randomBytes, generateKeyPairSync } from 'crypto';
import type { AddressInfo } from 'net';

/** How the fake answers one command. */
export interface FakeSshBehaviour {
  /** Lines whose text matches this are answered with `errorText`. */
  refuse?: RegExp;
  /** What the device prints when it refuses. Must match the caller's
   *  `errorPattern` for the refusal to be detected — proving that pairing is
   *  half the point of this harness. */
  errorText?: string;
  /** Prompt printed after every command. The default looks like a Vigor. */
  prompt?: string;
  /** Answer this many commands, then go silent — a device that wedged
   *  mid-apply. Exercises the timeout path, which is the one that decides
   *  whether a half-applied change is reported as half-applied. */
  silentAfter?: number;
  /** Drop the connection after this many commands, without a prompt. */
  closeAfter?: number;
  /** Split every answer across two TCP writes. A prompt matcher that assumes
   *  one chunk per command passes without this and fails a real network. */
  splitWrites?: boolean;
}

export interface FakeSshRouter {
  port: number;
  /** Every command line the server actually received, in order. THE ground
   *  truth: `applied` is a claim, this is what the device saw. */
  received: string[];
  close: () => Promise<void>;
}

const DEFAULT_PROMPT = '\r\nVigor> ';

/**
 * Start the fake on an ephemeral port.
 *
 * The host key is generated per run rather than committed: a private key in a
 * repository is a private key in a repository, even a throwaway one, and the
 * first person to copy this file into a real fixture would not notice.
 */
export async function startFakeSshRouter(
  behaviour: FakeSshBehaviour = {},
): Promise<FakeSshRouter> {
  // ssh2 is CommonJS, and the CJS->ESM interop is ASYMMETRIC here: under tsx,
  // `Client` is hoisted as a named export and `Server` is NOT — it exists only
  // under `.default`. Destructuring `{ Server }` therefore yields undefined and
  // fails with "Server is not a constructor", which reads like a broken
  // dependency and is really a bundler detail. Both shapes are accepted so this
  // harness behaves the same under `tsx` and under the compiled CJS build.
  const mod = (await import('ssh2')) as unknown as Record<string, unknown>;
  const ns = (mod.default as Record<string, unknown> | undefined) ?? mod;
  const Server = (ns.Server ?? mod.Server) as new (
    cfg: { hostKeys: string[] },
    onClient: (client: any) => void,
  ) => { listen: (p: number, h: string, cb: () => void) => void; address: () => unknown; close: (cb: () => void) => void };
  const prompt = behaviour.prompt ?? DEFAULT_PROMPT;
  const received: string[] = [];

  const { privateKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
    publicKeyEncoding: { type: 'pkcs1', format: 'pem' },
  });

  const server = new Server({ hostKeys: [privateKey] }, (client) => {
    // Authentication is accepted unconditionally. This harness is about the
    // APPLY loop; credential handling is the vault's problem and is tested
    // where the vault is.
    client.on('authentication', (auth: { accept: () => void }) => auth.accept());

    client.on('ready', () => {
      client.on('session', (accept: () => any) => {
        const session = accept();
        // A pty request must be ACCEPTED: `applyOverSsh` asks for `vt100`, and
        // a server that refuses it makes the client fall back in ways no real
        // router does — which would make this harness prove the wrong thing.
        session.once('pty', (acceptPty: unknown) => {
          if (typeof acceptPty === 'function') (acceptPty as () => void)();
        });
        session.once('shell', (accept2: () => any) => {
          const stream = accept2();
          let answered = 0;
          let line = '';

          const write = (text: string) => {
            if (!behaviour.splitWrites || text.length < 2) {
              stream.write(text);
              return;
            }
            const cut = Math.floor(text.length / 2);
            stream.write(text.slice(0, cut));
            setTimeout(() => stream.write(text.slice(cut)), 5);
          };

          // The banner. A real CLI greets before the first prompt, and a
          // matcher that treats the banner's prompt as an answer would count
          // one command too many — which is precisely the off-by-one this
          // harness exists to catch.
          write(prompt);

          stream.on('data', (chunk: Buffer) => {
            line += chunk.toString('utf8');
            let nl: number;
            while ((nl = line.indexOf('\n')) >= 0) {
              const command = line.slice(0, nl).replace(/\r$/, '');
              line = line.slice(nl + 1);
              if (command.trim() === '') continue;
              received.push(command);

              if (behaviour.closeAfter !== undefined && answered >= behaviour.closeAfter) {
                stream.end();
                return;
              }
              if (behaviour.silentAfter !== undefined && answered >= behaviour.silentAfter) {
                return;   // received, never answered: the device wedged
              }

              answered++;
              if (behaviour.refuse?.test(command)) {
                write(`\r\n${behaviour.errorText ?? '% Invalid input detected'}${prompt}`);
              } else {
                write(prompt);
              }
            }
          });
        });
      });
    });

    // A fake that throws on a client disconnect turns every test teardown into
    // an unhandled rejection, which then gets blamed on the code under test.
    client.on('error', () => undefined);
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as AddressInfo).port;

  return {
    port,
    received,
    close: () =>
      new Promise<void>((resolve) => {
        server.close(() => resolve());
      }),
  };
}

/** A password nobody needs to know, so nobody is tempted to reuse one. */
export function throwawaySecret(): string {
  return randomBytes(12).toString('hex');
}
