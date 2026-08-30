/**
 * ObliWAN — RouterOS configuration acquisition (layer L0).
 *
 * ONE JOB: get the text off the box, without ever letting the acquisition
 * itself become a variable of the diff. Everything semantic is downstream
 * (`parse.ts`, `quirks.ts`, `config/normalize.service.ts`).
 *
 * ┌─ THE THREE THINGS THAT ARE HARD-WIRED, AND WHY ───────────────────────────┐
 * │                                                                           │
 * │ R10 — `show-sensitive=no` IS A LITERAL IN THE COMMAND STRING. There is no │
 * │   parameter, no option object, no environment variable and no per-device  │
 * │   override that can turn it off. A boolean would eventually be flipped by │
 * │   someone debugging "why can't I see the PSK", and from that moment the   │
 * │   PSKs of the fleet are in a jsonb column, in a diff, in the UI and in a  │
 * │   log. The flag is doubled by a RouterOS service account WITHOUT the      │
 * │   `sensitive` policy, so even a compromised call site cannot retrieve     │
 * │   them. Belt and braces, on purpose: this is the one place in the product │
 * │   where a mistake is irreversible, because a secret that reached the      │
 * │   snapshot store has to be assumed to have leaked.                        │
 * │                                                                           │
 * │ N13 — NO PTY. `exec()` without `pty: true`. With a pty RouterOS wraps     │
 * │   long lines at the terminal width, which makes the width an input to     │
 * │   `ncm_hash`: the same unchanged router produces two different documents  │
 * │   depending on who collected it. The parser unfolds continuations anyway  │
 * │   as a safety net, but it WARNS, because absorbing the symptom here would │
 * │   hide the acquisition defect instead of fixing it.                       │
 * │                                                                           │
 * │ `terse` — one entry per line, full menu path on each line. Without it the │
 * │   output is the sectioned form and long lines are wrapped.                │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * CAPABILITY. Calling this is `CONFIG_READ`, which is deliberately a DIFFERENT
 * capability from `DEVICE_READ` (`shared/src/capabilities.ts`, risk R10): a
 * config export contains the whole security posture of a site, and the person
 * allowed to see that a device is up is not automatically allowed to read its
 * firewall. The check belongs to the route layer (not owned by this file); this
 * module states the requirement and the route that calls it must enforce
 * `CONFIG_READ`, never `DEVICE_READ`.
 */

import type { DeviceFamily } from '@obliwan/shared';
import { withSsh, type SshTarget } from '../../transport/ssh.transport';
import {
  DriverError,
  requireTransport,
  type DriverContext,
  type ResolvedTransport,
} from '../types';
import { familyFromVersion } from './mikrotik.driver';
import { parsePreamble, canonicalizeText, unfoldLines, type RouterOsPreamble } from './parse';

/**
 * The acquisition command. A frozen constant, exported so a test can assert on
 * the literal and so a reviewer can see the whole L0 contract in one line.
 *
 * NOT a template, NOT built by concatenation: a command assembled from parts is
 * a command someone can inject a part into.
 */
export const ROUTEROS_EXPORT_COMMAND = '/export terse show-sensitive=no' as const;

/**
 * The verbose oracle of N09 — `verbose − terse` is the set of that firmware's
 * default values, learned instead of typed in.
 *
 * It is NEVER the source of a drift snapshot: verbose output is far more
 * volatile between versions, and using it as the snapshot would trade the
 * defaults problem for a much bigger one. It is an oracle, run at first contact
 * with a device, on any `os_version` change, and at most weekly.
 *
 * Whether it exists and what it returns on 6.49 and on 7.14 is question 1 of
 * §7.4 of the study, and it is UNRESOLVED: no MikroTik was available. The
 * collector below therefore treats a failure of this command as normal and
 * records it, rather than treating the export as failed.
 */
export const ROUTEROS_EXPORT_VERBOSE_COMMAND = '/export terse verbose show-sensitive=no' as const;

export interface RouterOsExport {
  /** The export EXACTLY as the router produced it, preamble included. This is
   *  what `config_snapshots.raw_gz` stores and what `raw_sha256` covers. The
   *  raw is never normalised on disk: it is the only recoverable evidence the
   *  day a normalization rule turns out to be wrong, and it lets the whole
   *  corpus be replayed against a corrected ruleset without revisiting 300
   *  routers. */
  raw: string;
  preamble: RouterOsPreamble;
  /** From the preamble, and authoritative over `devices.family`: an operator
   *  who upgraded a hEX from 6.49 to 7.x changed the dialect. */
  observedFamily: DeviceFamily | null;
  collectedVia: 'ssh';
  collectedAt: string;
  durationMs: number;
  /** L0-level problems. A non-empty list is an acquisition defect to fix, not
   *  a diff to normalise. */
  warnings: string[];
}

/**
 * Runs the export over SSH.
 *
 * Not a method on `MikrotikRouterOsDriver`: `DeviceDriver.exportConfig` is
 * declared `Promise<never>` in `drivers/types.ts` (a file this workstream does
 * not own), so widening its signature is an M5 interface change. Rather than
 * fake it, the collector is a plain function the snapshot service calls
 * directly, and `exportConfig()` keeps throwing its dated `NotImplementedError`
 * until that signature moves. Loud and honest beats a method that lies about
 * its return type.
 */
export async function collectRouterOsExport(ctx: DriverContext): Promise<RouterOsExport> {
  const channel = requireTransport(ctx, 'ssh');
  const startedAt = Date.now();
  const raw = await runExportCommand(ctx, channel, ROUTEROS_EXPORT_COMMAND);
  const durationMs = Date.now() - startedAt;

  const warnings: string[] = [];
  const lines = canonicalizeText(raw);
  const { unfolded } = unfoldLines(lines);
  if (unfolded > 0) {
    warnings.push(
      `the export contains ${unfolded} wrapped line(s): a pty was allocated on the export channel. ` +
        'The terminal width must never be an input to ncm_hash (N13) — fix the transport, ' +
        'do not rely on the parser unfolding it.',
    );
  }
  const { preamble } = parsePreamble(lines);
  if (!preamble.osVersion) {
    warnings.push(
      'no "by RouterOS <version>" preamble line: the os_version of this snapshot is unknown, ' +
        'so the N09 default dictionary cannot be applied and default_fill is skipped for it.',
    );
  }

  assertNoSensitiveMaterial(raw);

  return {
    raw,
    preamble,
    observedFamily: familyFromVersion(preamble.osVersion),
    collectedVia: 'ssh',
    collectedAt: new Date().toISOString(),
    durationMs,
    warnings,
  };
}

/**
 * The N09 oracle. Returns `null` — never throws — when the command does not
 * exist on this firmware: `verbose` is an optimisation of the defaults
 * dictionary, and losing it must not lose the snapshot.
 */
export async function collectRouterOsVerboseExport(ctx: DriverContext): Promise<string | null> {
  const channel = requireTransport(ctx, 'ssh');
  try {
    return await runExportCommand(ctx, channel, ROUTEROS_EXPORT_VERBOSE_COMMAND);
  } catch {
    return null;
  }
}

async function runExportCommand(
  ctx: DriverContext,
  channel: ResolvedTransport,
  command: string,
): Promise<string> {
  if (!channel.host) {
    throw new DriverError('SSH transport row has no host', 'NO_TRANSPORT', {
      transport: 'ssh',
      retryable: false,
    });
  }
  const { username } = channel.credentials;
  if (!username) {
    throw new DriverError('SSH transport row has no username in the vault', 'AUTH_FAILED', {
      transport: 'ssh',
      retryable: false,
    });
  }

  const target: SshTarget = {
    host: channel.host,
    port: channel.port ?? undefined,
    username,
    password: channel.credentials.password ?? null,
    privateKey: channel.credentials.privateKey ?? null,
    passphrase: channel.credentials.passphrase ?? null,
    timeoutMs: ctx.timeoutMs ?? 60_000,
    legacyAlgorithms: channel.params?.['legacyAlgorithms'] === true,
  };

  return withSsh(target, async (ssh) => {
    const result = await ssh.exec(command, {
      // N13: the whole point.
      pty: false,
      timeoutMs: ctx.timeoutMs ?? 60_000,
    });
    if (result.code !== null && result.code !== 0) {
      throw new DriverError(
        `RouterOS "${command}" exited with code ${result.code}: ${result.stderr.trim().slice(0, 200)}`,
        'PROTOCOL_ERROR',
        { transport: 'ssh' },
      );
    }
    if (/not enough permissions|no such command/i.test(result.stderr)) {
      throw new DriverError(
        `RouterOS refused "${command}": ${result.stderr.trim().slice(0, 200)}`,
        'PERMISSION_DENIED',
        { transport: 'ssh', retryable: false },
      );
    }
    if (result.stdout.trim() === '') {
      // An empty export read as "this router has no configuration" is how a
      // drift engine invents a full-fleet wipe. Never return it as a document.
      throw new DriverError(
        `RouterOS "${command}" returned an empty document`,
        'PROTOCOL_ERROR',
        { transport: 'ssh' },
      );
    }
    return result.stdout;
  });
}

// ============================================================================
// R10 — the tripwire
// ============================================================================

/**
 * Props that MUST NOT carry a value in a `show-sensitive=no` export.
 *
 * Whether RouterOS omits the prop entirely or emits it empty varies by menu and
 * by version (question 3 of §7.4, unresolved without hardware), so this checks
 * the only thing that is version-independent: a non-empty value.
 *
 * The same list is what the CI fixture scanner greps for, because a fixture
 * committed with a real PSK in it is the same accident by another route.
 */
export const SENSITIVE_PROPS: readonly string[] = [
  'password', 'secret', 'pre-shared-key', 'wpa-pre-shared-key', 'wpa2-pre-shared-key',
  'private-key', 'passphrase', 'auth-password', 'priv-password',
  'authentication-password', 'encryption-password', 'key',
];

const SENSITIVE_RE = new RegExp(
  `(?:^|\\s)(${SENSITIVE_PROPS.join('|')})=("[^"]+"|[^\\s"]+)`,
  'gi',
);

/**
 * Fails the collection when a secret survived `show-sensitive=no`.
 *
 * REFUSING THE SNAPSHOT IS THE POINT. The alternative — strip it and carry on —
 * means the export ran against an account that has the `sensitive` policy, or
 * against a firmware that ignores the flag, and both are conditions an operator
 * has to know about. Redacting quietly would let the fleet run for months one
 * refactor away from persisting every PSK it owns.
 *
 * `key=` is deliberately in the list even though it produces false alarms on
 * `key=value`-shaped props: on this path a false alarm costs one failed
 * collection and one line in a log, and the other error costs the fleet's
 * secrets.
 */
export function assertNoSensitiveMaterial(raw: string): void {
  SENSITIVE_RE.lastIndex = 0;
  const hits = new Set<string>();
  for (const m of raw.matchAll(SENSITIVE_RE)) {
    const value = m[2];
    if (value === '""' || value === '') continue;
    hits.add(m[1].toLowerCase());
  }
  if (hits.size === 0) return;
  throw new DriverError(
    `the export carries values for sensitive prop(s) [${Array.from(hits).sort().join(', ')}] ` +
      `despite "${ROUTEROS_EXPORT_COMMAND}". The snapshot is REFUSED rather than redacted: ` +
      'this means the service account holds the RouterOS "sensitive" policy, or the firmware ' +
      'ignored the flag. Both must be fixed on the device — R10, section 8.2. ' +
      '(No value is reproduced in this message.)',
    'PROTOCOL_ERROR',
    { transport: 'ssh', retryable: false },
  );
}
