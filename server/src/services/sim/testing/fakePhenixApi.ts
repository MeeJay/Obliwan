/**
 * ObliWAN F9 — a protocol-level fake of the Phenix Partner API.
 *
 * ┌─ WHY A FAKE AND NOT A MOCK ───────────────────────────────────────────────┐
 * │ This project's method (ARCHITECTURE.md §8.3) is to build against          │
 * │ protocol-level fakes rather than against stubbed functions, because the   │
 * │ defects worth catching live in the WIRE FORMAT — an envelope shape, a     │
 * │ renamed field, a 401 body — and a stubbed `fetchBalances()` returns       │
 * │ whatever the test author already believed.                                │
 * │                                                                          │
 * │ That matters more here than anywhere else in the product, because the     │
 * │ field names this API uses ARE NOT CONFIRMED: they were read off the       │
 * │ extranet's Angular bundle, not off a captured response. So this fake can  │
 * │ serve the SAME line in several hostile dialects, and the connector must   │
 * │ answer "unknown" for every one it cannot read — never "0 Go left", which  │
 * │ is the reading that buys data.                                            │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * The dialects, and what each one is for:
 *
 *   `nominal`      the shape the bundle implies. Everything readable.
 *   `renamed`      the balance fields carry different names. The connector must
 *                  report `null`, and the sweep must report `unknown`.
 *   `partial`      one zone readable, one zone missing its `restValueGo`.
 *   `stringy`      numbers arrive as strings, some with a decimal comma.
 *   `envelope`     rows wrapped in `{ items: [...] }` instead of a bare array.
 *   `garbage`      an envelope matching nothing known. Must be an ERROR, not an
 *                  empty fleet — the two are indistinguishable on a dashboard
 *                  and only one of them means "stop".
 *   `expired`      every authenticated call answers 401.
 *   `otp`          `/Auth/authenticate` refuses and demands a one-time code.
 *   `truncated`    the listing declares more lines than it returns — what a
 *                  paged endpoint looks like above its page size. Must NOT be
 *                  reported as a smaller, healthy fleet.
 *   `ratelimited`  every read answers 429. This is NOT the same code path as a
 *                  4xx: `RestTransport` THROWS on 429 and 5xx rather than
 *                  returning, so the connector's own status check is never
 *                  reached — which is how the request path, MSISDN included,
 *                  escaped into the application log.
 *
 * Nothing here talks to a real partner, and nothing here needs a database.
 */

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { Buffer } from 'node:buffer';

export type PhenixDialect =
  | 'nominal'
  | 'renamed'
  | 'partial'
  | 'stringy'
  | 'envelope'
  | 'garbage'
  | 'expired'
  | 'otp'
  | 'ratelimited'
  | 'truncated';

export interface FakePhenixOptions {
  dialect?: PhenixDialect;
  /** Partner id baked into the issued token's claims. */
  partnerId?: number;
  /** Seconds from an arbitrary fixed epoch; the token's `exp` claim. */
  tokenExpSeconds?: number;
  lines?: Array<{ msisdn: string; operateur?: string; codeClient?: string; statut?: string }>;
}

export interface FakePhenix {
  readonly baseUrl: string;
  /** Every path the server was asked for, in order. Assert on this to prove a
   *  connector did NOT make a call — a sweep that skips a line must really skip
   *  it, not merely ignore the answer. */
  readonly calls: string[];
  /** Bearer tokens presented, in order. Never logged anywhere else. */
  readonly tokensSeen: string[];
  setDialect(d: PhenixDialect): void;
  close(): Promise<void>;
}

const DEFAULT_LINES = [
  { msisdn: '33600000001', operateur: 'Orange', codeClient: 'CLI-001', statut: 'Actif' },
  { msisdn: '33600000002', operateur: 'SFR', codeClient: 'CLI-002', statut: 'Actif' },
  { msisdn: '33600000003', operateur: 'Bouygues', codeClient: 'CLI-003', statut: 'Suspendu' },
];

/**
 * A JWT-shaped token. Signed with nothing: the connector only ever DECODES the
 * payload (best effort) and never verifies a signature, because it is not the
 * issuer. A fake that signed properly would be testing the wrong thing.
 */
function makeToken(partnerId: number, expSeconds: number): string {
  const b64 = (o: unknown) =>
    Buffer.from(JSON.stringify(o), 'utf8')
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
  return [
    b64({ alg: 'HS256', typ: 'JWT' }),
    b64({ PartenaireId: partnerId, exp: expSeconds, sub: 'fake' }),
    'not-a-signature',
  ].join('.');
}

function balancesFor(dialect: PhenixDialect): unknown {
  switch (dialect) {
    case 'renamed':
      // The exact defect this whole feature is designed around: the API answers,
      // the row is well formed, and NOT ONE key is a name the connector knows.
      return [
        { libelleZoneText: 'France', totalGo: 50, consommeGo: 49.8, disponibleGo: 0.2 },
      ];
    case 'partial':
      return [
        { libelleZoneText: 'France', rechargeGo: 50, usedValueGo: 20, restValueGo: 30 },
        { libelleZoneText: 'Europe', rechargeGo: 5, usedValueGo: 5 },
      ];
    case 'stringy':
      return [
        { libelleZoneText: 'France', rechargeGo: '50', usedValueGo: '49,5', restValueGo: '0,5' },
      ];
    case 'envelope':
      return {
        items: [{ libelleZoneText: 'France', rechargeGo: 50, usedValueGo: 10, restValueGo: 40 }],
      };
    case 'garbage':
      return { error: 'something went wrong', correlationId: 'abc-123' };
    default:
      return [
        { libelleZoneText: 'France', rechargeGo: 50, usedValueGo: 10, restValueGo: 40 },
        { libelleZoneText: 'Europe', rechargeGo: 5, usedValueGo: 4.5, restValueGo: 0.5 },
      ];
  }
}

export async function startFakePhenix(opts: FakePhenixOptions = {}): Promise<FakePhenix> {
  let dialect: PhenixDialect = opts.dialect ?? 'nominal';
  const partnerId = opts.partnerId ?? 4242;
  // A fixed instant, not a clock: `Date.now()` in a fixture makes a test that
  // passes today and fails in a year.
  const exp = opts.tokenExpSeconds ?? 4_102_444_800; // 2100-01-01T00:00:00Z
  const lines = opts.lines ?? DEFAULT_LINES;
  const calls: string[] = [];
  const tokensSeen: string[] = [];

  const server: Server = createServer((req: IncomingMessage, res: ServerResponse) => {
    const url = req.url ?? '';
    const path = url.split('?')[0];
    calls.push(url);

    const auth = req.headers.authorization;
    if (typeof auth === 'string' && auth.startsWith('Bearer ')) {
      tokensSeen.push(auth.slice(7));
    }

    const send = (code: number, body: unknown) => {
      const payload = typeof body === 'string' ? body : JSON.stringify(body);
      res.writeHead(code, { 'Content-Type': 'application/json' });
      res.end(payload);
    };

    // Drain the body: the extranet POSTs `[]` to GetSdtrConso, and a server that
    // never reads the request body leaves the socket half-open under undici.
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      if (path === '/Auth/authenticate') {
        if (dialect === 'otp') {
          // What an OTP-protected account actually looks like from here: a
          // refusal with no token, indistinguishable from a wrong password.
          return send(401, { message: 'Code de confirmation requis' });
        }
        return send(200, { access_token: makeToken(partnerId, exp) });
      }

      if (path === '/Auth/authenticateWithCodeConfirmation') {
        const body = Buffer.concat(chunks).toString('utf8');
        let code = '';
        try {
          code = (JSON.parse(body || '{}') as { code?: string }).code ?? '';
        } catch {
          code = '';
        }
        if (code !== '123456') return send(401, { message: 'Code invalide' });
        return send(200, { access_token: makeToken(partnerId, exp) });
      }

      // Everything below is authenticated.
      if (dialect === 'expired') return send(401, { message: 'Token expired' });
      if (dialect === 'ratelimited') return send(429, { message: 'Too many requests' });
      if (!auth) return send(401, { message: 'Missing Authorization' });

      if (path === '/GsmApi/GetLigneGsmByFilterPaged') {
        if (dialect === 'garbage') return send(200, { unexpected: true });
        if (dialect === 'truncated') {
          // One row returned, three declared: the shape of page one.
          return send(200, {
            items: [
              {
                msisdn: lines[0].msisdn,
                operateur: lines[0].operateur ?? '',
                codeClient: lines[0].codeClient ?? null,
                statut: lines[0].statut ?? null,
              },
            ],
            totalCount: lines.length,
          });
        }
        const rows = lines.map((l) => ({
          msisdn: l.msisdn,
          operateur: l.operateur ?? '',
          codeClient: l.codeClient ?? null,
          statut: l.statut ?? null,
        }));
        return send(200, dialect === 'envelope' ? { items: rows } : rows);
      }

      if (path === '/GsmApi/GetSdtrConso') {
        return send(200, balancesFor(dialect));
      }

      return send(404, { message: 'no such endpoint' });
    });
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (address === null || typeof address === 'string') {
    throw new Error('fake Phenix: could not determine the listening port');
  }

  return {
    baseUrl: `http://127.0.0.1:${address.port}`,
    calls,
    tokensSeen,
    setDialect(d: PhenixDialect) {
      dialect = d;
    },
    async close() {
      await new Promise<void>((resolve, reject) =>
        server.close((err) => (err ? reject(err) : resolve())),
      );
    },
  };
}
