/**
 * ObliWAN — the CWMP Express app. A SEPARATE application from the API.
 *
 * ┌─ WHY THIS IS NOT A ROUTER MOUNTED ON THE API ─────────────────────────────┐
 * │ Everything the API app does is wrong here, and each one is fatal:         │
 * │                                                                          │
 * │  express.json()   would reject `Content-Type: text/xml` and, worse,       │
 * │                   would turn the EMPTY POST — the protocol's own signal — │
 * │                   into a 400. See `sessionMachine.ts`'s header.           │
 * │  session()        would issue a `connect.sid` to every CPE and create a   │
 * │                   Postgres session row per POST. 300 CPEs at 300 s is a   │
 * │                   session table growing by 86 000 rows a day, for nothing.│
 * │  apiLimiter       would rate-limit a fleet reconnecting after an outage — │
 * │                   which is exactly the moment it must not.                │
 * │  helmet CSP/HSTS  are browser headers. A CPE ignores them, and HSTS on a  │
 * │                   plain-HTTP listener is a header that lies.              │
 * │  cors             there is no browser and no origin.                      │
 * │                                                                          │
 * │ And above all: this listener is NOT behind the client's nginx (§6.2). A   │
 * │ proxy that rewrites the request URI invalidates HA2 = MD5(method:uri) and │
 * │ every CPE in the fleet fails Digest with no diagnosable error.            │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ WHAT IT DOES CARRY ──────────────────────────────────────────────────────┐
 * │  - `express.text({ type: () => true })`, so an empty body arrives as `''` │
 * │    and a `text/xml` body arrives as a string, whatever Content-Type the   │
 * │    CPE invented.                                                          │
 * │  - a hard body-size cap, because a malformed Content-Length from a broken │
 * │    CPE must not become an OOM on the process that holds the fleet's       │
 * │    credentials.                                                           │
 * │  - the file server, on the same listener, because the CPE that fetches a  │
 * │    firmware image is the same box on the same line and giving it a second │
 * │    port to reach is a second thing to get wrong in a firewall.            │
 * └───────────────────────────────────────────────────────────────────────────┘
 */

import express, { type Request, type Response } from 'express';
import { config } from '../config';
import { logger } from '../utils/logger';
import { handleCwmpPost, type CwmpHttpRequest } from '../services/cwmp/sessionMachine';
import { SESSION_COOKIE } from '../services/cwmp/session.service';
import { createFileRouter } from './fileServer';

/**
 * The address the CPE really came from.
 *
 * `req.socket.remoteAddress` AND NOTHING ELSE. There is by construction no
 * reverse proxy in front of this listener — that is the argument the header of
 * this file makes at length (§6.2: a proxy that rewrites the request URI
 * invalidates HA2 = MD5(method:uri) and the whole fleet fails Digest with no
 * diagnosable error) — so an `X-Forwarded-For` arriving here was written by
 * whoever opened the socket.
 *
 * ┌─ WHY THE "ONLY IF THE PEER LOOKS PRIVATE" VERSION WAS WORSE THAN NOTHING ─┐
 * │ This function used to honour `X-Forwarded-For` when the immediate peer    │
 * │ was loopback or RFC1918, on the theory that such a peer can only be a     │
 * │ local reverse proxy. Under the deployment the product actually SHIPS      │
 * │ (`docker-compose.yml`, `ports: "7547:7547/tcp"`) the peer is the Docker   │
 * │ bridge gateway — 172.18.0.1, inside 172.16/12 — for EVERY CPE on earth    │
 * │ (ARCHITECTURE.md §7, arbitrage A6). The test was therefore TRUE ALWAYS    │
 * │ and the header was trusted from the whole internet: one header bypassed   │
 * │ `trusted_cidrs`, and one header chose the address the Digest nonce is     │
 * │ bound to.                                                                 │
 * │                                                                          │
 * │ Should a proxy ever be put in front, it earns an explicitly configured    │
 * │ allow-list of peer addresses — never "the peer looks private".            │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * And note what A6 means for the value this returns: under the shipped
 * deployment it is the bridge gateway for every CPE, so THE SOURCE ADDRESS
 * IDENTIFIES NOTHING. Decision D5 already says exactly that for SNMP traps; it
 * holds here too, and it is why nothing in the session machine keys on it.
 */
export function clientIp(req: Request): string {
  return normalise(req.socket.remoteAddress ?? '');
}

function normalise(ip: string): string {
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);
  return mapped ? mapped[1] : ip;
}

/** `ACSsession=xyz; Path=/` -> `xyz`. Parsed by hand: `cookie-parser` is a
 *  middleware with a signing feature we do not want on this app. */
export function readSessionCookie(header: string | undefined): string | null {
  if (!header) return null;
  for (const part of header.split(';')) {
    const [name, ...rest] = part.trim().split('=');
    if (name === SESSION_COOKIE) return rest.join('=');
  }
  return null;
}

export function createCwmpApp() {
  const app = express();

  // Do NOT trust proxies by default: see `clientIp` above.
  app.set('trust proxy', false);
  // A CPE does not care, and `X-Powered-By` on an internet-facing listener is
  // free reconnaissance.
  app.disable('x-powered-by');

  // THE BODY PARSER. `type: () => true` because CPEs send `text/xml`,
  // `text/xml; charset=utf-8`, `application/soap+xml`, and — on an empty POST —
  // sometimes no Content-Type at all. A type-matched parser leaves `req.body`
  // undefined on exactly the requests that matter most.
  app.use(
    express.text({
      type: () => true,
      limit: config.cwmp.maxBodyBytes,
      defaultCharset: 'utf-8',
    }),
  );

  // ── The file server, before the catch-all POST route ─────────────────────
  app.use('/cwmp-files', createFileRouter());

  // ── Health, for the container ────────────────────────────────────────────
  app.get('/health', (_req, res) => {
    res.json({ status: 'ok', service: 'cwmp-acs' });
  });

  /**
   * THE ONE ROUTE.
   *
   * `/:slug` and nothing else: the tenant is in the URL because a CPE has no
   * other way to tell us who it belongs to (see `acsSettings.service.ts`).
   */
  app.post('/:slug', async (req: Request, res: Response) => {
    const started = Date.now();
    const body = typeof req.body === 'string' ? req.body : '';

    const cwmpReq: CwmpHttpRequest = {
      slug: String(req.params.slug || ''),
      body,
      sourceIp: clientIp(req),
      cookieToken: readSessionCookie(req.headers.cookie),
      authorization: req.headers.authorization,
      requestUri: req.originalUrl,
    };

    try {
      const result = await handleCwmpPost(cwmpReq);

      for (const [name, value] of Object.entries(result.headers)) {
        res.setHeader(name, value);
      }
      if (result.setSessionCookie) {
        // No `Secure` (this listener is plain HTTP for CPEs that cannot do TLS)
        // and no `SameSite` (a CPE is not a browser and several firmware trains
        // DROP a cookie carrying attributes they do not recognise, which would
        // silently force every device onto the ambiguous fallback key).
        res.setHeader(
          'Set-Cookie',
          `${SESSION_COOKIE}=${result.setSessionCookie}; Path=/; HttpOnly`,
        );
      }

      if (result.status === 204 || result.body.length === 0) {
        // A CWMP 204 must carry no body and no Content-Type. Some CPE HTTP
        // stacks treat `Content-Length: 0` with a Content-Type as a malformed
        // response and abort the session.
        res.status(result.status).end();
      } else {
        res.status(result.status).send(result.body);
      }

      logger.debug(
        {
          slug: cwmpReq.slug,
          sourceIp: cwmpReq.sourceIp,
          empty: body.length === 0,
          status: result.status,
          ms: Date.now() - started,
        },
        'ACS: CWMP exchange',
      );
    } catch (err) {
      // A 500 here ends the CPE's session and it retries at its own interval.
      // That is the correct failure mode and it must not take the listener with
      // it: one malformed envelope from one Vigor cannot be allowed to stop 300
      // other CPEs from reporting.
      logger.error(
        { err, slug: cwmpReq.slug, sourceIp: cwmpReq.sourceIp },
        'ACS: unhandled error while serving a CWMP request',
      );
      res.status(500).end();
    }
  });

  // Anything else. A GET on 7547 is usually a scanner or a curious operator;
  // answering with a sentence is cheaper than answering a support ticket.
  app.use((_req, res) => {
    res
      .status(404)
      .type('text/plain')
      .send('ObliWAN ACS. CPEs POST to /<tenant-slug>. Nothing else lives here.\n');
  });

  return app;
}
