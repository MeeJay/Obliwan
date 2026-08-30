/**
 * ObliWAN — the dedicated CWMP listener(s).
 *
 * ┌─ ONE PROCESS, TWO SERVERS, AND WHY THE SECOND ONE IS OPTIONAL ────────────┐
 * │ 7547 is plain HTTP and it is the one that matters: the estate of CPEs     │
 * │ this product targets was provisioned with `http://` ACS URLs years ago    │
 * │ and cannot be re-provisioned without a van.                               │
 * │                                                                          │
 * │ 7548 is TLS and it is OFF unless a certificate is configured. A TLS       │
 * │ listener with a self-signed certificate is WORSE than none: a CPE that    │
 * │ cannot validate the chain does not fall back to plain HTTP, it retries    │
 * │ the same failing handshake at every inform interval, forever, and the     │
 * │ device simply never appears. Refusing to start it without a real          │
 * │ certificate is the honest behaviour.                                      │
 * │                                                                          │
 * │ `minVersion: TLSv1` and the wide cipher list are DELIBERATE and are the   │
 * │ reason §6.2 calls this "TLS permissif pour CPE anciens". A 2016 Vigor     │
 * │ speaks TLS 1.0 with RSA ciphers and nothing else. Node's defaults reject  │
 * │ it. This is a listener whose entire population is legacy hardware on      │
 * │ someone else's line; the alternative to weak TLS here is not strong TLS,  │
 * │ it is plain HTTP on 7547, which is what those CPEs use anyway.            │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ KEEP-ALIVE AND TIMEOUTS ─────────────────────────────────────────────────┐
 * │ A CWMP session is a dozen POSTs over up to a couple of minutes and a CPE  │
 * │ expects to reuse the connection. `keepAliveTimeout` is therefore RAISED,  │
 * │ not lowered — Node's 5 s default closes the socket between two POSTs of   │
 * │ the same session, and some firmware treats that as a session abort rather │
 * │ than reconnecting. `headersTimeout` must stay above it or Node kills the  │
 * │ connection it just agreed to keep.                                        │
 * └───────────────────────────────────────────────────────────────────────────┘
 */

import fs from 'fs';
import http from 'http';
import https from 'https';
import type { Express } from 'express';
import { config } from '../config';
import { logger } from '../utils/logger';

export interface CwmpListeners {
  http: http.Server | null;
  https: https.Server | null;
}

const KEEP_ALIVE_MS = 120_000;

function tune(server: http.Server | https.Server): void {
  server.keepAliveTimeout = KEEP_ALIVE_MS;
  // Node requires headersTimeout > keepAliveTimeout, otherwise a kept-alive
  // connection is killed the moment it goes idle — which looks, from the CPE,
  // exactly like the ACS hanging up mid-session.
  server.headersTimeout = KEEP_ALIVE_MS + 10_000;
  // A CPE on a 512 kbit/s uplink genuinely needs a minute to PUT a large
  // GetParameterValuesResponse. Node's 0 (no timeout) is too permissive for an
  // internet-facing listener; 5 minutes is generous and still bounded.
  server.requestTimeout = 300_000;
}

export function startCwmpListeners(app: Express): CwmpListeners {
  const listeners: CwmpListeners = { http: null, https: null };

  const plain = http.createServer(app);
  tune(plain);
  plain.on('error', (err: NodeJS.ErrnoException) => {
    // EADDRINUSE on 7547 is the single most likely deployment mistake (a second
    // instance, or an ACS already running). Say which port, and do NOT throw:
    // the API must keep serving even when the ACS cannot bind.
    logger.error(
      { err, port: config.cwmp.port },
      'ACS: CWMP listener failed — no CPE will be able to reach this instance',
    );
  });
  plain.listen(config.cwmp.port, config.cwmp.bind, () => {
    logger.info(
      { port: config.cwmp.port, bind: config.cwmp.bind },
      'ACS: CWMP listener up (dedicated, not behind nginx — Digest and long sessions)',
    );
  });
  listeners.http = plain;

  const { tlsCertPath, tlsKeyPath } = config.cwmp;
  if (tlsCertPath && tlsKeyPath) {
    try {
      const secure = https.createServer(
        {
          cert: fs.readFileSync(tlsCertPath),
          key: fs.readFileSync(tlsKeyPath),
          // See the header: this listener's population is legacy CPE firmware.
          minVersion: 'TLSv1',
          ciphers: 'DEFAULT:@SECLEVEL=0',
          honorCipherOrder: false,
        },
        app,
      );
      tune(secure);
      secure.on('error', (err) => {
        logger.error({ err, port: config.cwmp.tlsPort }, 'ACS: CWMP TLS listener failed');
      });
      secure.listen(config.cwmp.tlsPort, config.cwmp.bind, () => {
        logger.warn(
          { port: config.cwmp.tlsPort },
          'ACS: CWMP TLS listener up with a PERMISSIVE profile (TLSv1, SECLEVEL=0) for legacy CPEs',
        );
      });
      listeners.https = secure;
    } catch (err) {
      logger.error(
        { err, tlsCertPath },
        'ACS: could not read the CWMP TLS certificate — the TLS listener is NOT running',
      );
    }
  } else {
    logger.info(
      'ACS: no CWMP_TLS_CERT/CWMP_TLS_KEY configured — port 7548 stays closed (a self-signed ' +
        'certificate would make CPEs retry forever rather than fall back)',
    );
  }

  return listeners;
}

export async function stopCwmpListeners(listeners: CwmpListeners): Promise<void> {
  await Promise.all(
    [listeners.http, listeners.https].map(
      (server) =>
        new Promise<void>((resolve) => {
          if (!server) return resolve();
          server.close(() => resolve());
          // A CPE holding a kept-alive socket would otherwise keep the process
          // alive for the full keepAliveTimeout on every deploy.
          server.closeIdleConnections?.();
          setTimeout(resolve, 3_000).unref();
        }),
    ),
  );
}
