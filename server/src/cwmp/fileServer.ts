/**
 * ObliWAN — the file server the CPE fetches firmware from.
 *
 * ┌─ THE TOKEN IS THE AUTHORISATION, AND THAT IS THE DESIGN ──────────────────┐
 * │ A CPE fetching a firmware image is on the customer's line, behind carrier │
 * │ NAT, over plain HTTP, with no session of ours and no way to hold one.     │
 * │ TR-069 offers `Username`/`Password` fields on `Download`; using them puts │
 * │ a REUSABLE credential in clear on a transit network once per push (R9).   │
 * │                                                                          │
 * │ So the URL carries a 256-bit token, minted per transfer, bound to one     │
 * │ device and one file, expiring in an hour. Capturing it gets you one       │
 * │ firmware image — which is on the vendor's public download page anyway —   │
 * │ and nothing else. It is never logged.                                     │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ WHY GET AND HEAD, AND WHY NO RANGE ──────────────────────────────────────┐
 * │ HEAD because several CPE HTTP clients probe the size before committing to │
 * │ a download, and a 405 there makes them abandon the transfer with          │
 * │ `9010 Download failure` — a fault that reads like a network problem.      │
 * │                                                                          │
 * │ No `Range`: TR-069 downloads are single-shot and a CPE that supports      │
 * │ ranges does not need them for a 20 MB file. Implementing partial content  │
 * │ would mean a second code path handling offsets against a token whose      │
 * │ whole point is to be single-purpose, for no observed benefit.             │
 * └───────────────────────────────────────────────────────────────────────────┘
 */

import fs from 'fs';
import path from 'path';
import { Router, type Request, type Response } from 'express';
import { config } from '../config';
import { logger } from '../utils/logger';
import { markFetched, resolveToken } from '../services/cwmp/transfer.service';

/**
 * Resolve a stored path INSIDE the configured directory.
 *
 * `storage_path` is written by the upload endpoint and is not user input in the
 * usual sense — but it is a column, and a column is one bad migration away from
 * being whatever somebody put in it. The containment check costs one
 * `path.resolve` and removes an entire class of "read any file on the server"
 * from a listener published to the internet.
 */
export function safeResolve(storagePath: string): string | null {
  const root = path.resolve(config.cwmp.fileStorageDir);
  const resolved = path.resolve(root, storagePath);
  if (resolved !== root && !resolved.startsWith(root + path.sep)) return null;
  return resolved;
}

export function createFileRouter(): Router {
  const router = Router();

  const serve = async (req: Request, res: Response, withBody: boolean): Promise<void> => {
    const token = String(req.params.token || '');
    const found = await resolveToken(token);

    if (!found) {
      // 404 and not 403: an expired token and a forged one are indistinguishable
      // to anyone who does not already know, and saying which is which turns
      // the endpoint into an oracle.
      res.status(404).type('text/plain').send('not found\n');
      return;
    }

    const filePath = safeResolve(found.file.storagePath);
    if (!filePath) {
      logger.error(
        { fileId: found.file.id },
        'ACS: cwmp_files.storage_path escapes the storage directory — refusing to serve',
      );
      res.status(500).end();
      return;
    }

    let stat: fs.Stats;
    try {
      stat = await fs.promises.stat(filePath);
    } catch {
      logger.error(
        { fileId: found.file.id, name: found.file.name },
        'ACS: firmware file is registered in the database but missing on disk',
      );
      res.status(404).type('text/plain').send('not found\n');
      return;
    }

    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Length', String(stat.size));
    res.setHeader('Content-Disposition', `attachment; filename="${sanitiseFilename(found.file.name)}"`);
    // The image is immutable and the token is single-purpose: nothing in this
    // response should ever be cached by anything in between.
    res.setHeader('Cache-Control', 'no-store');

    if (!withBody) {
      res.status(200).end();
      return;
    }

    // Counted BEFORE the bytes flow, not after. A CPE that starts the fetch and
    // dies halfway has still fetched, and that is the fact an operator needs
    // when the TransferComplete never arrives.
    await markFetched(found.transfer.id);
    logger.info(
      {
        deviceId: found.transfer.deviceId,
        fileId: found.file.id,
        name: found.file.name,
        bytes: stat.size,
        // The token is deliberately absent from this log line.
      },
      'ACS: CPE is fetching a file',
    );

    const stream = fs.createReadStream(filePath);
    stream.on('error', (err) => {
      logger.error({ err, fileId: found.file.id }, 'ACS: file stream failed mid-transfer');
      res.destroy();
    });
    stream.pipe(res);
  };

  router.get('/:token', (req, res) => {
    void serve(req, res, true);
  });
  router.head('/:token', (req, res) => {
    void serve(req, res, false);
  });

  return router;
}

function sanitiseFilename(name: string): string {
  return name.replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 128) || 'firmware.bin';
}
