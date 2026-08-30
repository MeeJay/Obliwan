import type { Request, Response, NextFunction } from 'express';
import { logger } from '../utils/logger';

export class AppError extends Error {
  constructor(
    public statusCode: number,
    message: string,
  ) {
    super(message);
    this.name = 'AppError';
  }
}

/**
 * The shape `pg` gives a driver-level error. Only the fields this handler reads
 * are declared; everything else on the object is left alone.
 */
interface PgError extends Error {
  code?: string;
  detail?: string;
  table?: string;
  constraint?: string;
}

function isPgError(err: Error): err is PgError {
  return typeof (err as PgError).code === 'string';
}

/**
 * VERDICT-CONSOLIDATION §3.2 — a foreign-key violation reached the client as a
 * bare `500 Internal server error`.
 *
 * Reproduced before the fix: `PUT /api/users/99999/tenants` with a valid body
 * ran `INSERT INTO user_tenants (user_id, ...) VALUES (99999, ...)`, PostgreSQL
 * raised SQLSTATE 23503, nothing caught it, and the caller was told the server
 * had broken — when in fact the caller's request was wrong and a 404 was the
 * answer. Worse than the wrong number: a 500 is the one status an operator is
 * expected to escalate, so a typo'd id manufactured an incident.
 *
 * 23503 covers two OPPOSITE situations and they do not deserve the same status,
 * so the direction is read from `detail`, which PostgreSQL words unambiguously:
 *
 *   INSERT/UPDATE — "Key (user_id)=(99999) is not present in table \"users\"."
 *       The row being pointed AT does not exist  ->  404.
 *   DELETE/UPDATE — "Key (id)=(3) is still referenced from table \"devices\"."
 *       The row is still pointed at by others    ->  409, a real conflict.
 *
 * When `detail` is absent (it can be suppressed by log configuration), 409 is
 * the conservative fallback: it does not claim the resource is missing.
 *
 * 23505 is mapped for symmetry only. The services that can hit it already turn
 * it into their own 409 with a business message (duplicate team name, duplicate
 * site code, `permissionSets.routes`), and those run BEFORE this handler and are
 * untouched — this is the net under the paths nobody has covered yet, such as
 * the `users_email_lower_unique` index that migration 004 adds.
 *
 * The driver message is deliberately NOT forwarded: it names tables, columns and
 * the offending value. The `logger.warn` keeps all of it server-side.
 */
function mapPgError(err: PgError): { status: number; message: string } | null {
  switch (err.code) {
    case '23503': {
      const stillReferenced = err.detail?.includes('is still referenced from');
      return stillReferenced
        ? { status: 409, message: 'This record is still referenced by other records' }
        : err.detail?.includes('is not present in table')
          ? { status: 404, message: 'Referenced record not found' }
          : { status: 409, message: 'Referenced record constraint violated' };
    }
    case '23505':
      return { status: 409, message: 'A record with these values already exists' };
    default:
      return null;
  }
}

export function errorHandler(
  err: Error,
  _req: Request,
  res: Response,
  _next: NextFunction,
): void {
  if (err instanceof AppError) {
    res.status(err.statusCode).json({
      success: false,
      error: err.message,
    });
    return;
  }

  if (isPgError(err)) {
    const mapped = mapPgError(err);
    if (mapped) {
      logger.warn(
        { code: err.code, table: err.table, constraint: err.constraint, detail: err.detail },
        `Database constraint violation mapped to ${mapped.status}`,
      );
      res.status(mapped.status).json({ success: false, error: mapped.message });
      return;
    }
  }

  logger.error(err, 'Unhandled error');
  res.status(500).json({
    success: false,
    error: 'Internal server error',
  });
}
