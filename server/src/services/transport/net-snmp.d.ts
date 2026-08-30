/**
 * Minimal ambient types for `net-snmp` (v3.26), which ships no `.d.ts` and has
 * no `@types` package.
 *
 * Scope is what `snmp.transport.ts` actually calls: session creation, `get`,
 * `subtree` (the walk the M3 discovery needs), `on` and `close`. `getNext` and
 * `getBulk` are declared because `subtree` is built on them, but nothing here
 * calls them directly; `table` / `createReceiver` are deliberately absent
 * rather than guessed.
 *
 * This lives beside the transport that needs it instead of in a global
 * `src/types/` folder, so the declaration travels with its only consumer.
 */

declare module 'net-snmp' {
  export interface Varbind {
    oid: string;
    type: number;
    value: string | number | bigint | Buffer | null;
  }

  export interface SessionOptions {
    port?: number;
    retries?: number;
    timeout?: number;
    backoff?: number;
    transport?: 'udp4' | 'udp6';
    trapPort?: number;
    version?: number;
    backwardsGetNexts?: boolean;
    idBitsSize?: number;
    context?: string;
  }

  export interface V3User {
    name: string;
    level: number;
    authProtocol?: string;
    authKey?: string;
    privProtocol?: string;
    privKey?: string;
  }

  export interface Session {
    get(oids: string[], callback: (error: Error | null, varbinds: Varbind[]) => void): void;
    getNext(oids: string[], callback: (error: Error | null, varbinds: Varbind[]) => void): void;
    getBulk(
      oids: string[],
      nonRepeaters: number,
      maxRepetitions: number,
      callback: (error: Error | null, varbinds: Varbind[][]) => void,
    ): void;
    subtree(
      oid: string,
      maxRepetitions: number,
      feedCb: (varbinds: Varbind[]) => void,
      doneCb: (error: Error | null) => void,
    ): void;
    close(): void;
    on(event: 'error' | 'close', listener: (error?: Error) => void): Session;
    trap(...args: unknown[]): void;
  }

  export function createSession(
    target: string,
    community: string,
    options?: SessionOptions,
  ): Session;

  export function createV3Session(target: string, user: V3User, options?: SessionOptions): Session;

  export function isVarbindError(varbind: Varbind): boolean;
  export function varbindError(varbind: Varbind): string;

  export const Version1: number;
  export const Version2c: number;
  export const Version3: number;

  export const ObjectType: Record<string, number>;
  export const ErrorStatus: Record<string, number>;
  export const AuthProtocols: Record<string, string>;
  export const PrivProtocols: Record<string, string>;
  export const SecurityLevel: Record<string, number>;
}
