/**
 * ObliWAN — the per-brand CLI dialects. PURE DATA, ZERO IMPORTS.
 *
 * ┌─ WHY THIS IS ITS OWN MODULE ─────────────────────────────────────────────┐
 * │ It used to live in `safeApply.service.ts`, which imports the database.    │
 * │ Harmless on the server; fatal for the bench tool (M15), whose whole point │
 * │ is that it runs on a preparation workstation with no database, no vault   │
 * │ and no network to a registry.                                            │
 * │                                                                          │
 * │ The BUNDLER found it, not a reviewer: pulling one const dragged in knex   │
 * │ and its nine SQL drivers, and the build died on `oracledb`. A tool that   │
 * │ needs a connection string is a tool that cannot leave the office — the    │
 * │ comment saying so was already written, and the import graph contradicted  │
 * │ it. Data that both a server and a detached tool must agree on belongs in  │
 * │ a module that imports nothing.                                           │
 * └──────────────────────────────────────────────────────────────────────────┘
 */

/**
 * ONE PLACE WHERE THE PER-BRAND CLI STRINGS LIVE.
 *
 * ┌─ WHY THIS IS A TABLE AND NOT A PARAMETER EACH CALLER FILLS IN ───────────┐
 * │ `applyOverSsh` decides a command SUCCEEDED by failing to match           │
 * │ `errorPattern` in the device's own echo. None of these boxes sets a       │
 * │ usable exit code on a config line, so that regex is the entire failure    │
 * │ detector for the write path of three brands.                             │
 * │                                                                          │
 * │ A pattern that is too narrow does not throw and does not log: the device  │
 * │ prints "% Unknown command", nothing matches, and the line is counted as   │
 * │ APPLIED. The job goes green, `applied` equals the batch size, §8.3 sees   │
 * │ no reason to roll anything back, and a firewall is left half written.     │
 * │ Letting each call site invent its own regex guarantees that failure       │
 * │ eventually; one reviewed table makes it a diff on a single object.        │
 * │                                                                          │
 * │ PROVENANCE, stated because it decides how much to trust this: every       │
 * │ string here comes from vendor documentation and published CLI            │
 * │ transcripts. NONE of it has been read off a real appliance. The harness   │
 * │ `m6-sshapply.verify.ts` proves the LOOP is correct given a device that    │
 * │ answers this way; it cannot prove a Vigor answers this way. The first     │
 * │ session against real hardware should capture a transcript and correct     │
 * │ this table before anything is pushed in anger.                            │
 * └──────────────────────────────────────────────────────────────────────────┘
 */
export interface SshDialect {
  /** End-of-answer marker. The loop treats a buffer ending here as "the device
   *  is ready for the next line". */
  promptPattern: RegExp;
  /** Anything matching this in the echo means the line was REFUSED. Kept
   *  deliberately broad: a false refusal costs one aborted job, a missed
   *  refusal costs a half-configured router. */
  errorPattern: RegExp;
  /** What makes the change durable, if the brand needs an explicit verb.
   *  `null` when the CLI commits per line. */
  commitVerb: string | null;
  /** Free note for whoever validates this against hardware. */
  note: string;
}

/** The historical matcher, kept as the default so every existing call keeps
 *  the behaviour it was written against. */
export const DEFAULT_PROMPT_PATTERN = /[>#$]\s*$/;

export const SSH_DIALECTS: Readonly<Record<string, SshDialect>> = {
  draytek_vigor: {
    promptPattern: /(^|\r?\n)[^\r\n]*>\s*$/,
    errorPattern: /%\s|invalid input|unknown command|syntax error|command failed|not supported/i,
    commitVerb: null,
    note: 'Vigor CLI applies per line; `sys commit` exists on some trains but is not universal.',
  },
  zyxel_standalone: {
    promptPattern: /(^|\r?\n)[^\r\n]*[>#]\s*$/,
    errorPattern: /error|invalid|unknown command|incomplete command|permission denied/i,
    commitVerb: 'write',
    note: 'ZLD CLI needs an explicit `write` to survive a reboot — without it the change is lost silently on the next power cut, which looks exactly like drift.',
  },
  sonicwall_sonicos: {
    promptPattern: /(^|\r?\n)[^\r\n]*[>#]\s*$/,
    errorPattern: /%\s|error|invalid|failed|not (allowed|supported)/i,
    commitVerb: 'commit',
    note: 'SonicOS CLI is transactional: without `commit` the pending config is discarded when the session ends. A loop that reports success without it reports a change that never existed.',
  },
};
