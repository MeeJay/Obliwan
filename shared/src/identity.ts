// ============================================================================
// @obliwan/shared — F6, identity drift over TIME
// ============================================================================
//
// ONE SENTENCE: `deviceBinding.assertTargetBinding()` already asks "is this the
// box I recorded?" before every write; this file asks the question nobody was
// asking — "is this the same box it was LAST TIME?" — and it is the only place
// in the tree where the answer is decided.
//
// ┌─ THE FACT THIS FILE EXISTS TO STOP THROWING AWAY ─────────────────────────┐
// │ Every RouterOS connection this platform opens reads `/system/identity`,   │
// │ `/system/routerboard` and `/system/resource`. Three services do it        │
// │ (`device.service.testTransport`, `deviceBinding.assertTargetBinding`,     │
// │ `change/backup.service.openDeviceSession`) and all three compare the      │
// │ answer to the registry and then DROP IT. So the product knows the serial  │
// │ of every box it touches, several times a day, and remembers none of it.   │
// │                                                                          │
// │ A serial that changes on a site is a box that was swapped: RMA, failure,  │
// │ theft, or a technician who replaced hardware and told nobody. The day     │
// │ that site comes back with a blank router, the drift explodes and no one   │
// │ can say why — one second before, the information was on the wire.         │
// └───────────────────────────────────────────────────────────────────────────┘
//
// ┌─ SIX DECISIONS THAT MUST SURVIVE EVERY REFACTOR ──────────────────────────┐
// │                                                                           │
// │ 1. A BLANK SERIAL IS NOT A SERIAL CHANGE. THIS IS THE FIRST TRAP AND THE  │
// │    ONE THAT WOULD HAVE SHIPPED. A MikroTik CHR has no RouterBOARD, so     │
// │    `/system/routerboard/print` answers `!trap` and the serial is null     │
// │    FOREVER on every virtual concentrator in the fleet. A physical box     │
// │    under load answers the menu but omits `serial-number` once in a        │
// │    while. Treating either as "the serial changed to nothing" would file   │
// │    a hardware replacement against every CHR on every poll, and the        │
// │    feature would be switched off in a week. An UNANSWERED attribute is    │
// │    CARRIED FORWARD from the reference, never compared, never an event.    │
// │    `serial -> blank -> same serial` therefore produces NOTHING.           │
// │                                                                           │
// │ 2. PLACEHOLDERS ARE BLANKS. `"N/A"`, `"unknown"`, `"0"`, `"00000000"`,    │
// │    `"To be filled by O.E.M."` are what firmware writes when it has no     │
// │    serial to give. They are not identities, and two devices that both     │
// │    answer `"N/A"` are not the same device. `isPlaceholderSerial()` sends  │
// │    them down the decision-1 path.                                         │
// │                                                                           │
// │ 3. A SERIAL CHANGE IS A REPLACEMENT, AND IT SWALLOWS THE OTHER EVENTS.    │
// │    A swapped box also has a different name, a different firmware and      │
// │    often a different model. Emitting four events for one swap buries the  │
// │    one that matters under three that do not. `hardware_replacement` is    │
// │    EXCLUSIVE: it reports every attribute that moved, as one event.        │
// │                                                                           │
// │ 4. THE SAME SERIAL WITH A FACTORY NAME IS A RESET, NOT A RENAME.          │
// │    A box that comes back as `MikroTik` with the serial it always had was  │
// │    not renamed by an operator — it was wiped. That distinction decides    │
// │    whether the next drift run is reporting reality or reporting an empty  │
// │    router, so it is made here and not left to a human reading a diff.     │
// │                                                                           │
// │ 5. A REPLACEMENT (OR A RESET) INVALIDATES WHAT RESTED ON THE OLD BOX —    │
// │    AND THIS FILE ONLY SAYS SO. `invalidatesBaseline` is a FLAG ON AN      │
// │    EVENT. Nothing here deletes a snapshot, retires a baseline, closes a   │
// │    drift finding or touches a device. The second trap of the brief is     │
// │    that the "repair" is worse than the damage: a product that silently    │
// │    discards the reference config of a site because a serial moved has     │
// │    destroyed the only evidence of what that site used to be. We SIGNAL,   │
// │    a human decides, and the acknowledgement is recorded.                  │
// │                                                                           │
// │ 6. EVERY FUNCTION HERE IS PURE. No clock, no I/O, no database, no         │
// │    device. The rule that decides "this box was replaced" has to be        │
// │    readable in one screen and exercisable with no fleet at all.           │
// └───────────────────────────────────────────────────────────────────────────┘
//
// WHY `ppp_username` IS NOT ONE OF THE FOUR ATTRIBUTES
// It is OUR provisioning key, not something the box IS. We choose it, we write
// it into `/ppp/secret` on the concentrator, and a replacement box is given the
// SAME one on purpose — that is how the site comes back up. Watching it for
// change would watch our own paperwork. `deviceBinding` is right to assert it
// (it proves we are talking to the account we think we are); a replacement
// watcher must not. The four attributes below are all statements the HARDWARE
// makes about itself.
//
// NO SECRET APPEARS IN THIS FILE, IN ITS TYPES, OR IN ANY VALUE IT RETURNS
// (§8.2 / R10). The widest object it handles is a serial number, a hostname, a
// model designation and a firmware version.

// ============================================================================
// 1. Vocabularies
//
// Text + CHECK in the database, exactly like every other vocabulary in this
// package. Each list carries the LENGTH OF ITS LONGEST MEMBER, because
// migration 025 sizes its varchar columns from these numbers and a column
// narrower than its own CHECK is a table that rejects every legal INSERT.
// ============================================================================

/** The four things a box says about ITSELF. Order is the report order. */
export const IDENTITY_ATTRIBUTES = [
  'serial',
  'system_identity',
  'model',
  'os_version',
] as const;
export type IdentityAttributeName = (typeof IDENTITY_ATTRIBUTES)[number];

/**
 * Longest member: `system_identity_renamed`, 23 characters.
 * Migration 025 gives `device_identity_events.kind` varchar(32).
 */
export const IDENTITY_EVENT_KINDS = [
  /** First time we ever learned an attribute. Not a change: a gap filled. */
  'identity_learned',
  /** The serial moved from one real value to a different real value. */
  'hardware_replacement',
  /** Same serial, and the name came back as the vendor default. */
  'factory_reset',
  /** Same serial, and a human (or a template) renamed the box. */
  'system_identity_renamed',
  'firmware_upgraded',
  'firmware_downgraded',
  /** Firmware moved between two strings this file cannot order. */
  'firmware_changed',
  /** Same serial, different model designation. Our inventory or our read. */
  'model_changed',
] as const;
export type IdentityEventKind = (typeof IDENTITY_EVENT_KINDS)[number];

/** Longest member: `critical`, 8 characters. Column is varchar(16). */
export const IDENTITY_EVENT_SEVERITIES = ['info', 'notice', 'critical'] as const;
export type IdentityEventSeverity = (typeof IDENTITY_EVENT_SEVERITIES)[number];

/**
 * WHO looked. Longest members: `binding` and `session`, 7 characters.
 * Column is varchar(16).
 *
 * This is set by the SERVER at the call site and is never accepted from an
 * HTTP body: `probe` means "an operator pressed the button", `sweep` means
 * "the tenant-wide pass walked this device", and a caller able to choose
 * between them could dress a hand-made observation as a background fact.
 */
export const IDENTITY_OBSERVATION_SOURCES = [
  'probe',
  'sweep',
  'binding',
  'session',
  'import',
] as const;
export type IdentityObservationSource = (typeof IDENTITY_OBSERVATION_SOURCES)[number];

/**
 * Maximum storable length per attribute — THE EXACT WIDTH OF THE COLUMN IN
 * MIGRATION 025, which is itself the exact width of the matching column on
 * `devices` (migration 002). A value longer than this is refused as UNANSWERED
 * rather than truncated: a truncated serial can forge a match with a different
 * box just as easily as it can forge a mismatch, and both are worse than
 * "the box did not tell us".
 */
export const IDENTITY_MAX_LENGTH: Readonly<Record<IdentityAttributeName, number>> = {
  serial: 128,
  system_identity: 128,
  model: 128,
  os_version: 64,
};

/** Minimum ink in the note an operator writes when acknowledging an event.
 *  Mirrored by `device_identity_events_ack_justified_chk` in migration 025. */
export const MIN_IDENTITY_ACK_NOTE = 12;

// ============================================================================
// 2. Normalisation — where decisions 1 and 2 live
// ============================================================================

/**
 * Everything that occupies no ink, as a JavaScript character class.
 *
 * Written with escape sequences so this FILE contains no invisible character:
 * a source file holding the characters it is trying to catch is a file nobody
 * can review. Same set as `023_fix_evidence.ts` uses in SQL, for the same
 * reason — a value made of zero-width spaces is a value the screen renders as
 * nothing and a naive comparison treats as content.
 */
const INVISIBLE =
  /[\s\u00a0\u1680\u180e\u2000-\u200f\u202f\u205f\u2060\u2800\u3000\ufeff]/g;

/** ASCII control characters. A serial containing one is a framing accident. */
const CONTROL = /[\u0000-\u001f\u007f]/;

/**
 * What firmware writes into a serial field when it has none.
 *
 * Compared after casefolding and after every invisible character is removed,
 * so `"N / A"`, `"n/a"` and `"N  /  A"` all land on `n/a`.
 */
const SERIAL_PLACEHOLDERS: ReadonlySet<string> = new Set([
  '',
  '-',
  '--',
  '.',
  'na',
  'n/a',
  'none',
  'null',
  'nil',
  'nul',
  'unknown',
  'unspecified',
  'undefined',
  'notavailable',
  'notapplicable',
  'default',
  'defaultstring',
  'tobefilledbyo.e.m.',
  'tobefilledbyoem',
  'systemserialnumber',
  'serialnumber',
  'invalid',
]);

/**
 * The name a box carries when it has been wiped.
 *
 * Deliberately SHORT and deliberately exact. `hex`, `hap` and `ccr` are
 * MikroTik product lines and would be a plausible thing for an operator to
 * type as a real name, so they are NOT here: a false `factory_reset` claims a
 * customer's configuration is gone when it is not, and that is a worse
 * sentence to put on a screen than `system_identity_renamed`.
 */
const FACTORY_IDENTITIES: ReadonlySet<string> = new Set([
  'mikrotik',
  'routeros',
  'router',
  'draytek',
  'vigor',
  'zyxel',
  'sonicwall',
  'default',
  'unknown',
  'none',
]);

/** Strip the invisible family and casefold. Used for COMPARISON only. */
function fold(value: string): string {
  return value.replace(INVISIBLE, '').toLowerCase();
}

/** Trim and collapse inner whitespace runs to a single U+0020, for STORAGE. */
function tidy(value: string): string {
  return value.replace(/\s+/g, ' ').trim();
}

/**
 * `true` when this string is firmware saying "I have no serial".
 *
 * Also catches the all-zero and all-`x` serials, which are the other two
 * shapes of the same non-answer and which no comparison should ever treat as
 * a real value: two boxes both answering `00000000` are not one box.
 */
export function isPlaceholderSerial(raw: string | null | undefined): boolean {
  if (raw === null || raw === undefined) return true;
  const folded = fold(raw);
  if (folded.length === 0) return true;
  if (SERIAL_PLACEHOLDERS.has(folded)) return true;
  if (/^0+$/.test(folded)) return true;
  if (/^x+$/.test(folded)) return true;
  return false;
}

/** `true` when this name is the one the vendor ships, i.e. nobody's choice. */
export function isFactoryDefaultIdentity(raw: string | null | undefined): boolean {
  if (raw === null || raw === undefined) return false;
  return FACTORY_IDENTITIES.has(fold(raw));
}

/**
 * The storable form of one observed attribute, or `null` for "the box did not
 * answer" — which decision 1 turns into "carry the reference forward".
 *
 * FOUR ways to be null, and all four mean the same thing to the classifier:
 * absent, blank once the invisible characters are removed, containing a
 * control character (a framing accident, not a value), or longer than the
 * column that has to hold it.
 */
export function normalizeIdentityAttribute(
  attribute: IdentityAttributeName,
  raw: string | null | undefined,
): string | null {
  if (typeof raw !== 'string') return null;
  if (CONTROL.test(raw)) return null;
  const value = tidy(raw);
  if (fold(value).length === 0) return null;
  if (value.length > IDENTITY_MAX_LENGTH[attribute]) return null;
  if (attribute === 'serial' && isPlaceholderSerial(value)) return null;
  return value;
}

/**
 * Why an acknowledgement note is not acceptable, or `null` when it is.
 *
 * THIS IS THE APPLICATION HALF OF `device_identity_events_ack_justified_chk`,
 * AND IT MUST STAY THE SAME PREDICATE. `023_fix_evidence.ts` documents at
 * length what happens when the two halves differ: the application used
 * `String.trim()`, which removes U+0020 and a handful of others but NOT
 * U+200B ZERO WIDTH SPACE, while the database used `btrim()`, which removes
 * U+0020 and nothing else. Thirty zero-width spaces satisfied both, and an
 * empty justification was stored against a suppression valid for 300 days.
 *
 * The same hole opened here on the first run of the F6 harness: forty U+200B
 * passed `note.trim().length >= 12` and were then refused by the CHECK, so the
 * caller got a 500 with a constraint name instead of a 400 with a reason. The
 * fix is not a nicer error message — it is ONE predicate, stated twice.
 */
export function identityAckNoteProblem(note: unknown): string | null {
  if (typeof note !== 'string') return 'an acknowledgement must be text';
  const visible = note.replace(INVISIBLE, '');
  if (visible.length < MIN_IDENTITY_ACK_NOTE) {
    return `an acknowledgement needs at least ${MIN_IDENTITY_ACK_NOTE} characters that occupy `
      + 'ink saying what was found; invisible characters do not count';
  }
  if (!/[\p{L}\p{N}]/u.test(visible)) {
    return 'an acknowledgement needs at least one letter or digit: punctuation alone says '
      + 'nothing that can be read a year later';
  }
  return null;
}

/** Two identity values are the same value. Case-insensitive, invisible-blind. */
export function identityValuesEqual(a: string | null, b: string | null): boolean {
  if (a === null || b === null) return a === b;
  return fold(a) === fold(b);
}

// ============================================================================
// 3. Firmware ordering
// ============================================================================

const CHANNEL_RANK: Readonly<Record<string, number>> = {
  alpha: 0,
  development: 1,
  beta: 1,
  rc: 2,
  testing: 2,
  '': 3,
  stable: 3,
  long: 3,
};

/**
 * Order two firmware strings.
 *
 * Returns a negative number when `a` is older, positive when `a` is newer, `0`
 * when they are the same version, and `null` when THIS FUNCTION CANNOT TELL —
 * two vendor strings with no comparable numeric spine, or a difference that
 * survives the comparison. `null` is not a failure: it becomes
 * `firmware_changed`, which is a true statement, where guessing a direction
 * would put "downgraded" on a screen an operator acts on.
 *
 * Handles `7.14.3`, `6.49.10`, `7.16beta3`, `7.15rc2`, `3.9.7.2` (DrayTek) and
 * `V5.70(ABLN.2)` (Zyxel, whose numeric spine is `5.70`).
 */
export function compareOsVersion(a: string, b: string): number | null {
  const parse = (raw: string): { nums: number[]; channel: string; build: number } | null => {
    const m = /^[vV]?\s*(\d+(?:\.\d+)*)(.*)$/.exec(tidy(raw));
    if (!m) return null;
    const nums = m[1].split('.').map((n) => Number.parseInt(n, 10));
    if (nums.some((n) => !Number.isFinite(n))) return null;
    const tail = fold(m[2]).replace(/^[-_.]/, '');
    const cm = /^([a-z]*)(\d*)/.exec(tail);
    const word = cm ? cm[1] : '';
    // A tail we do not recognise (a Zyxel bracketed build id, a vendor suffix)
    // is not a channel; it is noise on top of a comparable numeric spine.
    const channel = word in CHANNEL_RANK ? word : '';
    const build = cm && cm[2] ? Number.parseInt(cm[2], 10) : 0;
    // The build number is kept OUT of `nums`. Appending it to the numeric
    // spine made `7.15rc2` compare as `[7,15,2]` against `7.15`'s `[7,15,0]`,
    // so a release candidate came out NEWER than the release it precedes and
    // an upgrade off it was reported as a downgrade. The spine is compared
    // first, then the channel, and the build only breaks a tie inside one
    // channel.
    return { nums, channel, build };
  };

  const pa = parse(a);
  const pb = parse(b);
  if (!pa || !pb) return null;

  const width = Math.max(pa.nums.length, pb.nums.length);
  for (let i = 0; i < width; i++) {
    const x = pa.nums[i] ?? 0;
    const y = pb.nums[i] ?? 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  const ra = CHANNEL_RANK[pa.channel];
  const rb = CHANNEL_RANK[pb.channel];
  if (ra === undefined || rb === undefined) return null;
  if (ra !== rb) return ra < rb ? -1 : 1;
  if (pa.build !== pb.build) return pa.build < pb.build ? -1 : 1;
  // Same numbers, same channel, different strings: we saw a difference we
  // cannot order. Say so rather than call it "no change".
  return fold(a) === fold(b) ? 0 : null;
}

// ============================================================================
// 4. The verdict
// ============================================================================

export interface IdentitySnapshot {
  serial: string | null;
  systemIdentity: string | null;
  model: string | null;
  osVersion: string | null;
}

export const EMPTY_IDENTITY: Readonly<IdentitySnapshot> = {
  serial: null,
  systemIdentity: null,
  model: null,
  osVersion: null,
};

export interface IdentityChange {
  kind: IdentityEventKind;
  severity: IdentityEventSeverity;
  /** Which of the four moved. Never empty. */
  changed: IdentityAttributeName[];
  /** The reference as it stood BEFORE this observation. */
  previous: IdentitySnapshot;
  /** The observation, normalised. Unanswered attributes are `null` here even
   *  though the reference carries them forward — the event records what the
   *  box actually said. */
  observed: IdentitySnapshot;
  /**
   * DECISION 5. `true` means: the last config snapshot of this device is no
   * longer a reference, and the drift that follows is not drift. It is a FLAG.
   * Nothing in this package or in the service acts on it; a human does.
   */
  invalidatesBaseline: boolean;
  reason: string;
}

export interface IdentityVerdict {
  events: IdentityChange[];
  /** What to store as the reference for next time. Sticky: an attribute the
   *  box did not answer keeps its previous value (decision 1). */
  reference: IdentitySnapshot;
  /** Attributes the box did not answer this time, in `IDENTITY_ATTRIBUTES`
   *  order. `serial` appearing here is the CHR case and the flaky-read case,
   *  and it is why no event was raised for it. */
  unanswered: IdentityAttributeName[];
  /** The observation carried no usable attribute at all. The caller must NOT
   *  record it: an empty observation is a failed read, not a fact about a box. */
  empty: boolean;
}

/** Normalise a raw reading into the shape the classifier compares. */
export function normalizeIdentitySnapshot(raw: Partial<IdentitySnapshot>): IdentitySnapshot {
  return {
    serial: normalizeIdentityAttribute('serial', raw.serial),
    systemIdentity: normalizeIdentityAttribute('system_identity', raw.systemIdentity),
    model: normalizeIdentityAttribute('model', raw.model),
    osVersion: normalizeIdentityAttribute('os_version', raw.osVersion),
  };
}

/** The two kinds that mean "the reference config no longer describes this
 *  box". Used to set the flag here, and read back from stored rows by
 *  `identityWatch.service.ts` when it answers "is the snapshot still good?". */
export function isBaselineInvalidatingKind(kind: IdentityEventKind): boolean {
  return kind === 'hardware_replacement' || kind === 'factory_reset';
}

/** The three firmware kinds, as one predicate. A firmware move does NOT
 *  invalidate the reference — the box is the same box — but it changes what an
 *  export looks like, so a reader comparing a snapshot across one deserves to
 *  be told. */
export function isFirmwareEventKind(kind: IdentityEventKind): boolean {
  return (
    kind === 'firmware_upgraded' || kind === 'firmware_downgraded' || kind === 'firmware_changed'
  );
}

function pick(snapshot: IdentitySnapshot, attribute: IdentityAttributeName): string | null {
  switch (attribute) {
    case 'serial':
      return snapshot.serial;
    case 'system_identity':
      return snapshot.systemIdentity;
    case 'model':
      return snapshot.model;
    case 'os_version':
      return snapshot.osVersion;
    default:
      return null;
  }
}

/**
 * THE decision.
 *
 * `reference` is what we believed this device to be, or `null` when we have
 * never observed it. `observed` is what the box just said — RAW; it is
 * normalised here so that no caller can skip decisions 1 and 2 by handing over
 * a pre-cleaned value.
 *
 * PURE. No clock, no I/O. The timestamps and the persistence belong to
 * `identityWatch.service.ts`; the judgement belongs here.
 */
export function classifyIdentityChange(
  reference: Partial<IdentitySnapshot> | null,
  observed: Partial<IdentitySnapshot>,
): IdentityVerdict {
  const ref: IdentitySnapshot = reference
    ? normalizeIdentitySnapshot(reference)
    : { ...EMPTY_IDENTITY };
  const obs = normalizeIdentitySnapshot(observed);

  const unanswered = IDENTITY_ATTRIBUTES.filter((a) => pick(obs, a) === null);
  const empty = unanswered.length === IDENTITY_ATTRIBUTES.length;

  // DECISION 1, applied once, for every attribute, before anything is compared.
  const carried: IdentitySnapshot = {
    serial: obs.serial ?? ref.serial,
    systemIdentity: obs.systemIdentity ?? ref.systemIdentity,
    model: obs.model ?? ref.model,
    osVersion: obs.osVersion ?? ref.osVersion,
  };

  if (empty) {
    return { events: [], reference: { ...ref }, unanswered: [...unanswered], empty: true };
  }

  const events: IdentityChange[] = [];
  const known = IDENTITY_ATTRIBUTES.some((a) => pick(ref, a) !== null);

  // ── The gaps this observation filled. Never an alarm. ─────────────────────
  const learned = IDENTITY_ATTRIBUTES.filter(
    (a) => pick(ref, a) === null && pick(obs, a) !== null,
  );

  // ── DECISION 3: a serial that moved between two REAL values. Exclusive. ──
  const replaced =
    ref.serial !== null && obs.serial !== null && !identityValuesEqual(ref.serial, obs.serial);

  if (replaced) {
    const changed = IDENTITY_ATTRIBUTES.filter(
      (a) => pick(obs, a) !== null && !identityValuesEqual(pick(ref, a), pick(obs, a)),
    );
    events.push({
      kind: 'hardware_replacement',
      severity: 'critical',
      changed,
      previous: { ...ref },
      observed: { ...obs },
      invalidatesBaseline: true,
      reason:
        `serial changed from "${ref.serial}" to "${obs.serial}": this is a different ` +
        'chassis. The last config snapshot describes the box that left, so the drift ' +
        'that follows is not drift — review before trusting it.',
    });
    return { events, reference: carried, unanswered: [...unanswered], empty: false };
  }

  if (learned.length > 0) {
    events.push({
      kind: 'identity_learned',
      severity: 'info',
      changed: learned,
      previous: { ...ref },
      observed: { ...obs },
      invalidatesBaseline: false,
      reason: known
        ? `first reading of ${learned.join(', ')} for this device`
        : 'first identity ever recorded for this device',
    });
  }

  // ── DECISION 4: same serial, and the name moved. ─────────────────────────
  if (
    ref.systemIdentity !== null &&
    obs.systemIdentity !== null &&
    !identityValuesEqual(ref.systemIdentity, obs.systemIdentity)
  ) {
    const wiped =
      isFactoryDefaultIdentity(obs.systemIdentity) && !isFactoryDefaultIdentity(ref.systemIdentity);
    events.push({
      kind: wiped ? 'factory_reset' : 'system_identity_renamed',
      severity: wiped ? 'critical' : 'notice',
      changed: ['system_identity'],
      previous: { ...ref },
      observed: { ...obs },
      invalidatesBaseline: wiped,
      reason: wiped
        ? `the box still answers serial "${carried.serial ?? 'unknown'}" but its name came ` +
          `back as the vendor default "${obs.systemIdentity}": it was wiped, not renamed. ` +
          'Its configuration is gone and the last snapshot no longer describes it.'
        : `system identity renamed from "${ref.systemIdentity}" to "${obs.systemIdentity}" ` +
          'on the same chassis',
    });
  }

  // ── Firmware. Same box; the reference config still describes it. ─────────
  if (
    ref.osVersion !== null &&
    obs.osVersion !== null &&
    !identityValuesEqual(ref.osVersion, obs.osVersion)
  ) {
    const order = compareOsVersion(ref.osVersion, obs.osVersion);
    const kind: IdentityEventKind =
      order === null || order === 0
        ? 'firmware_changed'
        : order < 0
          ? 'firmware_upgraded'
          : 'firmware_downgraded';
    events.push({
      kind,
      severity: kind === 'firmware_upgraded' ? 'info' : 'notice',
      changed: ['os_version'],
      previous: { ...ref },
      observed: { ...obs },
      invalidatesBaseline: false,
      reason:
        `firmware moved from "${ref.osVersion}" to "${obs.osVersion}" on the same chassis` +
        (kind === 'firmware_changed' ? ' (the two strings cannot be ordered)' : ''),
    });
  }

  // ── Model. Same serial, different designation: our record or our read. ───
  if (ref.model !== null && obs.model !== null && !identityValuesEqual(ref.model, obs.model)) {
    events.push({
      kind: 'model_changed',
      severity: 'notice',
      changed: ['model'],
      previous: { ...ref },
      observed: { ...obs },
      invalidatesBaseline: false,
      reason:
        `model changed from "${ref.model}" to "${obs.model}" while the serial did not: ` +
        'either the inventory was wrong or one of the two readings was',
    });
  }

  return { events, reference: carried, unanswered: [...unanswered], empty: false };
}
