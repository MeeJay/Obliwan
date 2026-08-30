import type { Knex } from 'knex';

/**
 * 022_fix_weather.ts — the schema half of one F5 audit finding.
 *
 * ┌─ WHAT THIS MIGRATION IS FOR, IN ONE SENTENCE ─────────────────────────────┐
 * │ To let an incident member remember WHICH LINE it voted for, so that five  │
 * │ routers behind one DSL modem cannot be counted as five sites.             │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * THE DEFECT. `devices.site_id` is nullable (migration 002) and nothing fills
 * it in — not device creation, not binding a concentrator discovery. Every
 * quorum count in F5 was `COUNT(DISTINCT COALESCE(site_id, -device_id))`, so a
 * site whose routers have no `site_id` contributed ONE VOTE PER ROUTER. Five
 * CPEs behind a single line, one caller-ip between them: that line bounces, the
 * five sessions come back on one new address, and the correlator reports
 * `quorum:5/5_sites,1.00/0.25_of_asn` — both quorums, absolute and relative,
 * satisfied by one line and one bounce. `shared/src/weather.ts` opens by
 * declaring exactly that conclusion untakeable.
 *
 * THE FIX, AND WHY IT NEEDS A COLUMN. The quorum now counts `lineKeyOf()`:
 * the site id when there is one, otherwise the PUBLIC ADDRESS the device
 * egressed from. `wan_path_events` already carries `from_ip`, so the numerator
 * and the denominator can compute that key from the row they are already
 * reading. `operator_incident_members` cannot: it is the durable record of a
 * vote — it is what `current_site_count` and `peak_site_count` are counted
 * from, months after the event rows behind it may have been pruned — and it
 * holds no address at all. The key is therefore RESOLVED WHEN THE MEMBER JOINS
 * AND STORED, which also means a member's identity cannot silently change
 * underneath an open incident because a device was re-addressed mid-outage.
 *
 * ┌─ THREE DECISIONS ─────────────────────────────────────────────────────────┐
 * │                                                                           │
 * │ 1. NULLABLE, WITH THE READS COALESCING. Rows written before this          │
 * │    migration have no line key and must keep counting exactly as they did  │
 * │    — `COALESCE(m.line_key, 'site:'||site_id, 'dev:'||device_id)` is the   │
 * │    read, and it reproduces the old arithmetic for old rows rather than    │
 * │    back-filling a guess. Back-filling would mean inventing which line a   │
 * │    device was on during an incident that is already closed, from a        │
 * │    `from_ip` that may since have changed hands.                           │
 * │                                                                           │
 * │ 2. varchar(72) FOR A LONGEST VALUE OF 50. `line:` + a full IPv6 literal   │
 * │    (`2001:0db8:0000:0000:0000:ff00:0042:8329`, 39 characters, 45 with a   │
 * │    zone) is 50. `site:` + a 32-bit id is 15. The column is wider than the │
 * │    longest value its vocabulary can produce, which is the same rule       │
 * │    migration 021 applies to every CHECK-backed column it declares.        │
 * │                                                                           │
 * │ 3. NO CHECK ON THE PREFIX. The three namespaces (`site:`, `line:`,        │
 * │    `dev:`) are produced by one pure function and never typed by a human,  │
 * │    and a CHECK enumerating them would have to be edited in lockstep with  │
 * │    a fourth. What matters is that the value is OPAQUE and compared only   │
 * │    for equality; an unrecognised prefix costs one extra distinct key, not │
 * │    a wrong verdict.                                                       │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * SECRETS (§8.2): a line key is a site id or a PUBLIC egress address — the same
 * datum `wan_path_events.from_ip` has held since 021. No credential, no vault
 * reference, nothing a driver writes into.
 */

/** `line:` + a full IPv6 literal with a zone = 50 characters. */
const LINE_KEY_WIDTH = 72;

export async function up(knex: Knex): Promise<void> {
  await knex.schema.alterTable('operator_incident_members', (t) => {
    t.string('line_key', LINE_KEY_WIDTH).nullable();
  });

  // The clearing arithmetic reads (tenant, incident, line_key) on every sweep,
  // for every live incident. Partial: rows predating this migration have no key
  // and are resolved by the COALESCE in the read, not by this index.
  await knex.schema.raw(
    'CREATE INDEX oim_incident_line_idx ON operator_incident_members ' +
      '(tenant_id, incident_id, line_key) WHERE line_key IS NOT NULL',
  );
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.raw('DROP INDEX IF EXISTS oim_incident_line_idx');
  await knex.schema.alterTable('operator_incident_members', (t) => {
    t.dropColumn('line_key');
  });
}
