/* eslint-disable @typescript-eslint/no-explicit-any */
/**
 * M5 — adversarial verification of `variableResolver.service.ts`.
 * Run against a DISPOSABLE PostgreSQL. Direct service calls, no HTTP.
 *
 * Runs on the REAL `config_variables` of migration 008 (written concurrently by
 * another agent), including its `is_secret <-> secret_enc <-> value` CHECK and
 * its `config_variables_key_chk`. Nothing is stubbed.
 */
import { db } from '../src/db';
import {
  variableResolver,
  VariableResolutionError,
  ImpureContextError,
  assertJsonPure,
  redactedPlaceholder,
  assertNoPlaintextSecret,
  type VarSchema,
} from '../src/services/template/variableResolver.service';
import { setVariableSchema, varSchemaSchema } from '../src/validators/template.schema';

let pass = 0;
let fail = 0;
const failures: string[] = [];
function ok(name: string, cond: boolean, detail = '') {
  if (cond) {
    pass++;
    console.log(`PASS  ${name}${detail ? ' :: ' + detail : ''}`);
  } else {
    fail++;
    failures.push(name + (detail ? ' :: ' + detail : ''));
    console.log(`FAIL  ${name} :: ${detail}`);
  }
}

// Count the queries the resolver actually issues (AUDIT-CORR §2.3: one query
// for the chain, never N+1).
let queryCount = 0;
let counting = false;
db.on('query', () => {
  if (counting) queryCount++;
});
async function counted<T>(fn: () => Promise<T>): Promise<{ result: T; queries: number }> {
  queryCount = 0;
  counting = true;
  try {
    const result = await fn();
    return { result, queries: queryCount };
  } finally {
    counting = false;
  }
}

async function main() {
  await db.migrate.latest();
  // Idempotent: the fixtures below are rebuilt from scratch on every run.
  await db.raw(
    'truncate config_variables, group_closure, devices, device_groups, tenants restart identity cascade',
  );

  // ── Fixtures ──────────────────────────────────────────────────────────────
  const [acme] = await db('tenants').insert({ name: 'Acme', slug: 'acme' }).returning('id');
  const [globex] = await db('tenants').insert({ name: 'Globex', slug: 'globex' }).returning('id');
  const A = acme.id as number;
  const G = globex.id as number;

  // Acme: a FOUR-level chain  FR > IDF > Paris > Paris-Nord
  const mkGroup = async (tenant: number, name: string, slug: string, parent: number | null) =>
    (
      await db('device_groups')
        .insert({ tenant_id: tenant, name, slug, parent_id: parent })
        .returning('id')
    )[0].id as number;

  const gFr = await mkGroup(A, 'FR', 'fr', null);
  const gIdf = await mkGroup(A, 'IDF', 'idf', gFr);
  const gParis = await mkGroup(A, 'Paris', 'paris', gIdf);
  const gNord = await mkGroup(A, 'Paris-Nord', 'paris-nord', gParis);

  // group_closure is maintained by group.service in production; here it is
  // written explicitly so the fixture is self-evident.
  const closure: [number, number, number][] = [
    [gFr, gFr, 0],
    [gIdf, gIdf, 0],
    [gParis, gParis, 0],
    [gNord, gNord, 0],
    [gFr, gIdf, 1],
    [gFr, gParis, 2],
    [gFr, gNord, 3],
    [gIdf, gParis, 1],
    [gIdf, gNord, 2],
    [gParis, gNord, 1],
  ];
  await db('group_closure').insert(
    closure.map(([a, d, depth]) => ({ ancestor_id: a, descendant_id: d, depth })),
  );

  // Globex: its own group, with variables of the same names.
  const gEvil = await mkGroup(G, 'Globex-HQ', 'globex-hq', null);
  await db('group_closure').insert({ ancestor_id: gEvil, descendant_id: gEvil, depth: 0 });

  const mkDevice = async (tenant: number, name: string, group: number | null) =>
    (
      await db('devices')
        .insert({
          tenant_id: tenant,
          name,
          brand: 'mikrotik',
          family: 'mikrotik_routeros7',
          group_id: group,
        })
        .returning('id')
    )[0].id as number;

  const dev = await mkDevice(A, 'cpe-paris-nord-1', gNord);
  const devNoGroup = await mkDevice(A, 'cpe-orphan', null);

  // ── 1. Precedence: device > near group > far group > tenant > global ──────
  const V = variableResolver;
  await V.set(A, 'global', null, 'wan_vlan', 100);
  await V.set(A, 'tenant', null, 'wan_vlan', 200);
  await V.set(A, 'group', gFr, 'wan_vlan', 300); // depth 3 — farthest
  await V.set(A, 'group', gIdf, 'wan_vlan', 400); // depth 2
  await V.set(A, 'group', gParis, 'wan_vlan', 500); // depth 1
  await V.set(A, 'group', gNord, 'wan_vlan', 600); // depth 0 — nearest
  await V.set(A, 'device', dev, 'wan_vlan', 700);

  // Each level also sets a key that no narrower level touches, so we can read
  // the whole ladder in one resolution.
  await V.set(A, 'global', null, 'ntp_server', 'ntp.global');
  await V.set(A, 'tenant', null, 'dns_server', '10.0.0.53');
  await V.set(A, 'group', gFr, 'country', 'FR');
  await V.set(A, 'group', gIdf, 'region', 'idf');
  await V.set(A, 'group', gParis, 'city', 'paris');
  await V.set(A, 'group', gNord, 'zone_code', 'pn');
  await V.set(A, 'device', dev, 'loopback', '10.255.0.1');

  const r1 = await counted(() => V.resolveForDevice(A, dev));
  const vars = r1.result.variables;
  ok('precedence: device wins over everything', vars.wan_vlan?.value === 700,
    `value=${vars.wan_vlan?.value} source=${vars.wan_vlan?.source}`);
  ok('origin of the winner is the device', vars.wan_vlan?.source === 'device' &&
    vars.wan_vlan?.sourceName === 'cpe-paris-nord-1');
  ok('4-level ladder is fully visible',
    vars.country?.value === 'FR' && vars.region?.value === 'idf' &&
    vars.city?.value === 'paris' && vars.zone_code?.value === 'pn',
    'FR/idf/paris/pn');
  ok('global and tenant levels resolve',
    vars.ntp_server?.value === 'ntp.global' && vars.ntp_server?.source === 'global' &&
    vars.dns_server?.value === '10.0.0.53' && vars.dns_server?.source === 'tenant');
  ok('group origins carry name + closure depth',
    vars.country?.source === 'group' && vars.country?.sourceName === 'FR' &&
    vars.country?.sourceDepth === 3 && vars.zone_code?.sourceDepth === 0,
    `country depth=${vars.country?.sourceDepth}, zone_code depth=${vars.zone_code?.sourceDepth}`);
  ok('resolution costs 2 queries, not N+1', r1.queries === 2, `${r1.queries} queries`);

  // Remove the device override: the NEAREST group must take over, not the root.
  await V.remove(A, 'device', dev, 'wan_vlan');
  const r2 = await V.resolveForDevice(A, dev);
  ok('near group beats far group', r2.variables.wan_vlan?.value === 600 &&
    r2.variables.wan_vlan?.sourceName === 'Paris-Nord',
    `value=${r2.variables.wan_vlan?.value} from ${r2.variables.wan_vlan?.sourceName}`);
  await V.remove(A, 'group', gNord, 'wan_vlan');
  const r3 = await V.resolveForDevice(A, dev);
  ok('next-nearest group takes over', r3.variables.wan_vlan?.value === 500 &&
    r3.variables.wan_vlan?.sourceName === 'Paris');
  await V.remove(A, 'group', gParis, 'wan_vlan');
  await V.remove(A, 'group', gIdf, 'wan_vlan');
  const r4 = await V.resolveForDevice(A, dev);
  ok('root group beats tenant', r4.variables.wan_vlan?.value === 300);
  await V.remove(A, 'group', gFr, 'wan_vlan');
  const r5 = await V.resolveForDevice(A, dev);
  ok('tenant beats global', r5.variables.wan_vlan?.value === 200 &&
    r5.variables.wan_vlan?.source === 'tenant');
  await V.remove(A, 'tenant', null, 'wan_vlan');
  const r6 = await V.resolveForDevice(A, dev);
  ok('global is the floor', r6.variables.wan_vlan?.value === 100 &&
    r6.variables.wan_vlan?.source === 'global');

  // Restore a device-level value for the rest of the run.
  await V.set(A, 'device', dev, 'wan_vlan', 700);

  // ── 2. Cross-tenant isolation ─────────────────────────────────────────────
  await V.set(G, 'global', null, 'wan_vlan', 999);
  await V.set(G, 'global', null, 'globex_only', 'leak');
  await V.set(G, 'tenant', null, 'globex_only', 'leak-tenant');
  await V.set(G, 'group', gEvil, 'globex_only', 'leak-group');
  await V.set(G, 'device', dev, 'globex_only', 'leak-device'); // Acme's device id!

  const iso = await V.resolveForDevice(A, dev);
  ok('another tenant s global does not leak', iso.variables.wan_vlan?.value === 700);
  ok('another tenant s variables are invisible', iso.variables.globex_only === undefined,
    `got ${JSON.stringify(iso.variables.globex_only ?? null)}`);

  // AUDIT-SEC #9 — forge a cross-tenant closure edge. group_closure's FKs only
  // reference device_groups(id), so this row is insertable; the resolver's
  // `device_groups.tenant_id = :tenantId` join predicate is the only thing
  // standing between it and a customer inheriting another customer's config.
  await db('group_closure').insert({ ancestor_id: gEvil, descendant_id: gNord, depth: 1 });
  await V.set(G, 'group', gEvil, 'wan_vlan', 4242);
  const isoForged = await V.resolveForDevice(A, dev);
  ok('forged cross-tenant closure edge inherits NOTHING',
    isoForged.variables.wan_vlan?.value === 700 &&
      isoForged.variables.globex_only === undefined,
    `wan_vlan=${isoForged.variables.wan_vlan?.value}`);
  // And the reverse direction: Globex resolving through its own group must not
  // pick up Acme's rows either.
  const gDev = await mkDevice(G, 'globex-cpe', gEvil);
  const isoG = await V.resolveForDevice(G, gDev);
  ok('the other tenant sees only its own', isoG.variables.wan_vlan?.value === 4242 &&
    isoG.variables.city === undefined && isoG.variables.country === undefined);
  // Asking for a device that belongs to another tenant is not a silent empty
  // resolution — it does not exist.
  let crossThrew = '';
  try {
    await V.resolveForDevice(G, dev);
  } catch (e) {
    crossThrew = (e as Error).message;
  }
  ok('a device of another tenant does not resolve', crossThrew.includes('does not exist'),
    crossThrew);
  await db('group_closure').where({ ancestor_id: gEvil, descendant_id: gNord }).del();

  // ── 3. Required without default -> a NAMED error, never a hole ────────────
  const schema: VarSchema = {
    type: 'object',
    properties: {
      wan_vlan: { type: 'integer', minimum: 1, maximum: 4094 },
      site_code: { type: 'string', minLength: 2, 'x-obliwan-level': 'device' },
      mtu: { type: 'integer', default: 1500 },
      ntp_server: { type: 'string' },
      dns_server: { type: 'string' },
      country: { type: 'string' },
      region: { type: 'string' },
      city: { type: 'string' },
      zone_code: { type: 'string' },
      loopback: { type: 'string' },
    },
    required: ['wan_vlan', 'site_code'],
  };

  const rep = await V.resolveForDevice(A, dev, schema);
  ok('required-without-default is reported missing',
    rep.missing.length === 1 && rep.missing[0].key === 'site_code' &&
      rep.missing[0].expectedScope === 'device',
    JSON.stringify(rep.missing));
  ok('a schema default is applied WITH its origin',
    rep.variables.mtu?.value === 1500 && rep.variables.mtu?.source === 'default' &&
      rep.variables.mtu?.sourceName === 'Default');
  ok('report is not ok', rep.ok === false);

  let thrown: any = null;
  try {
    await V.buildRenderContext(A, dev, schema);
  } catch (e) {
    thrown = e;
  }
  ok('buildRenderContext THROWS instead of rendering a hole',
    thrown instanceof VariableResolutionError);
  const msg = String(thrown?.message ?? '');
  ok('the error names the variable', msg.includes('"site_code"'));
  ok('the error names the device', msg.includes(`#${dev}`) && msg.includes('cpe-paris-nord-1'));
  ok('the error names the level to fix it at', msg.includes('should be defined at the device level'));
  ok('the error prints the chain it searched',
    msg.includes('Global') && msg.includes(`Tenant #${A}`) && msg.includes('Group "FR"') &&
      msg.includes('Group "Paris-Nord"'),
    msg.slice(msg.indexOf('Chain searched')));
  ok('no context object escapes the failure', thrown?.missing?.[0]?.key === 'site_code');

  // Satisfy it, and the render proceeds.
  await V.set(A, 'device', dev, 'site_code', 'PN01');
  const rcOk = await V.buildRenderContext(A, dev, schema);
  ok('once defined, the context is complete',
    rcOk.context.site_code === 'PN01' && rcOk.context.wan_vlan === 700 &&
      rcOk.context.mtu === 1500);
  ok('the context has no undefined hole',
    !Object.values(rcOk.context).some((v) => v === undefined || v === null),
    JSON.stringify(rcOk.context));

  // Typed validation: a string where an integer was declared is refused.
  await V.set(A, 'device', dev, 'wan_vlan', '700');
  const typed = await V.resolveForDevice(A, dev, schema);
  ok('a wrongly-typed value is a type error, not a render',
    typed.typeErrors.length === 1 && typed.typeErrors[0].key === 'wan_vlan' &&
      typed.typeErrors[0].sourceName === 'cpe-paris-nord-1',
    JSON.stringify(typed.typeErrors));
  await V.set(A, 'device', dev, 'wan_vlan', 5000);
  const outOfRange = await V.resolveForDevice(A, dev, schema);
  ok('an out-of-range value is refused too',
    outOfRange.typeErrors.some((t) => t.key === 'wan_vlan'),
    JSON.stringify(outOfRange.typeErrors));
  await V.set(A, 'device', dev, 'wan_vlan', 700);

  // ── 4. Secrets ────────────────────────────────────────────────────────────
  const PSK = 'S3cr3t-PSK-do-not-log-me';
  const secretSchema: VarSchema = {
    type: 'object',
    properties: {
      site_code: { type: 'string' },
      wan_vlan: { type: 'integer' },
      ipsec_psk: { 'x-obliwan-secret': true, 'x-obliwan-level': 'device' },
    },
    required: ['ipsec_psk'],
  };

  const noSecret = await V.resolveForDevice(A, dev, secretSchema);
  ok('a missing SECRET is reported as a secret, not as a typo',
    noSecret.missing.length === 1 && noSecret.missing[0].key === 'ipsec_psk' &&
      noSecret.missing[0].reason === 'secret-declared-but-absent',
    JSON.stringify(noSecret.missing));

  await V.set(A, 'device', dev, 'ipsec_psk', PSK, true);

  const stored = await db('config_variables')
    .where({ tenant_id: A, scope: 'device', scope_id: dev, key: 'ipsec_psk' })
    .first('value', 'is_secret', 'secret_enc');
  ok('the secret is NOT stored in clear (008 decision 6: value IS NULL)',
    stored.is_secret === true && stored.value === null &&
      typeof stored.secret_enc === 'string' && !stored.secret_enc.includes(PSK),
    `value=${JSON.stringify(stored.value)} secret_enc=${String(stored.secret_enc).slice(0, 40)}...`);

  const sec = await V.resolveForDevice(A, dev, secretSchema);
  const sv = sec.variables.ipsec_psk;
  ok('the redacted form carries a placeholder, not the value',
    sv.value === redactedPlaceholder('ipsec_psk') && sv.isSecret && sv.redacted,
    String(sv.value));
  ok('the whole redacted report is free of the plaintext',
    !JSON.stringify(sec).includes(PSK));
  ok('the secret has a keyed fingerprint',
    sv.fingerprint?.algo === 'hmac-sha256/v1' && typeof sv.fingerprint?.fp === 'string' &&
      sv.fingerprint!.fp!.length === 22 && !sv.fingerprint!.fp!.includes(PSK),
    String(sv.fingerprint?.fp));

  const rcRedacted = await V.buildRenderContext(A, dev, secretSchema);
  ok('the DEFAULT render context is redacted',
    rcRedacted.mode === 'redacted' &&
      rcRedacted.context.ipsec_psk === redactedPlaceholder('ipsec_psk') &&
      !JSON.stringify(rcRedacted.context).includes(PSK));
  ok('secret keys are advertised', rcRedacted.secretKeys.includes('ipsec_psk'));

  const rcSecrets = await V.buildRenderContext(A, dev, secretSchema, { mode: 'secrets' });
  ok('the explicit secrets mode returns the plaintext',
    rcSecrets.context.ipsec_psk === PSK);
  ok('even in secrets mode, the redacted VIEW stays redacted',
    rcSecrets.variables.ipsec_psk.value === redactedPlaceholder('ipsec_psk'),
    'variables_snapshot would be safe to persist');

  // Fingerprint moves when the secret is rotated; the masked body does not.
  const fp1 = sv.fingerprint!.fp;
  await V.set(A, 'device', dev, 'ipsec_psk', 'a-completely-different-psk', true);
  const rotated = await V.resolveForDevice(A, dev, secretSchema);
  ok('rotating the secret changes the fingerprint',
    rotated.variables.ipsec_psk.fingerprint!.fp !== fp1);
  ok('rotating the secret does NOT change the masked value',
    rotated.variables.ipsec_psk.value === sv.value,
    'the masked artefact is not a rotation oracle');
  await V.set(A, 'device', dev, 'ipsec_psk', PSK, true);

  // A secret set at the tenant level is inherited and stays redacted.
  await V.set(A, 'tenant', null, 'radius_key', 'tenant-wide-radius', true);
  const inh = await V.resolveForDevice(A, dev);
  ok('an inherited secret is redacted at every level',
    inh.variables.radius_key.isSecret && inh.variables.radius_key.source === 'tenant' &&
      !JSON.stringify(inh).includes('tenant-wide-radius'));

  // The leak guard.
  const secrets = await V.loadSecrets(A, dev);
  ok('loadSecrets returns the plaintexts for the push path',
    secrets.some((s) => s.key === 'ipsec_psk' && s.plaintext === PSK));
  let leakGuard = '';
  try {
    assertNoPlaintextSecret(`/ip ipsec identity secret="${PSK}"`, secrets, 'rendered body');
  } catch (e) {
    leakGuard = (e as Error).message;
  }
  ok('assertNoPlaintextSecret catches a secret in a body to be stored',
    leakGuard.includes('ipsec_psk') && !leakGuard.includes(PSK), leakGuard);

  // A secret declared by the template but stored in clear = fail closed.
  await V.remove(A, 'device', dev, 'ipsec_psk');
  await V.set(A, 'device', dev, 'ipsec_psk', 'plaintext-oops', false);
  const clash = await V.resolveForDevice(A, dev, secretSchema);
  ok('a clear value for a declared-secret variable is refused',
    clash.typeErrors.some((t) => t.key === 'ipsec_psk' && t.message.includes('stored in clear')),
    JSON.stringify(clash.typeErrors));
  await V.set(A, 'device', dev, 'ipsec_psk', PSK, true);

  // A corrupted vault envelope must not degrade into a rendered hole.
  await db('config_variables')
    .where({ tenant_id: A, scope: 'device', scope_id: dev, key: 'ipsec_psk' })
    .update({ secret_enc: 'v1:1:AAAAAAAAAAAAAAAA:BBBBBBBBBBBBBBBBBBBBBB==:CCCC' });
  const corrupt = await V.resolveForDevice(A, dev, secretSchema);
  ok('a corrupted secret is rejected, not rendered',
    corrupt.rejected.some((r) => r.key === 'ipsec_psk') &&
      corrupt.variables.ipsec_psk === undefined && corrupt.ok === false,
    JSON.stringify(corrupt.rejected));
  await V.set(A, 'device', dev, 'ipsec_psk', PSK, true);

  // ── 5. R6 — nothing impure crosses into the worker ────────────────────────
  let protoWrite = '';
  try {
    await V.set(A, 'device', dev, '__proto__', { polluted: true } as any);
  } catch (e) {
    protoWrite = (e as Error).message;
  }
  ok('`__proto__` cannot be written as a variable name', protoWrite.includes('Illegal variable name'),
    protoWrite);
  ok('the API schema refuses it too',
    setVariableSchema.safeParse({ key: '__proto__', value: 1 }).success === false &&
      setVariableSchema.safeParse({ key: 'constructor', value: 1 }).success === false &&
      setVariableSchema.safeParse({ key: 'wan_vlan', value: 1 }).success === true);

  // Forge the rows straight into the table, behind the API's back.
  // `__proto__` is stopped by migration 008's own key CHECK...
  let dbRefusedProto = false;
  try {
    await db.raw(
      `insert into config_variables (tenant_id, scope, scope_id, key, value, is_secret)
         values (?, 'device', ?, '__proto__', '{"polluted":true}'::jsonb, false)`,
      [A, dev],
    );
  } catch (e) {
    dbRefusedProto = String((e as any).constraint).includes('key_chk');
  }
  ok('the database itself refuses `__proto__` as a key', dbRefusedProto);

  // ...but `constructor` and `prototype` MATCH `^[a-z][a-zA-Z0-9_]{0,119}$`, so
  // the database accepts them. 008's header claims otherwise. This is the case
  // FORBIDDEN_KEYS exists for, and it is the only thing standing in the way.
  for (const k of ['constructor', 'prototype']) {
    await db.raw(
      `insert into config_variables (tenant_id, scope, scope_id, key, value, is_secret)
         values (?, 'device', ?, ?, '{"polluted":true}'::jsonb, false)`,
      [A, dev, k],
    );
  }
  const dbAccepted = await db('config_variables')
    .whereIn('key', ['constructor', 'prototype'])
    .count<{ count: string }[]>('* as count');
  ok('the database ACCEPTS `constructor` / `prototype` (008 header is wrong)',
    Number(dbAccepted[0].count) === 2);

  const forged = await V.resolveForDevice(A, dev);
  ok('the resolver REJECTS them at read time anyway',
    forged.rejected.length === 2 &&
      forged.rejected.every((r) => r.reason.includes('VARIABLE_KEY_RE')) &&
      forged.variables['constructor'] === undefined &&
      forged.variables['prototype'] === undefined,
    JSON.stringify(forged.rejected.map((r) => r.key)));
  ok('and it makes the render refuse to proceed', forged.ok === false);
  let forgedThrow: any = null;
  try {
    await V.buildRenderContext(A, dev, null);
  } catch (e) {
    forgedThrow = e;
  }
  ok('buildRenderContext refuses while a forged row exists',
    forgedThrow instanceof VariableResolutionError);
  ok('({}).polluted is still undefined', ({} as any).polluted === undefined);
  await db('config_variables').whereIn('key', ['constructor', 'prototype']).del();

  // `toString` / `valueOf` / `hasOwnProperty` are legal keys for both the regex
  // and 008's CHECK. On a `{}` map they resolve to inherited FUNCTIONS, which
  // would read as "already present" and hand a caller a callable instead of a
  // value. This is why every map in the resolver is null-prototype.
  await V.set(A, 'device', dev, 'toString', 'a-real-value');
  const shadow = await V.resolveForDevice(A, dev, {
    type: 'object',
    properties: { valueof: { type: 'string', default: 'defaulted' }, toString: { type: 'string' } },
  });
  ok('a variable named `toString` is a value, not the inherited function',
    shadow.variables.toString?.value === 'a-real-value' &&
      typeof shadow.variables.toString?.value === 'string',
    typeof shadow.variables.toString?.value);
  ok('an unset variable does not resolve through the prototype',
    shadow.variables.valueof?.source === 'default' &&
      (shadow.variables as any).hasOwnProperty === undefined,
    'the prototype chain is not a value source');
  const rcShadow = await V.buildRenderContext(A, dev, null);
  ok('and it reaches the context as a plain string',
    rcShadow.context.toString === 'a-real-value');
  await V.remove(A, 'device', dev, 'toString');

  const rcPure = await V.buildRenderContext(A, dev, null, {
    extra: { device_name: 'cpe-paris-nord-1', os_version: '7.14.3' },
  });
  ok('the context is a plain object with a plain prototype',
    Object.getPrototypeOf(rcPure.context) === Object.prototype);
  ok('the context carries no function anywhere',
    !Object.values(rcPure.context).some((v) => typeof v === 'function'));
  ok('`extra` device facts are merged', rcPure.context.device_name === 'cpe-paris-nord-1');
  ok('the context survives a structuredClone (worker boundary)',
    JSON.stringify(structuredClone(rcPure.context)) === JSON.stringify(rcPure.context));

  const impure: [string, unknown][] = [
    ['a Date', new Date()],
    ['a Buffer', Buffer.from('x')],
    ['a function', () => 1],
    ['a class instance', new (class Live { x = 1 })()],
    ['a Map', new Map()],
    ['NaN', NaN],
    ['undefined', undefined],
    ['a getter', Object.defineProperty({}, 'g', { get: () => 1, enumerable: true })],
  ];
  let impureCaught = 0;
  for (const [label, v] of impure) {
    try {
      assertJsonPure({ x: v });
      console.log(`FAIL  assertJsonPure accepted ${label}`);
    } catch (e) {
      if (e instanceof ImpureContextError) impureCaught++;
    }
  }
  ok('assertJsonPure rejects every live value', impureCaught === impure.length,
    `${impureCaught}/${impure.length}`);

  const cyc: any = { a: 1 };
  cyc.self = cyc;
  let cycCaught = false;
  try {
    assertJsonPure(cyc);
  } catch {
    cycCaught = true;
  }
  ok('assertJsonPure rejects a cycle', cycCaught);

  let extraCollision = '';
  try {
    await V.buildRenderContext(A, dev, null, { extra: { wan_vlan: 1 } });
  } catch (e) {
    extraCollision = (e as Error).message;
  }
  ok('device facts cannot silently shadow an operator variable',
    extraCollision.includes('collides'), extraCollision);

  // ── 6. Ten devices, ten contexts ──────────────────────────────────────────
  const fleet: number[] = [];
  for (let i = 0; i < 10; i++) {
    const g = [gFr, gIdf, gParis, gNord][i % 4];
    const id = await mkDevice(A, `fleet-${i}`, g);
    fleet.push(id);
    await variableResolver.set(A, 'device', id, 'site_code', `SITE${i}`);
  }
  const fleetSchema: VarSchema = {
    type: 'object',
    properties: {
      site_code: { type: 'string', minLength: 2 },
      wan_vlan: { type: 'integer' },
      country: { type: 'string' },
    },
    required: ['site_code', 'country'],
  };
  const t0 = Date.now();
  const contexts = [];
  for (const id of fleet) contexts.push(await V.buildRenderContext(A, id, fleetSchema));
  const elapsed = Date.now() - t0;
  ok('10 devices produce 10 distinct, complete contexts',
    contexts.length === 10 &&
      new Set(contexts.map((c) => c.context.site_code)).size === 10 &&
      contexts.every((c) => c.context.country === 'FR'),
    `${elapsed} ms total, ${(elapsed / 10).toFixed(1)} ms/device`);
  ok('the per-group variable differs across the fleet',
    contexts[3].context.zone_code === 'pn' && contexts[0].context.zone_code === undefined,
    'device #3 is in Paris-Nord, device #0 is in FR');

  // A device with no group at all resolves global+tenant only, and still
  // refuses when a group-level variable was required.
  const orphan = await V.resolveForDevice(A, devNoGroup, fleetSchema);
  ok('a device with no group still resolves the global levels',
    orphan.variables.ntp_server?.value === 'ntp.global');
  ok('and it names what is missing rather than rendering it empty',
    orphan.missing.map((m) => m.key).sort().join(',') === 'country,site_code',
    JSON.stringify(orphan.missing.map((m) => m.key)));

  // ── 7. Group-level view (the variables UI) ────────────────────────────────
  const gview = await V.resolveForGroup(A, gParis);
  ok('a group inherits from its ancestors but not from itself',
    gview.inherited.country?.value === 'FR' && gview.inherited.region?.value === 'idf' &&
      gview.inherited.city === undefined && gview.overrides.city?.value === 'paris',
    'inherited: FR/idf, own: paris');

  // ── 8. Write-side invariants ──────────────────────────────────────────────
  const writeCases: [string, () => Promise<unknown>][] = [
    ['global with a scope_id', () => V.set(A, 'global', 1, 'x_key', 1)],
    ['tenant with a scope_id', () => V.set(A, 'tenant', 1, 'x_key', 1)],
    ['group without a scope_id', () => V.set(A, 'group', null, 'x_key', 1)],
    ['device without a scope_id', () => V.set(A, 'device', null, 'x_key', 1)],
    ['a non-string secret', () => V.set(A, 'device', dev, 'x_key', 42, true)],
    ['an impure value', () => V.set(A, 'device', dev, 'x_key', { d: new Date() } as any)],
  ];
  let writeRefused = 0;
  for (const [label, fn] of writeCases) {
    try {
      await fn();
      console.log(`FAIL  write accepted ${label}`);
    } catch {
      writeRefused++;
    }
  }
  ok('every write-side invariant is enforced', writeRefused === writeCases.length,
    `${writeRefused}/${writeCases.length}`);

  // Upsert really upserts at the two NULL-scope_id levels — the partial unique
  // index of AUDIT-CORR §1.1 is what makes this true.
  await V.set(A, 'global', null, 'dup_key', 1);
  await V.set(A, 'global', null, 'dup_key', 2);
  await V.set(A, 'tenant', null, 'dup_key', 3);
  const dupRows = await db('config_variables')
    .where({ tenant_id: A, key: 'dup_key' })
    .select('scope', 'value');
  ok('a NULL-scope_id upsert updates instead of appending',
    dupRows.length === 2 &&
      dupRows.find((r: any) => r.scope === 'global')?.value === 2 &&
      dupRows.find((r: any) => r.scope === 'tenant')?.value === 3,
    JSON.stringify(dupRows));
  // The same key at the same level in the OTHER tenant is a different row.
  await V.set(G, 'global', null, 'dup_key', 77);
  const dupG = await db('config_variables')
    .where({ tenant_id: G, scope: 'global', key: 'dup_key' })
    .first('value');
  const dupA = await db('config_variables')
    .where({ tenant_id: A, scope: 'global', key: 'dup_key' })
    .first('value');
  ok('two tenants hold two different values for the same global key',
    dupG.value === 77 && dupA.value === 2, `A=${dupA.value} G=${dupG.value}`);

  // setBulk is atomic: one bad entry writes nothing.
  try {
    await V.setBulk(A, 'device', dev, [
      { key: 'bulk_a', value: 1 },
      { key: 'BULK_B', value: 2 },
    ]);
  } catch {
    /* expected */
  }
  const bulkRow = await db('config_variables')
    .where({ tenant_id: A, scope: 'device', scope_id: dev, key: 'bulk_a' })
    .first();
  ok('setBulk validates everything before writing anything', bulkRow === undefined);

  // ── 9. var_schema validation at the API boundary ──────────────────────────
  ok('varSchemaSchema refuses a __proto__ property',
    varSchemaSchema.safeParse({ properties: { __proto__: { type: 'string' } } }).success === false);
  ok('varSchemaSchema refuses a default on a secret',
    varSchemaSchema.safeParse({
      properties: { psk: { 'x-obliwan-secret': true, default: 'oops' } },
    }).success === false);
  ok('varSchemaSchema refuses a required that is not declared',
    varSchemaSchema.safeParse({ properties: { a: { type: 'string' } }, required: ['b'] })
      .success === false);
  ok('varSchemaSchema accepts a real one',
    varSchemaSchema.safeParse({
      type: 'object',
      properties: {
        site_code: { type: 'string', 'x-obliwan-level': 'device' },
        psk: { 'x-obliwan-secret': true },
      },
      required: ['site_code'],
    }).success === true);

  console.log(`\n${pass} passed, ${fail} failed`);
  if (fail) {
    console.log('FAILURES:');
    for (const f of failures) console.log('  - ' + f);
  }
  await db.destroy();
  process.exit(fail ? 1 : 0);
}

main().catch(async (e) => {
  console.error(e);
  await db.destroy();
  process.exit(1);
});
