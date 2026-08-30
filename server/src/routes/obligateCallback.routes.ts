import { Router } from 'express';
import type { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import { sanitizeCapabilities } from '@obliwan/shared';
import { db } from '../db';
import { requireAuth, regenerateSession, invalidateIdentityCache } from '../middleware/auth';
import { invalidateMembershipCache } from '../middleware/tenant';
import { obligateService } from '../services/obligate.service';
import { tenantService } from '../services/tenant.service';
import { appConfigService } from '../services/appConfig.service';
import { destroyUserSessions } from '../utils/sessions';
import { logger } from '../utils/logger';

const router = Router();

/**
 * AUDIT-SEC #11 (MINEUR by exploitability, MAXIMAL by impact) — the three
 * machine-to-machine routes below compared the bearer token with `!==`, which
 * returns at the first differing byte. They carry no session, only
 * `apiLimiter` counts them, and `/sso-user-sync` alone can delete any user by
 * id or promote anyone to platform `admin`.
 *
 * `timingSafeEqual` throws on unequal lengths, which would itself leak the key
 * length, so both sides are hashed to a fixed 32 bytes first and the digests
 * are compared. Factored into one middleware so a fourth route cannot be added
 * with the old comparison.
 */
function sha256(value: string): Buffer {
  return crypto.createHash('sha256').update(value, 'utf8').digest();
}

async function requireObligateKey(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    res.status(401).json({ success: false, error: 'Missing Bearer token' });
    return;
  }
  const raw = await appConfigService.getObligateRaw();
  if (!raw.apiKey) {
    res.status(401).json({ success: false, error: 'Invalid API key' });
    return;
  }
  if (!crypto.timingSafeEqual(sha256(authHeader.slice(7)), sha256(raw.apiKey))) {
    res.status(401).json({ success: false, error: 'Invalid API key' });
    return;
  }
  next();
}

/**
 * GET /auth/callback?code=xxx&state=xxx
 * Called by Obligate after successful authentication.
 * Exchanges the code for user info, auto-provisions, creates session, redirects.
 */
router.get('/callback', async (req, res) => {
  try {
    const { code, state } = req.query as { code?: string; state?: string };
    if (!code) {
      res.status(400).json({ success: false, error: 'Missing code' });
      return;
    }

    // Validate OAuth state parameter to prevent login CSRF (RFC 6749 §10.12)
    const expectedState = req.session.oauthState;
    delete req.session.oauthState;
    if (!expectedState || !state || state !== expectedState) {
      logger.warn({ receivedState: state, hasExpected: !!expectedState }, 'Obligate callback: state mismatch — possible CSRF');
      res.redirect('/login?error=sso_failed');
      return;
    }

    // Build the redirect_uri that was used in the authorize request
    const protocol = req.headers['x-forwarded-proto'] || req.protocol;
    const host = req.headers['x-forwarded-host'] || req.headers.host;
    const redirectUri = `${protocol}://${host}/auth/callback`;

    // Exchange code with Obligate
    logger.info({ redirectUri }, 'Obligate callback: exchanging code');
    const assertion = await obligateService.exchangeCode(code, redirectUri);
    if (!assertion) {
      logger.warn('Obligate callback: exchange returned null — code invalid/expired or redirect_uri mismatch');
      res.redirect('/login?error=sso_failed');
      return;
    }
    logger.info({ obligateUserId: assertion.obligateUserId, username: assertion.username }, 'Obligate callback: exchange OK');

    // ── Resolve the local account this remote subject owns ─────────────────
    //
    // SECFIX-C2 (CRITIQUE). This block used to be:
    //
    //     if (assertion.linkedLocalUserId) {
    //       const existingUser = await db('users')
    //         .where({ id: assertion.linkedLocalUserId }).first();
    //       if (existingUser) { localUserId = assertion.linkedLocalUserId; ... }
    //
    // with no condition of any kind on `foreign_source`, followed a few dozen
    // lines below by a session opened on that row. `linkedLocalUserId` is a
    // FIELD OF THE ASSERTION: it is chosen by whatever answers
    // `POST /api/oauth/token/exchange` at `obligate_url`. An Obligate that is
    // compromised, mis-pointed by an admin, or simply impersonated by anyone
    // holding the API key (which SECFIX-C1 was publishing in a redirect
    // header) answered `{"role":"admin","linkedLocalUserId":1}` and thereby:
    // overwrote the LOCAL platform admin — id 1 on every install — with the
    // attacker's role, e-mail and display name, then logged the attacker in as
    // that account. `foreign_source` stayed NULL on the hijacked row, so
    // `/sso-user-sync` could not even be used to disable it afterwards, and
    // the legitimate administrator's password kept working: nothing surfaced
    // the takeover.
    //
    // `/sso-user-sync` was hardened against exactly this primitive ("this
    // endpoint may only act on accounts Obligate actually owns"). The login
    // path is strictly MORE powerful — it does not merely rewrite the account,
    // it establishes a session on it — and carried no such rule. It does now,
    // and it is the stricter of the two:
    //
    //   * `sso_foreign_users` — the real join table — is the AUTHORITY. If it
    //     holds a row for (obligate, obligateUserId), that row alone decides
    //     which local account this remote subject is.
    //   * `linkedLocalUserId` is demoted to a HINT, honoured only when the
    //     row it names is ALREADY federated by THIS provider AND THIS remote
    //     subject (`users.foreign_source = 'obligate'` AND
    //     `users.foreign_id = assertion.obligateUserId`).
    //   * A pure local account (`foreign_source IS NULL`) can never be adopted,
    //     nor can an account federated for a DIFFERENT remote subject. Either
    //     case logs a WARN and re-provisions a fresh `og_*` account instead.
    //
    // Nothing legitimate is lost. On the Obligate side the ONLY writer of
    // `user_app_links.remote_user_id` — the column that becomes
    // `linkedLocalUserId` — is `POST /api/apps/report-provision`
    // (server/src/routes/api.routes.ts:164), i.e. a value ObliWAN itself sent.
    // The field is an echo of our own bookkeeping, never an independent claim,
    // so requiring it to agree with our own records costs no valid flow.
    let localUserId = 0;
    let needsProvision = false;

    const hintedId = Number(assertion.linkedLocalUserId) || 0;

    const existingLink = await db('sso_foreign_users')
      .where({ foreign_source: 'obligate', foreign_user_id: assertion.obligateUserId })
      .first() as { local_user_id: number } | undefined;

    if (existingLink) {
      const linked = await db('users')
        .where({ id: existingLink.local_user_id })
        .first('id', 'foreign_source', 'foreign_id') as
          { id: number; foreign_source: string | null; foreign_id: number | null } | undefined;
      if (linked) {
        localUserId = linked.id;
        if (hintedId && hintedId !== linked.id) {
          logger.warn(
            { obligateUserId: assertion.obligateUserId, hintedId, linkedId: linked.id },
            'Obligate callback: assertion linkedLocalUserId disagrees with sso_foreign_users — the assertion is ignored',
          );
        }
        // Heal an account whose join-table row exists but whose mirror columns
        // were never written. This widens nothing: the join table has already
        // asserted the ownership we are recording.
        if (
          linked.foreign_source !== 'obligate'
          || Number(linked.foreign_id) !== Number(assertion.obligateUserId)
        ) {
          await db('users')
            .where({ id: localUserId })
            .update({ foreign_source: 'obligate', foreign_id: assertion.obligateUserId });
        }
      } else {
        logger.warn(`sso_foreign_users points to deleted user ${existingLink.local_user_id} — cleaning up and re-provisioning`);
        await db('sso_foreign_users')
          .where({ foreign_source: 'obligate', foreign_user_id: assertion.obligateUserId })
          .del();
        needsProvision = true;
      }
    } else if (hintedId) {
      const candidate = await db('users')
        .where({ id: hintedId })
        .first('id', 'foreign_source', 'foreign_id') as
          { id: number; foreign_source: string | null; foreign_id: number | null } | undefined;
      const adoptable = !!candidate
        && candidate.foreign_source === 'obligate'
        && candidate.foreign_id !== null
        && Number(candidate.foreign_id) === Number(assertion.obligateUserId);
      if (candidate && adoptable) {
        localUserId = candidate.id;
        // The mirror columns proved ownership but the join table had no row.
        // Write it, so the account is visible to the SSO revocation machinery
        // (`sso-user-sync` action 'delete' clears `sso_foreign_users` by
        // `local_user_id`).
        await db('sso_foreign_users')
          .insert({ foreign_source: 'obligate', foreign_user_id: assertion.obligateUserId, local_user_id: localUserId })
          .onConflict(['foreign_source', 'foreign_user_id'])
          .merge({ local_user_id: localUserId });
      } else {
        logger.warn(
          {
            obligateUserId: assertion.obligateUserId,
            hintedId,
            targetExists: !!candidate,
            targetForeignSource: candidate?.foreign_source ?? null,
            targetForeignId: candidate?.foreign_id ?? null,
          },
          'Obligate callback REFUSED account adoption: linkedLocalUserId does not name an account federated by this provider for this remote subject — re-provisioning instead',
        );
        // Tell Obligate its link is stale so it stops sending it.
        obligateService.reportProvision(assertion.obligateUserId, 0).catch(() => {});
        needsProvision = true;
      }
    } else {
      needsProvision = true;
    }

    if (needsProvision) {
      const [newUser] = await db('users')
        .insert({
          username: `og_${assertion.username}`,
          display_name: assertion.displayName || assertion.username,
          email: assertion.email,
          role: assertion.role === 'admin' ? 'admin' : 'user',
          is_active: true,
          foreign_source: 'obligate',
          foreign_id: assertion.obligateUserId,
          enrollment_version: 999,
        })
        .returning('id') as Array<{ id: number }>;
      localUserId = newUser.id;

      await db('sso_foreign_users')
        .insert({ foreign_source: 'obligate', foreign_user_id: assertion.obligateUserId, local_user_id: localUserId })
        .onConflict(['foreign_source', 'foreign_user_id'])
        .merge({ local_user_id: localUserId });

      obligateService.reportProvision(assertion.obligateUserId, localUserId).catch(() => {});
    }

    // ── Mirror the asserted profile onto the account we now own ────────────
    //
    // Previously this UPDATE lived inside each adoption branch above; it is
    // hoisted here so there is exactly ONE writer of `users.role` on this path
    // and so `previousRole` can be captured for SECFIX-R9 further down.
    const assertedRole = assertion.role === 'admin' ? 'admin' : 'user';
    let previousRole: string | null = null;
    if (!needsProvision) {
      const before = await db('users')
        .where({ id: localUserId })
        .first('role') as { role: string } | undefined;
      previousRole = before?.role ?? null;
      await db('users').where({ id: localUserId }).update({
        role: assertedRole,
        email: assertion.email,
        display_name: assertion.displayName,
        updated_at: new Date(),
      });
    }

    // ── Sync tenants + capabilities from Obligate (every SSO login) ────────
    //
    // SECFIX-M3 (MAJEUR) — the loop below used to be purely ADDITIVE: it
    // upserted whatever the assertion contained and removed NOTHING. A
    // contractor whose `globex` entitlement was withdrawn in Obligate kept his
    // `user_tenants` row, his `user_tenant_capabilities` row (`secret.read`
    // included) and his team memberships indefinitely — and ObliWAN refuses
    // local edits of an SSO user's tenants (`users.controller.ts:178`, "manage
    // from Obligate"), so the operator had no way to undo it by hand either.
    // The Obligate console displayed "no access to globex"; the product
    // disagreed, silently, and `POST /api/tenant/switch` still worked.
    //
    // The assertion is now treated as the COMPLETE state of what Obligate
    // governs — and of that only. The governed set is deliberately NOT "every
    // tenant this user has": a local admin can hand an SSO account a tenant
    // through `POST /api/tenants/:id/members` (tenant.routes.ts:129, which has
    // no SSO guard), and such a grant must not evaporate merely because
    // Obligate has never heard of it. Provenance is read off
    // `user_tenant_capabilities.source` — the one column that records who
    // granted what. A tenant carrying a row with `source = 'obligate'` was
    // granted HERE by a previous assertion and is therefore ours to revoke; a
    // tenant with no such row, or one marked `local`, is left strictly alone.
    //
    // Finding 16 of the same review: the three authorisation tables are now
    // written in ONE transaction together with the revocation, so a SIGTERM
    // landing between two statements can no longer leave Alice holding the
    // capabilities of an entitlement she no longer has.
    const assertedTenants = Array.isArray(assertion.tenants) ? assertion.tenants : [];
    const assertedTeams = new Set(
      (Array.isArray(assertion.teams) ? assertion.teams : []).map((s) => String(s)),
    );
    let revokedTenantIds: number[] = [];

    await db.transaction(async (trx) => {
      const assertedTenantIds: number[] = [];

      for (const t of assertedTenants) {
        const tenant = await trx('tenants').where({ slug: t.slug }).first() as { id: number } | undefined;
        if (!tenant) {
          logger.warn(
            { userId: localUserId, slug: t?.slug },
            'Obligate SSO: asserted tenant slug has no local tenant — entitlement ignored',
          );
          continue;
        }
        assertedTenantIds.push(tenant.id);
        const tenantRole = t.role === 'admin' ? 'admin' : 'member';

        await trx('user_tenants')
          .insert({ user_id: localUserId, tenant_id: tenant.id, role: tenantRole })
          .onConflict(['user_id', 'tenant_id'])
          .merge({ role: tenantRole });

        // ── Sync local team memberships from the Obligate assertion ────────
        // Previously SSO created tenant access but NOT team memberships, so the
        // user landed in a tenant with no group visibility — empty sidebar tree
        // and no group-scoped permissions — until an admin ticked the box by
        // hand. Match each asserted team to a local team in THIS tenant by id OR
        // name and ensure a membership row exists. Additive WITHIN an asserted
        // tenant (a membership granted by hand inside a tenant Obligate still
        // grants is preserved); memberships inside a tenant the assertion no
        // longer mentions are removed by the revocation pass below.
        if (assertedTeams.size > 0) {
          const localTeams = await trx('user_teams')
            .where({ tenant_id: tenant.id })
            .select('id', 'name') as Array<{ id: number; name: string }>;
          const matchedTeamIds = localTeams
            .filter((lt) => assertedTeams.has(String(lt.id)) || assertedTeams.has(lt.name))
            .map((lt) => lt.id);
          for (const teamId of matchedTeamIds) {
            await trx('team_memberships')
              .insert({ user_id: localUserId, team_id: teamId })
              .onConflict(['team_id', 'user_id'])
              .ignore();
          }
          if (matchedTeamIds.length > 0) {
            logger.info(
              { userId: localUserId, tenant: t.slug, teamIds: matchedTeamIds },
              'Obligate SSO: synced team membership(s)',
            );
          } else {
            logger.warn(
              { userId: localUserId, tenant: t.slug, asserted: [...assertedTeams] },
              'Obligate SSO: no local team matched the asserted teams (check team name/id mapping)',
            );
          }
        }

        // ── Federated capabilities ────────────────────────────────────────
        // AUDIT-SEC #4 (MAJEUR). This used to write Alice's asserted capability
        // list onto EVERY `team_permissions` row of every team she belonged to.
        // That table is keyed by TEAM, not by user, so Bob — read-only by
        // design, same team — held Alice's `secret.read` on his next login; and
        // because the write was an overwrite, the whole team's capabilities
        // became "whatever the last person to log in was granted". The value
        // was also persisted without `sanitizeCapabilities`, letting a third
        // party store arbitrary strings in an authorisation table.
        //
        // Capabilities now land in `user_tenant_capabilities` (migration 003),
        // which is keyed by (user, tenant) exactly like the assertion itself,
        // and are sanitised on the way in as well as on the way out.
        // The row is written even for an EMPTY list: an assertion that grants
        // nothing must revoke what a previous assertion granted.
        //
        // The `Array.isArray` guard is not cosmetic: `t.capabilities` is remote
        // JSON. A provider sending the string "admin" instead of a list made
        // `sanitizeCapabilities` call `.filter` on a string and throw, and the
        // outer catch turns any throw here into `/login?error=sso_failed` — an
        // unexplained login failure where a sanitised empty list was meant.
        const federated = sanitizeCapabilities(Array.isArray(t.capabilities) ? t.capabilities : []);
        await trx('user_tenant_capabilities')
          .insert({
            user_id: localUserId,
            tenant_id: tenant.id,
            capabilities: JSON.stringify(federated),
            source: 'obligate',
            updated_at: new Date(),
          })
          .onConflict(['user_id', 'tenant_id'])
          .merge({
            capabilities: JSON.stringify(federated),
            source: 'obligate',
            updated_at: new Date(),
          });
      }

      // ── Revocation: the assertion is the complete state of what it governs ─
      // Read AFTER the upserts, inside the same transaction: every tenant this
      // assertion just (re)granted now carries `source = 'obligate'` and sits in
      // `assertedTenantIds`, so it cannot be caught by the difference below.
      // What remains is precisely "granted by a PREVIOUS assertion, absent from
      // this one".
      const governedTenantIds = await trx('user_tenant_capabilities')
        .where({ user_id: localUserId, source: 'obligate' })
        .pluck('tenant_id') as number[];
      revokedTenantIds = governedTenantIds.filter((id) => !assertedTenantIds.includes(id));

      if (revokedTenantIds.length > 0) {
        await trx('user_tenants')
          .where({ user_id: localUserId })
          .whereIn('tenant_id', revokedTenantIds)
          .del();
        await trx('user_tenant_capabilities')
          .where({ user_id: localUserId })
          .whereIn('tenant_id', revokedTenantIds)
          .del();
        // `team_memberships` has no tenant_id of its own; the tenant lives on
        // `user_teams`. Only the memberships inside the revoked tenants go.
        const staleTeamIds = await trx('user_teams')
          .whereIn('tenant_id', revokedTenantIds)
          .pluck('id') as number[];
        if (staleTeamIds.length > 0) {
          await trx('team_memberships')
            .where({ user_id: localUserId })
            .whereIn('team_id', staleTeamIds)
            .del();
        }
        logger.warn(
          { userId: localUserId, revokedTenantIds, assertedTenantIds, staleTeamIds },
          'Obligate SSO: revoked tenant access that the assertion no longer grants',
        );
      }
    });

    // Sync preferences from Obligate (theme, language, toast settings)
    if (assertion.preferences) {
      const prefUpdate: Record<string, unknown> = {};
      if (assertion.preferences.preferredLanguage) prefUpdate.preferred_language = assertion.preferences.preferredLanguage;
      if (assertion.preferences.profilePhotoUrl !== undefined) prefUpdate.avatar = assertion.preferences.profilePhotoUrl;
      if (Object.keys(prefUpdate).length > 0) {
        await db('users').where({ id: localUserId }).update(prefUpdate);
      }
      const uiPrefs: Record<string, unknown> = {};
      if (assertion.preferences.preferredTheme) uiPrefs.preferredTheme = assertion.preferences.preferredTheme;
      if (assertion.preferences.toastEnabled !== undefined) uiPrefs.toastEnabled = assertion.preferences.toastEnabled;
      if (assertion.preferences.toastPosition) uiPrefs.toastPosition = assertion.preferences.toastPosition;
      if (assertion.preferences.anonymousMode !== undefined) uiPrefs.anonymousMode = assertion.preferences.anonymousMode;
      if (Object.keys(uiPrefs).length > 0) {
        const existingRow = await db('users').where({ id: localUserId }).select('preferences').first() as { preferences: unknown } | undefined;
        const existing = (typeof existingRow?.preferences === 'string' ? JSON.parse(existingRow.preferences) : existingRow?.preferences) ?? {};
        await db('users').where({ id: localUserId }).update({
          preferences: JSON.stringify({ ...existing, ...uiPrefs }),
        });
      }
    }

    // ── SECFIX-R9 — make an SSO demotion take effect NOW ───────────────────
    //
    // The UPDATE above rewrites `users.role` from the assertion and used to do
    // nothing else. `requireAuth` caches (role, is_active) for 10 s and the
    // user's OTHER live sessions carry the old role in their session row, so a
    // demotion from `admin` to `user` performed in Obligate took up to ten
    // seconds to bite on this process and stayed live on every other session
    // the account had open. `/sso-user-sync` action `update-role` already
    // destroys sessions for exactly this reason ("a demotion must take effect
    // now, not in 10 s and not in 7 days"); the login path did not. Same rule
    // here — and the same rule for a tenant the assertion has just revoked,
    // which `requireTenant` would otherwise keep serving from its own
    // membership cache.
    //
    // The caches are cleared unconditionally (two Map deletes, no I/O) because
    // a tenant ROLE change inside a still-granted tenant also feeds the
    // capability matrix. Sessions are destroyed only when something actually
    // shrank: doing it on every login would log the user out of his other
    // devices each time he signs in, which is a product regression, not a
    // hardening.
    invalidateIdentityCache(localUserId);
    invalidateMembershipCache(localUserId);
    const roleChanged = previousRole !== null && previousRole !== assertedRole;
    if (roleChanged || revokedTenantIds.length > 0) {
      // Runs BEFORE regenerateSession, and deletes rows by
      // `sess->>'userId'`. The session in hand is still anonymous at this
      // point — it only carries `oauthState` / `requestedTenantSlug` — so it
      // is not among the rows deleted and the login completes normally.
      const killed = await destroyUserSessions(localUserId);
      logger.warn(
        { userId: localUserId, previousRole, assertedRole, revokedTenantIds, killedSessions: killed },
        'Obligate SSO: role and/or tenant set shrank — existing sessions revoked',
      );
    }

    // Establish session.
    //
    // AUDIT-SEC #5 — third and last elevation point. This one matters most:
    // `GET /auth/sso-redirect` (a few lines below) is what materialises a
    // server-side session for an anonymous caller in the first place, by
    // writing `oauthState` and calling `session.save()`. Regenerating here
    // means the id an attacker could have obtained there — and planted in a
    // victim's browser — is discarded the moment the victim authenticates.
    // The cross-app tenant slug is the one value that must survive, so it is
    // read off the old session and handed to the new one BY NAME.
    const carriedSlug = req.session.requestedTenantSlug;
    await regenerateSession(req, { requestedTenantSlug: carriedSlug });

    req.session.userId = localUserId;
    const user = await db('users').where({ id: localUserId }).first() as { username: string; role: string } | undefined;
    if (user) {
      req.session.username = user.username;
      req.session.role = user.role;
    }

    // Cross-app handoff: prefer the tenant slug requested by the source app
    // when the user has access to a tenant with that slug. Otherwise fall
    // back to the first available tenant (existing behaviour).
    //
    // Platform admins (assertion.role === 'admin') have implicit access to
    // every tenant but no user_tenants rows — so the regular JOIN misses for
    // them. They only need a tenant-existence check. Tenant admins / members
    // keep the strict JOIN to preserve access control. Detection uses the
    // assertion role, never the local user.role.
    let resolvedTenantId: number | null = null;
    const requestedSlug = req.session.requestedTenantSlug;
    if (requestedSlug) {
      const isPlatformAdmin = assertion.role === 'admin';
      let match: { id: number } | undefined;
      if (isPlatformAdmin) {
        match = await db('tenants')
          .where({ slug: requestedSlug })
          .select('id')
          .first() as { id: number } | undefined;
      } else {
        match = await db('tenants as t')
          .join('user_tenants as ut', 'ut.tenant_id', 't.id')
          .where({ 't.slug': requestedSlug, 'ut.user_id': localUserId })
          .select('t.id')
          .first() as { id: number } | undefined;
      }
      if (match) {
        resolvedTenantId = match.id;
        logger.info({ userId: localUserId, slug: requestedSlug, isPlatformAdmin }, 'Cross-app handoff: tenant matched');
      } else {
        logger.info({ userId: localUserId, slug: requestedSlug, isPlatformAdmin },
          'Cross-app handoff: requested tenant not accessible, falling back');
      }
      // Always clear so the value does not leak into a subsequent login that did
      // not originate from a cross-app pill click.
      delete req.session.requestedTenantSlug;
    }

    if (resolvedTenantId === null) {
      const tenant = await tenantService.getFirstTenantForUser(localUserId);
      resolvedTenantId = tenant?.id ?? null;
    }
    // AUDIT-SEC #2 — no `?? 1`. Tenant 1 is the god view; handing it to an SSO
    // user whose assertion mapped to no local tenant (slug typo, tenant not
    // provisioned yet) showed them every customer's alerts and group trees.
    if (resolvedTenantId !== null) {
      req.session.currentTenantId = resolvedTenantId;
    } else {
      delete req.session.currentTenantId;
      logger.warn(
        { userId: localUserId, assertedTenants: assertion.tenants.map((t) => t.slug) },
        'Obligate SSO: no local tenant matched the assertion — session has no current tenant ' +
          '(tenant-scoped routes will answer 403). Check the tenant slug mapping in Obligate.',
      );
    }

    logger.info(`Obligate SSO: user ${assertion.username} (obligate #${assertion.obligateUserId}) → local #${localUserId}`);

    // Save session, then redirect via HTML meta refresh to ensure Set-Cookie header
    // is fully processed by the browser before navigation occurs.
    req.session.save((err) => {
      if (err) { logger.error(err, 'Session save failed'); res.redirect('/login?error=sso_failed'); return; }
      logger.info({ sessionId: req.sessionID, userId: req.session.userId }, 'Session saved, redirecting to /');
      res.setHeader('Content-Type', 'text/html');
      res.end(`<!DOCTYPE html><html><head><meta http-equiv="refresh" content="0;url=/"><style>body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0d1117;color:#8b949e;font-family:-apple-system,BlinkMacSystemFont,sans-serif}.s{text-align:center}.d{width:28px;height:28px;border:2.5px solid #30363d;border-top-color:#58a6ff;border-radius:50%;animation:r .6s linear infinite;margin:0 auto 14px}@keyframes r{to{transform:rotate(360deg)}}</style></head><body><div class="s"><div class="d"></div><div>Signing in...</div></div></body></html>`);
    });
  } catch (err) {
    logger.error(err, 'Obligate callback error');
    res.redirect('/login?error=sso_failed');
  }
});

/**
 * GET /auth/sso-redirect
 * Server-side redirect to the Obligate authorize endpoint (browser redirect).
 *
 * SECFIX-C1 (CRITIQUE). The comment that used to sit here said "The server
 * knows the API key — the client never sees it", and the line that built the
 * URL said the exact opposite:
 *
 *     `${raw.url}/authorize?client_id=${encodeURIComponent(raw.apiKey)}&...`
 *
 * This route is unauthenticated and mounted twice (app.ts:110 as
 * /auth/sso-redirect, routes/index.ts:35 as /api/auth/sso-redirect). Any
 * anonymous visitor — `curl -sD- http://obliwan/auth/sso-redirect` is enough —
 * got a 302 whose `Location` header carried the FULL API key. The same string
 * is the bearer credential `requireObligateKey` checks below, so reading one
 * response header granted:
 *   - `POST /api/auth/sso-user-sync` — promote any Obligate-provisioned
 *     account to platform `admin`, or delete it;
 *   - `GET /api/auth/app-info` — every tenant and every team of every client;
 *   - and, towards Obligate itself, `Authorization: Bearer <key>` on
 *     `/api/oauth/token/exchange`, i.e. the power to mint assertions, which is
 *     the entry point of SECFIX-C2 above.
 * On a product that holds WAN administration credentials for several
 * customers, that is the whole estate for the price of one HTTP header.
 *
 * The two roles are now separate values (see appConfig.service.ts):
 * `clientId` is public and is the only one allowed in a URL; `apiKey` never
 * leaves this process except inside an `Authorization` header. When no
 * `clientId` is configured this route FAILS CLOSED rather than fall back to
 * the secret.
 *
 * ── What Obligate must ship for this to be complete ────────────────────────
 * Read at D:\Obligate, commit of the day. Obligate resolves the incoming
 * `client_id` with `appService.getAppByApiKey(client_id)`
 * (server/src/routes/oauth.routes.ts:32), i.e. it looks the value up in
 * `connected_apps.api_key` — the very column it also accepts as the bearer on
 * `/api/oauth/token/exchange` (oauth.routes.ts:88) and on `/api/apps/*`.
 * `connected_apps` has NO public identifier column at all
 * (server/src/services/app.service.ts:5-17: id, app_type, name, base_url,
 * api_key, icon, color, is_active). So today the provider exposes exactly ONE
 * value and asks for it in a query string.
 *
 * Obligate therefore needs, in this order of preference:
 *   (a) a `connected_apps.client_id` column — random, public, unique, shown in
 *       the app admin screen — with `/authorize` resolving on it and
 *       `getAppByApiKey` reserved for the `Authorization` header; or
 *   (b) at minimum, `/authorize` accepting `app_type` (or the app id) as the
 *       public identifier, since the redirect_uri is already validated at
 *       exchange time.
 *
 * The fallback suggested by the review — an auto-submitted POST to
 * `/authorize` so the secret leaves the address bar — does NOT work against
 * the current provider: `/authorize` is registered GET-only, both at the root
 * alias (server/src/app.ts:81, `app.get('/authorize', ...)`) and on the real
 * route (`oauthRoutes.get('/authorize', ...)`); a POST falls through to the
 * static handler. It is recorded here so the next reader does not spend an
 * afternoon on it.
 *
 * Until Obligate ships (a) or (b), an operator who accepts the exposure can
 * point `clientId` at the API key explicitly — `OBLIGATE_CLIENT_ID=<key>` or
 * `patchObligateConfig({ clientId })`. That is a deliberate, logged, opt-in
 * act by someone who knows what they are publishing, which is the whole
 * difference with the previous behaviour: doing it silently on everyone's
 * behalf.
 */
router.get('/sso-redirect', async (req, res) => {
  try {
    // Cross-app tenant handoff: the source Obli* app appends ?tenant=<slug>
    // when the user clicks the topbar switcher pill. Stash it in the session
    // so /auth/callback can apply it once the user comes back from Obligate.
    // Validate against the same regex the tenants table enforces — anything
    // else is dropped silently (defence-in-depth, untrusted query input).
    const requestedTenant = req.query.tenant;
    if (typeof requestedTenant === 'string' && /^[a-z0-9-]{1,64}$/.test(requestedTenant)) {
      req.session.requestedTenantSlug = requestedTenant;
    }

    // `appConfigService` is already imported at module scope; the dynamic
    // import that used to be here re-resolved the module on every anonymous
    // hit for no reason.
    const raw = await appConfigService.getObligateRaw();
    if (!raw.url || !raw.apiKey) {
      res.redirect('/login');
      return;
    }

    // SECFIX-C1 — fail CLOSED. `clientId` is the public application id; the
    // API key is a bearer credential and must never reach a URL, a browser
    // history, a proxy log or a Referer header. If no public id is configured
    // we refuse to build the redirect instead of publishing the secret.
    if (!raw.clientId) {
      logger.error(
        { obligateUrl: raw.url },
        'sso-redirect REFUSED: no public Obligate client_id configured. The API key is a ' +
          'server-to-server bearer credential and is no longer used as client_id. Set one with ' +
          'OBLIGATE_CLIENT_ID=<value> (or appConfigService.patchObligateConfig({ clientId })) — ' +
          'see the note above this route for what Obligate must expose.',
      );
      res.redirect('/login?error=sso_client_id_missing');
      return;
    }
    // Verify Obligate is reachable before redirecting (prevents redirect loop when Gate is down)
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 2000);
      const healthRes = await fetch(`${raw.url}/health`, { signal: controller.signal });
      clearTimeout(timeout);
      if (!healthRes.ok) { res.redirect('/login?error=sso_failed'); return; }
    } catch {
      res.redirect('/login?error=sso_failed');
      return;
    }
    const protocol = req.headers['x-forwarded-proto'] || req.protocol;
    const host = req.headers['x-forwarded-host'] || req.headers.host;
    const selfUrl = `${protocol}://${host}`;
    // Safety: never redirect to ourselves (misconfigured obligate_url pointing to this app)
    if (raw.url.replace(/\/$/, '') === selfUrl.replace(/\/$/, '')) {
      logger.error({ obligateUrl: raw.url, selfUrl }, 'sso-redirect: obligate_url points to this app — aborting to prevent loop');
      res.redirect('/login?error=sso_misconfigured');
      return;
    }
    const redirectUri = `${selfUrl}/auth/callback`;

    // Generate cryptographic state token to prevent login CSRF (RFC 6749 §10.12)
    const oauthState = crypto.randomBytes(32).toString('hex');
    req.session.oauthState = oauthState;

    // Only `clientId` goes in the query string. If an operator has knowingly
    // set clientId to the API key (the documented stop-gap while Obligate has
    // no public identifier), say so out loud on every redirect so it shows up
    // in the logs rather than in nobody's memory.
    if (raw.apiKey && raw.clientId === raw.apiKey) {
      logger.warn(
        { obligateUrl: raw.url },
        'sso-redirect: the configured Obligate client_id IS the API key — the bearer credential ' +
          'is being published in a redirect URL. Accepted because it was configured explicitly, ' +
          'but it must be replaced by a real public client_id.',
      );
    }
    const obligateUrl = `${raw.url}/authorize?client_id=${encodeURIComponent(raw.clientId)}&redirect_uri=${encodeURIComponent(redirectUri)}&state=${encodeURIComponent(oauthState)}`;
    logger.info({ obligateUrl: raw.url, redirectUri }, 'sso-redirect: redirecting to Obligate');

    // Save session before redirecting to ensure state is persisted
    req.session.save((err) => {
      if (err) { logger.error(err, 'sso-redirect: session save failed'); res.redirect('/login?error=sso_failed'); return; }
      res.redirect(obligateUrl);
    });
  } catch {
    res.redirect('/login');
  }
});

/**
 * GET /api/auth/app-info
 * Called by Obligate (Bearer auth) to discover teams + tenants for mapping UI.
 */
router.get('/app-info', requireObligateKey, async (_req, res) => {
  try {
    // Fetch all teams across all tenants
    const teams = await db('user_teams')
      .join('tenants', 'user_teams.tenant_id', 'tenants.id')
      .select('user_teams.id', 'user_teams.name', 'tenants.slug as tenant_slug', 'tenants.name as tenant_name')
      .orderBy('tenants.name')
      .orderBy('user_teams.name') as Array<{ id: number; name: string; tenant_slug: string; tenant_name: string }>;

    // Fetch all tenants
    const tenants = await db('tenants')
      .select('id', 'name', 'slug')
      .orderBy('name') as Array<{ id: number; name: string; slug: string }>;

    // Capabilities are applied to team_permissions in /auth/callback only when
    // the user is in a team on the tenant — without a team they are a no-op.
    // We therefore no longer advertise permissionSets to Obligate, so its UI
    // stops offering orphan capability checkboxes alongside the team picker.
    res.json({
      success: true,
      data: {
        roles: ['admin', 'user'],
        teams: teams.map(t => ({ id: t.id, name: t.name, tenantSlug: t.tenant_slug, tenantName: t.tenant_name })),
        tenants: tenants.map(t => ({ slug: t.slug, name: t.name })),
      },
    });
  } catch (err) {
    logger.error(err, 'app-info error');
    res.status(500).json({ success: false, error: 'Failed to fetch app info' });
  }
});

/**
 * GET /api/auth/dashboard-stats
 * Called by Obligate (Bearer auth) to display stats on the Obligate dashboard.
 */
router.get('/dashboard-stats', requireObligateKey, async (_req, res) => {
  try {
    // M1 has no fleet yet: sites, devices and drift findings arrive with
    // migration 002. Report the entities that DO exist rather than querying
    // the Obliguard IPS tables (agent_devices / ip_bans / ip_events), which
    // no longer exist and made this endpoint throw on every call.
    const [tenants, groups, users] = await Promise.all([
      db('tenants').count('id as c').first(),
      db('device_groups').count('id as c').first(),
      db('users').where({ is_active: true }).count('id as c').first(),
    ]);
    res.json({ success: true, data: { stats: [
      { label: 'Tenants', value: Number((tenants as { c?: string | number } | undefined)?.c ?? 0), color: '#58a6ff' },
      { label: 'Groups',  value: Number((groups  as { c?: string | number } | undefined)?.c ?? 0), color: '#3fb950' },
      { label: 'Users',   value: Number((users   as { c?: string | number } | undefined)?.c ?? 0), color: '#d29922' },
    ] } });
  } catch { res.json({ success: true, data: null }); }
});

/**
 * GET /api/auth/sso-config
 * Returns Obligate SSO config for the LoginPage (public, no auth required).
 */
router.get('/sso-config', async (_req, res) => {
  try {
    const config = await obligateService.getSsoConfig();
    res.json({ success: true, data: config });
  } catch (err) {
    res.json({ success: true, data: { obligateUrl: null, obligateReachable: false, obligateEnabled: false } });
  }
});

/**
 * GET /api/auth/sso-logout-url
 * Returns Obligate logout URL so the client can redirect after local logout.
 */
router.get('/sso-logout-url', async (req, res) => {
  try {
    const cfg = await appConfigService.getObligateRaw();
    if (!cfg.url) {
      res.json({ success: true, data: null });
      return;
    }
    const protocol = req.headers['x-forwarded-proto'] || req.protocol;
    const host = req.headers['x-forwarded-host'] || req.headers.host;
    const redirectUri = `${protocol}://${host}/login`;
    const logoutUrl = `${cfg.url}/logout?redirect_uri=${encodeURIComponent(redirectUri)}`;
    res.json({ success: true, data: logoutUrl });
  } catch {
    res.json({ success: true, data: null });
  }
});

/**
 * GET /api/auth/connected-apps
 * Returns list of connected apps from Obligate (for cross-app nav buttons).
 */
router.get('/connected-apps', requireAuth, async (req, res) => {
  try {
    // Scope the app switcher to the caller's Obligate entitlements. Local
    // (non-SSO) users have no Obligate id → pass null (unfiltered fallback);
    // SSO-provisioned users get only the apps they can actually reach.
    const row = await db('users')
      .where({ id: req.session.userId })
      .select('foreign_source', 'foreign_id')
      .first() as { foreign_source: string | null; foreign_id: number | null } | undefined;
    const obligateUserId = row?.foreign_source === 'obligate' && row.foreign_id ? row.foreign_id : null;
    const apps = await obligateService.getConnectedApps(obligateUserId);
    res.json({ success: true, data: apps });
  } catch (err) {
    res.json({ success: true, data: [] });
  }
});

/**
 * POST /api/auth/sso-user-sync
 * Called by Obligate (Bearer auth) when an SSO user is deactivated, reactivated, deleted, or role-changed.
 */
router.post('/sso-user-sync', requireObligateKey, async (req, res) => {
  try {
    const { remoteUserId, action, role } = req.body as {
      obligateUserId: number; obligateUsername: string; remoteUserId: number;
      action: 'deactivate' | 'reactivate' | 'delete' | 'update-role'; role?: string;
    };

    if (!remoteUserId || !action) { res.status(400).json({ success: false, error: 'Missing fields' }); return; }

    const user = await db('users')
      .where({ id: remoteUserId })
      .first('id', 'foreign_source') as { id: number; foreign_source: string | null } | undefined;
    if (!user) { res.json({ success: true }); return; }

    // AUDIT-SEC #11 — this endpoint may only act on accounts Obligate actually
    // owns. Without this check, the API key alone deleted ANY user by id
    // (including the local platform admin, whose id is 1 on every install) or
    // promoted any local account to `admin`. `remoteUserId` is a raw id chosen
    // by the caller, not a value we ever handed out.
    if (user.foreign_source !== 'obligate') {
      logger.warn(
        { remoteUserId, action, foreignSource: user.foreign_source },
        'sso-user-sync refused: target is not an Obligate-provisioned account',
      );
      res.status(403).json({ success: false, error: 'Not an SSO-managed account' });
      return;
    }

    switch (action) {
      case 'deactivate':
        await db('users').where({ id: remoteUserId }).update({ is_active: false, updated_at: new Date() });
        // AUDIT-SEC #6 — the row said `is_active = false` and nothing else
        // happened: requireAuth never re-read the user, so the deactivated
        // account kept full HTTP access for the 7-day cookie lifetime.
        await destroyUserSessions(remoteUserId);
        logger.info(`SSO sync: deactivated user #${remoteUserId}`);
        break;
      case 'reactivate':
        await db('users').where({ id: remoteUserId }).update({ is_active: true, updated_at: new Date() });
        logger.info(`SSO sync: reactivated user #${remoteUserId}`);
        break;
      case 'delete':
        await db('sso_foreign_users').where({ local_user_id: remoteUserId }).del();
        await db('users').where({ id: remoteUserId }).del();
        await destroyUserSessions(remoteUserId);
        logger.info(`SSO sync: deleted user #${remoteUserId}`);
        break;
      case 'update-role':
        if (role) {
          await db('users').where({ id: remoteUserId }).update({ role: role === 'admin' ? 'admin' : 'user', updated_at: new Date() });
          // A demotion must take effect now, not in 10 s and not in 7 days.
          await destroyUserSessions(remoteUserId);
          logger.info(`SSO sync: updated role of user #${remoteUserId} to ${role}`);
        }
        break;
    }

    res.json({ success: true });
  } catch (err) {
    logger.error(err, 'sso-user-sync error');
    res.status(500).json({ success: false, error: 'Sync failed' });
  }
});

export default router;
