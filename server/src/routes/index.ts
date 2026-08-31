import { Router } from 'express';
import { requireAuth } from '../middleware/auth';
import { requireTenant } from '../middleware/tenant';
import authRoutes from './auth.routes';
import obligateCallbackRoutes from './obligateCallback.routes';
import tenantRoutes from './tenant.routes';
import groupsRoutes from './groups.routes';
import settingsRoutes from './settings.routes';
import notificationsRoutes from './notifications.routes';
import usersRoutes from './users.routes';
import profileRoutes from './profile.routes';
import teamsRoutes from './teams.routes';
import smtpServerRoutes from './smtpServer.routes';
import appConfigRoutes from './appConfig.routes';
import twoFactorRoutes from './twoFactor.routes';
import permissionSetsRoutes from './permissionSets.routes';
import importExportRoutes from './importExport.routes';
import systemRoutes from './system.routes';
import { liveAlertRouter } from './liveAlert.routes';
import sitesRoutes from './sites.routes';
import devicesRoutes from './devices.routes';
import discoveriesRoutes from './discoveries.routes';
import snmpRoutes from './snmp.routes';
import backupsRoutes from './backups.routes';
import configRoutes from './config.routes';
import driftRoutes from './drift.routes';
import templatesRoutes from './templates.routes';
import variablesRoutes from './variables.routes';
import planRoutes from './plan.routes';
import changesRoutes from './changes.routes';
import intentRoutes from './intent.routes';
import baselineRoutes from './baseline.routes';
import exceptionsRoutes from './exceptions.routes';
import attestationRoutes from './attestation.routes';
import interventionsRoutes from './interventions.routes';
import aftermathRoutes from './aftermath.routes';
import weatherRoutes from './weather.routes';
import identityRoutes from './identity.routes';
import slaRoutes from './sla.routes';
import lifecycleRoutes from './lifecycle.routes';
import rolloutsRoutes from './rollouts.routes';
import logsRoutes from './logs.routes';
import queryRoutes from './query.routes';

/**
 * M2 + M3 + M4 route surface. Sites, devices + transports, the PPP discovery
 * quarantine, the SNMP telemetry (interfaces, series, thresholds, credentials)
 * and now config snapshots + read-only drift are live. Templates, plans, jobs,
 * rollouts, fleet query and CWMP arrive from M5 onwards and are deliberately
 * absent rather than stubbed: a route that answers an empty array is
 * indistinguishable, from the client, from a fleet that has nothing in it.
 */
const router = Router();

// -- Global (no tenant required) ---------------------------------------------
router.use('/auth', authRoutes);
router.use('/auth', obligateCallbackRoutes);  // Obligate SSO: sso-config, connected-apps, app-info
router.use('/admin/config', appConfigRoutes);
router.use('/system', systemRoutes);          // system info / about (admin only)
router.use('/profile/2fa', twoFactorRoutes);  // must be mounted before /profile
// Your own account is not tenant-scoped: reading your profile or changing your
// password must work before you belong to anything. This lived under tenantRouter,
// which was harmless only as long as the `?? 1` fallback gave every session a
// tenant; removing that fallback turned it into a lockout. profile.routes.ts
// carries its own requireAuth and reads no req.tenantId.
router.use('/profile', profileRoutes);
router.use('/live-alerts', liveAlertRouter);
router.use('/permission-sets', permissionSetsRoutes);
router.use('/admin', importExportRoutes);      // GET /admin/export, POST /admin/import

// -- Tenant management --------------------------------------------------------
router.use('/tenants', tenantRoutes);
router.use('/tenant', tenantRoutes);

// -- Tenant-scoped routes (requireAuth + requireTenant) ------------------------
const tenantRouter = Router();
tenantRouter.use(requireAuth);
tenantRouter.use(requireTenant);

tenantRouter.use('/groups', groupsRoutes);
tenantRouter.use('/settings', settingsRoutes);
tenantRouter.use('/notifications', notificationsRoutes);
tenantRouter.use('/users', usersRoutes);
tenantRouter.use('/teams', teamsRoutes);
tenantRouter.use('/admin/smtp-servers', smtpServerRoutes);

// -- Fleet (M2) ---------------------------------------------------------------
// Tenant-scoped like everything above. `discoveries` carries no tenant column of
// its own (quarantine is pre-tenant, migration 002), so its controller scopes
// through the concentrator instead of through a WHERE clause.
tenantRouter.use('/sites', sitesRoutes);
tenantRouter.use('/devices', devicesRoutes);
tenantRouter.use('/discoveries', discoveriesRoutes);

// -- Telemetry (M3) -----------------------------------------------------------
// Tenant-scoped like the fleet above. `snmp_interfaces`, `snmp_if_samples` and
// the rollups carry no tenant column of their own -- the series tables
// deliberately have no foreign key at all (study 1.1b) -- so the controller
// scopes through `devices` on every single read. That is the ONLY thing
// standing between one customer and another customer's traffic graphs.
tenantRouter.use('/snmp', snmpRoutes);

// -- Configuration & drift (M4) -----------------------------------------------
// `config_snapshots`, the ten `ncm_*` tables, `drift_runs` and `drift_findings`
// carry NO tenant column: the scoping goes through `devices` on every single
// read, exactly as the SNMP series tables above. That join is the only thing
// standing between one customer and another customer's firewall.
//
// M4 is READ-ONLY drift: nothing under these two prefixes proposes a
// remediation, compiles a plan or writes to an equipment. The one route that
// touches the fleet at all (`POST /config/devices/:id/collect`) runs
// `/export terse show-sensitive=no` and nothing else, and sits behind
// CONFIG_WRITE for that reason.
// Pre-change backups (M6). READ ONLY, and it never returns the archive's
// encryption password nor its storage path — see the box in backups.routes.ts.
tenantRouter.use('/backups', backupsRoutes);
tenantRouter.use('/config', configRoutes);
tenantRouter.use('/drift', driftRoutes);

// -- Templates, variables and plans (M5) --------------------------------------
// Still nothing writes to an equipment: `/plan` COMPILES a plan and stores it,
// applying one is M6. `TEMPLATE_WRITE` is the security boundary of risk R6 —
// it is the capability that lets a caller make this server evaluate template
// code, on the process that holds the whole fleet's admin credentials.
tenantRouter.use('/templates', templatesRoutes);
tenantRouter.use('/variables', variablesRoutes);
tenantRouter.use('/plan', planRoutes);

// -- Change jobs (M6 — decision D3) -------------------------------------------
// THE LINE THIS FILE CROSSES AT M6. Everything mounted above reads, compiles or
// proposes; nothing under any other prefix can make this server modify somebody
// else's hardware. `/changes` can, and it is the only one — D3 says nothing
// writes to an equipment outside `change_jobs`, and this mount is where that
// sentence becomes a route table.
//
// The capabilities are split inside `changes.routes.ts` and the split is not
// cosmetic: `CHANGE_APPLY` asks for a change, `CHANGE_APPROVE` overrules the
// Management-Path Guard, and `SETTINGS_MANAGE` releases the kill switch.
// Enqueuing with an override demands the first two together.
//
// Tenant-scoped like everything above. `command_audit` and `apply_outcomes`
// carry NO foreign key to `tenants` at all (they must outlive an offboarding),
// so the tenant filter in their controllers is the only isolation they have.
tenantRouter.use('/changes', changesRoutes);

// -- Waved rollouts (M7 — K3) --------------------------------------------------
// The second thing in the product that can modify somebody else's hardware, and
// it does so at scale. It still writes through change_jobs like everything else
// (D3): a rollout never applies anything itself, it enqueues jobs wave by wave.
//
// Two refusals live under here and both are enforced by the DATABASE, not by the
// controller: a wave cannot be queued without a health baseline captured BEFORE
// it, and a concentrator can never share an active rollout with its own children
// (§8.5 — a concentrator that drops mid-soak leaves N armed dead-men nobody can
// disarm, and N good changes revert themselves).
tenantRouter.use('/rollouts', rolloutsRoutes);

// -- Logs, attribution and reachability (M8 — K6 + K7) -------------------------
// Read-only. Attribution answers "who changed this", and its most important
// answer is "unattributed": naming the wrong person is worse than naming nobody,
// because a name gets believed.
tenantRouter.use('/logs', logsRoutes);

// -- Fleet Query (M9 — K5) -----------------------------------------------------
// Turns user text into SQL over the ncm jsonb. The path whitelist is generated
// from the NCM Zod schemas and is a CORRECTNESS guard; the injection guard is the
// bound parameter, and nothing else.
tenantRouter.use('/query', queryRoutes);

// -- Intent Compiler (M11 — K4) ------------------------------------------------
// Compiles a site intent into the NCM of a specific box, and REFUSES at
// compilation — before any socket, session or credential — when the hardware
// cannot do what the intent asks. Applying the result still goes through
// change_jobs (D3): this prefix produces documents, never packets.
tenantRouter.use('/intent', intentRoutes);

// -- Fleet takeover / Golden Site (M12 — K8) -----------------------------------
// Read-only mining of existing snapshots into template drafts. It proposes; a
// human publishes. Nothing here writes to a device or to a published revision.
tenantRouter.use('/baseline', baselineRoutes);

// -- Evidence: justified drift exceptions + attestations (F1 + F2, §10) --------
// An exception REQUIRES a justification and a review date, both enforced by CHECK
// constraints rather than by validation: the point is that an unjustified
// exception cannot exist, not that we decline to create one. "Expired" is derived,
// so a stale exception hands its drift back instead of hiding it forever.
tenantRouter.use('/exceptions', exceptionsRoutes);
tenantRouter.use('/attestations', attestationRoutes);

// -- Intervention mode and change aftermath (F3 + F4, §10) ---------------------
// An open intervention is NOT a permission to write: nothing under here bypasses
// D3. It brackets a human's work so that the drift it produces is attributed to
// it instead of surfacing as an anomaly.
tenantRouter.use('/interventions', interventionsRoutes);
tenantRouter.use('/aftermath', aftermathRoutes);

// -- Operator weather (F5, §10) ------------------------------------------------
// Correlation, never a single-site verdict. The public address it reasons on is
// the one the CONCENTRATOR observed in the PPP caller-id — an outside observation
// that stays true behind NAT — and never an address a device claims for itself.
tenantRouter.use('/weather', weatherRoutes);

// -- Identity, availability and lifecycle (F6 + F7 + F8) ----------------------
// All three READ. None of them writes to a device, and none of them corrects
// anything on its own: a hardware replacement is SIGNALLED (the old snapshot
// stops being a trustworthy baseline and says so) rather than silently retired.
tenantRouter.use('/identity', identityRoutes);
tenantRouter.use('/sla', slaRoutes);
tenantRouter.use('/lifecycle', lifecycleRoutes);

router.use('/', tenantRouter);

export { router as routes };
