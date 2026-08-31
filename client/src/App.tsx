import { useEffect, lazy, Suspense } from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { Toaster } from 'react-hot-toast';
import { useAuthStore } from '@/store/authStore';
import { ProtectedRoute } from '@/components/layout/ProtectedRoute';
import { AppLayout } from '@/components/layout/AppLayout';
import { LoginPage } from '@/pages/LoginPage';
import { NotFoundPage } from '@/pages/NotFoundPage';
import { CAPABILITIES } from '@obliwan/shared';
import '@/i18n';
import { initTheme } from '@/utils/theme';

// Lazily loaded: one chunk per screen. Vite names them after the file, so a
// slow route is identifiable in the network tab without a source map.
const EnrollmentPage = lazy(() => import('@/pages/EnrollmentPage').then((m) => ({ default: m.EnrollmentPage })));
const ForgotPasswordPage = lazy(() => import('@/pages/ForgotPasswordPage').then((m) => ({ default: m.ForgotPasswordPage })));
const ResetPasswordPage = lazy(() => import('@/pages/ResetPasswordPage').then((m) => ({ default: m.ResetPasswordPage })));
const DashboardPage = lazy(() => import('@/pages/DashboardPage').then((m) => ({ default: m.DashboardPage })));
const GroupManagePage = lazy(() => import('@/pages/GroupManagePage').then((m) => ({ default: m.GroupManagePage })));
const DevicesPage = lazy(() => import('@/pages/DevicesPage').then((m) => ({ default: m.DevicesPage })));
const InterfacesPage = lazy(() => import('@/pages/InterfacesPage').then((m) => ({ default: m.InterfacesPage })));
const ThresholdsPage = lazy(() => import('@/pages/ThresholdsPage').then((m) => ({ default: m.ThresholdsPage })));
const DeviceDetailPage = lazy(() => import('@/pages/DeviceDetailPage').then((m) => ({ default: m.DeviceDetailPage })));
const ConfigPage = lazy(() => import('@/pages/ConfigPage').then((m) => ({ default: m.ConfigPage })));
const DriftPage = lazy(() => import('@/pages/DriftPage').then((m) => ({ default: m.DriftPage })));
const DriftDetailPage = lazy(() => import('@/pages/DriftDetailPage').then((m) => ({ default: m.DriftDetailPage })));
const PlanPage = lazy(() => import('@/pages/PlanPage').then((m) => ({ default: m.PlanPage })));
const ChangesPage = lazy(() => import('@/pages/ChangesPage').then((m) => ({ default: m.ChangesPage })));
const ChangeJobPage = lazy(() => import('@/pages/ChangeJobPage').then((m) => ({ default: m.ChangeJobPage })));
const RolloutsPage = lazy(() => import('@/pages/RolloutsPage').then((m) => ({ default: m.RolloutsPage })));
const RolloutDetailPage = lazy(() => import('@/pages/RolloutDetailPage').then((m) => ({ default: m.RolloutDetailPage })));
const LogsPage = lazy(() => import('@/pages/LogsPage').then((m) => ({ default: m.LogsPage })));
const QueryPage = lazy(() => import('@/pages/QueryPage').then((m) => ({ default: m.QueryPage })));
const AlertsPage = lazy(() => import('@/pages/AlertsPage').then((m) => ({ default: m.AlertsPage })));
const SitesPage = lazy(() => import('@/pages/SitesPage').then((m) => ({ default: m.SitesPage })));
const TemplatesPage = lazy(() => import('@/pages/TemplatesPage').then((m) => ({ default: m.TemplatesPage })));
const VariablesPage = lazy(() => import('@/pages/VariablesPage').then((m) => ({ default: m.VariablesPage })));
const AuditPage = lazy(() => import('@/pages/AuditPage').then((m) => ({ default: m.AuditPage })));
const BackupsPage = lazy(() => import('@/pages/BackupsPage').then((m) => ({ default: m.BackupsPage })));
const SiteDetailPage = lazy(() => import('@/pages/SiteDetailPage').then((m) => ({ default: m.SiteDetailPage })));
const DiscoveriesPage = lazy(() => import('@/pages/DiscoveriesPage').then((m) => ({ default: m.DiscoveriesPage })));
const SettingsPage = lazy(() => import('@/pages/SettingsPage').then((m) => ({ default: m.SettingsPage })));
const NotificationsPage = lazy(() => import('@/pages/NotificationsPage').then((m) => ({ default: m.NotificationsPage })));
const AdminUsersPage = lazy(() => import('@/pages/AdminUsersPage').then((m) => ({ default: m.AdminUsersPage })));
const ProfilePage = lazy(() => import('@/pages/ProfilePage').then((m) => ({ default: m.ProfilePage })));
const GroupDetailPage = lazy(() => import('@/pages/GroupDetailPage').then((m) => ({ default: m.GroupDetailPage })));
const GroupEditPage = lazy(() => import('@/pages/GroupEditPage').then((m) => ({ default: m.GroupEditPage })));
const ImportExportPage = lazy(() => import('@/pages/ImportExportPage').then((m) => ({ default: m.ImportExportPage })));
const AdminTenantsPage = lazy(() => import('@/pages/AdminTenantsPage').then((m) => ({ default: m.AdminTenantsPage })));
const SsoEnrollPage = lazy(() => import('@/pages/SsoEnrollPage').then((m) => ({ default: m.SsoEnrollPage })));
const AcsPage = lazy(() => import('@/pages/AcsPage').then((m) => ({ default: m.AcsPage })));
const IntentPage = lazy(() => import('@/pages/IntentPage').then((m) => ({ default: m.IntentPage })));
const BaselinePage = lazy(() => import('@/pages/BaselinePage').then((m) => ({ default: m.BaselinePage })));

// Apply saved theme immediately to avoid flash of unstyled content
initTheme();

/**
 * Route table.
 *
 * Only the pages that actually exist are routed. M2 added the inventory
 * (/devices, /devices/:id, /sites, /sites/:id, /admin/discoveries); M3 adds
 * telemetry (/interfaces and its thresholds screen); M4 adds the NCM screens
 * (/config, /config/:deviceId, /drift, /drift/:id).
 *
 * M6 adds the safe-write screens (/plan, /plan/:deviceId, /changes,
 * /changes/:id). /plan sits behind PLAN_CREATE and /changes behind
 * CHANGE_APPLY: reading what a plan would do and being allowed to push it are
 * two different privileges, exactly as CONFIG_READ is distinct from
 * DEVICE_READ below.
 *
 * M7 adds /rollouts and /rollouts/:id (CHANGE_APPLY — a rollout is N change
 * jobs and nothing else). M8 adds /logs (DEVICE_READ) and the attribution
 * banner inside /drift/:id. M9 adds /query (CONFIG_READ at the route, QUERY_RUN
 * checked inside the page: reading configuration and being allowed to sweep the
 * whole fleet for a pattern are two different privileges). /alerts is opened
 * with no capability, matching §4.1 — it reads `/api/live-alerts`, which is
 * session-scoped rather than capability-scoped.
 *
 * M10 adds /acs (ACS_ADMIN — §4.1 names that capability explicitly). M11 adds
 * /intent and M12 /baseline; neither has a row in §4.1, which stops at the
 * screens known when the spec was written, so their guards are derived from
 * what the pages actually do. /intent sits behind TEMPLATE_WRITE: composing a
 * site intent is authoring configuration, and `capabilities.ts` files intent
 * under "Templates & intent (M5 / K4)" itself. /baseline sits behind
 * CONFIG_READ because mining reads snapshots; the promote-to-template gesture
 * inside it carries its own TEMPLATE_WRITE check, exactly as /query opens on
 * CONFIG_READ and then checks QUERY_RUN before executing.
 *
 * The remaining fleet pages (/templates, /variables, /backups, /admin/audit)
 * arrive later — the sidebar renders them as disabled entries so no menu item
 * can navigate to a route that does not exist.
 *
 * `/config` and `/drift` sit behind CONFIG_READ, which risk R10 makes
 * deliberately DISTINCT from DEVICE_READ: seeing that a router exists and
 * reading its configuration are two different privileges, and the sidebar
 * guard and the route guard have to agree on that or one of them is decorative.
 */
export default function App() {
  const { checkSession } = useAuthStore();

  useEffect(() => {
    checkSession();
  }, [checkSession]);

  return (
    <BrowserRouter>
      <Suspense fallback={<div className="p-8 text-sm text-text-secondary">…</div>}>
        <Routes>
        {/* Public routes */}
        <Route path="/login" element={<LoginPage />} />
        <Route path="/forgot-password" element={<ForgotPasswordPage />} />
        <Route path="/reset-password" element={<ResetPasswordPage />} />
        {/* Protected routes */}
        <Route element={<ProtectedRoute />}>
          {/* Enrollment — full-screen, outside AppLayout */}
          <Route path="/enroll" element={<EnrollmentPage />} />
          {/* SSO new-user enrollment — full-screen, outside AppLayout */}
          <Route path="/sso-enroll" element={<SsoEnrollPage />} />
          <Route element={<AppLayout />}>
            <Route path="/" element={<DashboardPage />} />
            <Route path="/profile" element={<ProfilePage />} />
            <Route path="/group/:id" element={<GroupDetailPage />} />
            <Route path="/group/:id/edit" element={<GroupEditPage />} />

            {/* Fleet inventory (M2) → DEVICE_READ capability */}
            <Route element={<ProtectedRoute requiredCapability={CAPABILITIES.DEVICE_READ} />}>
              <Route path="/devices" element={<DevicesPage />} />
              <Route path="/devices/:id" element={<DeviceDetailPage />} />
              <Route path="/sites" element={<SitesPage />} />
              <Route path="/templates" element={<TemplatesPage />} />
              <Route path="/variables" element={<VariablesPage />} />
              <Route path="/admin/audit" element={<AuditPage />} />
              <Route path="/backups" element={<BackupsPage />} />
              <Route path="/sites/:id" element={<SiteDetailPage />} />
              {/* Telemetry (M3). The thresholds screen sits UNDER /interfaces
                  rather than under a sidebar entry of its own: spec §4.1 gives
                  it no row, and the mission for this milestone unlocks the
                  Interfaces entry only. */}
              <Route path="/interfaces" element={<InterfacesPage />} />
              <Route path="/interfaces/thresholds" element={<ThresholdsPage />} />
              {/* Unified log (M8, K6/K7): syslog + traps + RouterOS /log.
                  DEVICE_READ and not CONFIG_READ — a log line is an event about
                  a box, not its configuration. */}
              <Route path="/logs" element={<LogsPage />} />
            </Route>

            {/* Configuration + drift (M4) → CONFIG_READ capability */}
            <Route element={<ProtectedRoute requiredCapability={CAPABILITIES.CONFIG_READ} />}>
              <Route path="/config" element={<ConfigPage />} />
              <Route path="/config/:deviceId" element={<ConfigPage />} />
              <Route path="/drift" element={<DriftPage />} />
              <Route path="/drift/:id" element={<DriftDetailPage />} />
              {/* Fleet Query (M9, K5). CONFIG_READ opens the screen because a
                  query answers about configuration; the page itself then checks
                  QUERY_RUN before it will execute one. */}
              <Route path="/query" element={<QueryPage />} />
              {/* Fleet takeover / Golden Site (M12, K8). Mining reads every
                  snapshot the session may read, which is CONFIG_READ and
                  nothing more — it touches no equipment (D3). Promoting a
                  deduced draft into a template is a different privilege and is
                  checked inside the page against TEMPLATE_WRITE. */}
              <Route path="/baseline" element={<BaselinePage />} />
            </Route>

            {/* Intent compiler (M11, K4) -> TEMPLATE_WRITE.
                Composing an intent is authoring configuration for a whole site,
                and `capabilities.ts` files intent under "Templates & intent"
                itself. The screen compiles and stops there: §5/M11 puts
                `capabilityCheck` BEFORE any network access, and applying stays
                behind /plan and the change queue (D3). */}
            <Route element={<ProtectedRoute requiredCapability={CAPABILITIES.TEMPLATE_WRITE} />}>
              <Route path="/intent" element={<IntentPage />} />
            </Route>

            {/* ACS / TR-069 (M10, C10) -> ACS_ADMIN, as §4.1 requires.
                CPEs, the CWMP task queue, the parameter map and firmware — the
                four things that capability's description names. Coverage is
                DrayTek + Zyxel CPE only (D2) and the page states that before it
                states anything else. */}
            <Route element={<ProtectedRoute requiredCapability={CAPABILITIES.ACS_ADMIN} />}>
              <Route path="/acs" element={<AcsPage />} />
            </Route>

            {/* Plan compilation (M5 screens, M6 gate) -> PLAN_CREATE.
                Deliberately NOT CHANGE_APPLY: compiling and reading a plan
                touches no equipment, and an operator who may not push must
                still be able to ask "what would ObliWAN change on this box".
                The apply controls inside the page carry their own
                CHANGE_APPLY / CHANGE_APPROVE checks. */}
            <Route element={<ProtectedRoute requiredCapability={CAPABILITIES.PLAN_CREATE} />}>
              <Route path="/plan" element={<PlanPage />} />
              <Route path="/plan/:deviceId" element={<PlanPage />} />
            </Route>

            {/* Change jobs (M6 -- decision D3) -> CHANGE_APPLY.
                The queue is the ONLY path along which this product writes to an
                equipment, so the screens that watch it sit behind the same
                capability that enqueues one. The kill switch lives here too:
                it is reached in a panic and must not be behind an admin page. */}
            <Route element={<ProtectedRoute requiredCapability={CAPABILITIES.CHANGE_APPLY} />}>
              <Route path="/changes" element={<ChangesPage />} />
              <Route path="/changes/:id" element={<ChangeJobPage />} />
              {/* Wave rollouts (M7 — killer K3). Same capability as the queue
                  they feed: a rollout is N change jobs and nothing else, so
                  gating it more loosely than /changes would be a way around
                  CHANGE_APPLY rather than a separate privilege. */}
              <Route path="/rollouts" element={<RolloutsPage />} />
              <Route path="/rollouts/:id" element={<RolloutDetailPage />} />
            </Route>

            {/* Alerts (§4.1: no capability guard). Backed by
                `/api/live-alerts`, which is scoped by the session's tenants
                rather than by a capability. */}
            <Route path="/alerts" element={<AlertsPage />} />

            {/* Group management → GROUP_WRITE capability */}
            <Route element={<ProtectedRoute requiredCapability={CAPABILITIES.GROUP_WRITE} />}>
              <Route path="/admin/groups" element={<GroupManagePage />} />
            </Route>

            {/* Admin-only routes */}
            <Route element={<ProtectedRoute requiredRole="admin" />}>
              <Route path="/admin/discoveries" element={<DiscoveriesPage />} />
              <Route path="/admin/notifications" element={<NotificationsPage />} />
              <Route path="/admin/users" element={<AdminUsersPage />} />
              <Route path="/admin/import-export" element={<ImportExportPage />} />
              <Route path="/admin/tenants" element={<AdminTenantsPage />} />
              <Route path="/admin/settings" element={<SettingsPage />} />
            </Route>
          </Route>
        </Route>

        {/* 404 */}
        <Route path="*" element={<NotFoundPage />} />
      </Routes>
      </Suspense>

      <Toaster
        position="top-right"
        toastOptions={{
          className: '!bg-bg-secondary !text-text-primary !border !border-border',
          duration: 4000,
        }}
      />
    </BrowserRouter>
  );
}
