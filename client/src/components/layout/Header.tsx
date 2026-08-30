import { useEffect, useState } from 'react';
import { LogOut } from 'lucide-react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { useAuthStore } from '@/store/authStore';
import { useTenantStore } from '@/store/tenantStore';
import { useSocketStore } from '@/store/socketStore';
import { anonUsername } from '@/utils/anonymize';
import { NotificationCenter } from './NotificationCenter';
import { TenantSwitcher } from './TenantSwitcher';
import { UserAvatar } from '@/components/common/UserAvatar';
import { Logo } from '@/components/common/Logo';
import { cn } from '@/utils/cn';

/** True when running inside the native desktop app overlay. */
const isNativeApp = typeof window !== 'undefined' &&
  !!(window as Window & { __obliwan_is_native_app?: boolean }).__obliwan_is_native_app;

// ── App switcher data ───────────────────────────────────────────────────────
//
// Per D:\Mockup\obli-design-system.md §1 + §4.1 — seven fixed pills, current
// app glowing with its own brand colour. Order is fixed across the suite so
// muscle memory carries between apps.

type AppType = 'obliwan' | 'obliview' | 'obliguard' | 'oblimap' | 'obliance' | 'obliplan' | 'oblidesk' | 'oblihub';

interface AppEntry {
  type: AppType;
  label: string;
  /** Brand dot colour. Reused as the active pill's text + glow. */
  color: string;
}

const APP_ORDER: AppEntry[] = [
  { type: 'obliview',  label: 'Obliview',  color: '#2bc4bd' },
  { type: 'obliguard', label: 'Obliguard', color: '#f5a623' },
  // TODO(design): ObliWAN has no brand colour of its own yet — this is a
  // placeholder, to be replaced together with the logo/favicon artwork.
  { type: 'obliwan',   label: 'ObliWAN',   color: '#4e9cff' },
  { type: 'oblimap',   label: 'Oblimap',   color: '#1edd8a' },
  { type: 'obliance',  label: 'Obliance',  color: '#e03a3a' },
  { type: 'obliplan',  label: 'Obliplan',  color: '#7c6cff' },
  { type: 'oblidesk',  label: 'Oblidesk',  color: '#22b8f5' },
  { type: 'oblihub',   label: 'Oblihub',   color: '#2d4ec9' },
];

const CURRENT_APP: AppType = 'obliwan';

export function Header() {
  const { t } = useTranslation();
  const { user, logout } = useAuthStore();
  const { status: socketStatus } = useSocketStore();
  const [connectedApps, setConnectedApps] = useState<Array<{ appType: string; name: string; baseUrl: string }>>([]);

  useEffect(() => {
    fetch('/api/auth/connected-apps', { credentials: 'include' })
      .then(r => r.json())
      .then((d: { success: boolean; data?: Array<{ appType: string; name: string; baseUrl: string }> }) => {
        if (d.success && d.data) setConnectedApps(d.data);
      })
      .catch(() => {});
  }, []);

  // Build a map of which apps are reachable so we know which pills are
  // clickable. The current app (ObliWAN) is always available.
  const reachable = new Set<string>([CURRENT_APP]);
  for (const a of connectedApps) reachable.add(a.appType);

  const goApp = (app: AppEntry) => {
    if (app.type === CURRENT_APP) return;
    const target = connectedApps.find(c => c.appType === app.type);
    if (!target) return;
    // Cross-app tenant handoff: forward the current tenant slug so the target
    // app can re-select the same tenant after Obligate SSO completes. Falls
    // back to the user's first available tenant on the target side if the
    // slug does not exist there.
    const ts = useTenantStore.getState();
    const tenantSlug = ts.tenants.find(t => t.id === ts.currentTenantId)?.slug;
    const url = new URL(`${target.baseUrl}/auth/sso-redirect`);
    if (tenantSlug) url.searchParams.set('tenant', tenantSlug);
    window.location.href = url.toString();
  };

  const username = user?.username ?? '';
  const rawName = user?.displayName?.trim() || (username.startsWith('og_') ? username.slice(3) : username);
  const displayedUsername = anonUsername(rawName);

  return (
    <header className="flex h-13 shrink-0 items-center gap-3 bg-bg-secondary px-4" style={{ height: 52 }}>
      {/* Logo — always visible in the topbar so it stays accessible regardless
          of sidebar state (pinned, collapsed, floating). */}
      <Link to="/" className="flex items-center gap-2 shrink-0">
        <Logo className="h-8 w-auto max-w-[160px] object-contain" />
      </Link>

      {/* Tenant selector — sits left of the app switcher, preserving the
          context that gets carried across apps. */}
      <TenantSwitcher />

      {/* App switcher pills — only show the current app + apps the user can
          actually reach (returned by /api/auth/connected-apps). Unreachable
          apps are hidden entirely rather than greyed out. */}
      {!isNativeApp && (
        <nav className="flex items-center gap-1 rounded-lg bg-bg-hover p-1 ml-1">
          {APP_ORDER
            .filter((app) => app.type === CURRENT_APP || reachable.has(app.type))
            .map((app) => {
              const isCurrent = app.type === CURRENT_APP;
              return (
                <button
                  key={app.type}
                  type="button"
                  onClick={() => goApp(app)}
                  className={cn(
                    'flex items-center gap-2 px-3 py-1.5 rounded-md text-[12.5px] font-medium transition-colors',
                    isCurrent
                      ? 'bg-bg-secondary text-text-primary font-semibold shadow-[0_1px_3px_rgb(46_52_64_/_0.1)]'
                      : 'text-text-secondary hover:bg-bg-active hover:text-text-primary',
                  )}
                  title={app.label}
                >
                  <span
                    className="w-2 h-2 rounded-full shrink-0"
                    style={{ background: app.color }}
                  />
                  {app.label}
                </button>
              );
            })}
        </nav>
      )}

      <div className="ml-auto flex items-center gap-3">
        {/* Socket connection status dot */}
        <button
          onClick={socketStatus !== 'connected' ? () => window.location.reload() : undefined}
          title={
            socketStatus === 'connected'    ? t('header.socketConnected')    :
            socketStatus === 'reconnecting' ? t('header.socketReconnecting') :
                                              t('header.socketDisconnected')
          }
          className={cn(
            'flex h-7 w-7 items-center justify-center rounded-md transition-opacity',
            socketStatus !== 'connected' && 'cursor-pointer hover:opacity-70',
            socketStatus === 'connected'  && 'cursor-default',
          )}
        >
          <span
            className={cn(
              'h-2 w-2 rounded-full transition-colors',
              socketStatus === 'connected'    && 'bg-green-500',
              socketStatus === 'reconnecting' && 'bg-amber-400 animate-pulse',
              socketStatus === 'disconnected' && 'bg-red-500 animate-pulse',
            )}
          />
        </button>

        {/* Notification Center */}
        <NotificationCenter />

        {user && (
          <>
            <div className="flex items-center gap-2 pl-1.5 pr-3 py-1 rounded-lg bg-bg-hover">
              <UserAvatar avatar={user.avatar} username={username} size={28} />
              <span className="text-[13px] font-medium text-text-primary">{displayedUsername}</span>
              <span className="text-[10px] font-mono uppercase tracking-wider text-accent pl-2 border-l border-border-light">
                {user.role}
              </span>
            </div>
            <button
              onClick={logout}
              title={t('nav.signOut')}
              className="flex h-7 w-7 items-center justify-center rounded-md text-text-muted hover:bg-bg-hover hover:text-text-primary transition-colors"
            >
              <LogOut size={15} />
            </button>
          </>
        )}
      </div>
    </header>
  );
}

