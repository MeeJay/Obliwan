import { useCallback, useEffect, useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import {
  DndContext,
  PointerSensor,
  useSensor,
  useSensors,
  useDroppable,
  useDraggable,
  type DragEndEvent,
} from '@dnd-kit/core';
import {
  Activity,
  Archive,
  BellRing,
  Braces,
  Building2,
  Cpu,
  ChevronDown,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
  FileCode,
  FolderTree,
  GitCompareArrows,
  GripVertical,
  Layers,
  LayoutDashboard,
  Lock,
  LogOut,
  MapPin,
  PackageOpen,
  Pin,
  PinOff,
  PlayCircle,
  Radar,
  RadioTower,
  Rocket,
  Router,
  ScrollText,
  Search,
  Send,
  Server,
  Settings,
  ShieldCheck,
  SquareStack,
  Users,
} from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { cn } from '@/utils/cn';
import { useAuthStore } from '@/store/authStore';
import { useGroupStore } from '@/store/groupStore';
import { useUiStore } from '@/store/uiStore';
import type { GroupTreeNode, Capability } from '@obliwan/shared';
import { CAPABILITIES } from '@obliwan/shared';
import { groupsApi } from '@/api/groups.api';
import { anonHostname, anonUsername } from '@/utils/anonymize';
import { UserAvatar } from '@/components/common/UserAvatar';
import { useDeviceStore } from '@/store/deviceStore';
import { PresenceDot } from '@/components/fleet/PresenceDot';
import { FleetTree } from '@/components/fleet/FleetTree';
import toast from 'react-hot-toast';

// ── localStorage helpers ─────────────────────────────────────────────────────

function usePersisted<T>(key: string, initial: T): [T, (v: T | ((prev: T) => T)) => void] {
  const [value, setValue] = useState<T>(() => {
    try {
      const stored = localStorage.getItem(key);
      return stored !== null ? (JSON.parse(stored) as T) : initial;
    } catch {
      return initial;
    }
  });
  const set = useCallback((v: T | ((prev: T) => T)) => {
    setValue(prev => {
      const next = typeof v === 'function' ? (v as (p: T) => T)(prev) : v;
      localStorage.setItem(key, JSON.stringify(next));
      return next;
    });
  }, [key]);
  return [value, set];
}

// ── Recursive group section ───────────────────────────────────────────────────
//
// M2: the group tree now carries the devices filed under each group, each with
// its live PPP pastille. The dot is fed by `deviceStore.presence`, which the
// socket writes directly — the tree repaints on `wan:site:presence` without a
// refetch and without the fleet page being open. The sites → devices tree
// (spec §4.1) sits below, in <FleetTree />.

function GroupSection({ group, depth }: { group: GroupTreeNode; depth: number }) {
  const { t } = useTranslation();
  const location = useLocation();
  const [expanded, setExpanded] = usePersisted<boolean>(`sidebar:group-${group.id}-open`, true);

  const devices = useDeviceStore(s => s.devices);
  const livePresence = useDeviceStore(s => s.presence);
  const groupDevices = devices
    .filter(d => d.groupId === group.id)
    .sort((a, b) => a.name.localeCompare(b.name));

  const isGroupActive = location.pathname === `/group/${group.id}`;
  const hasContent = group.children.length > 0 || groupDevices.length > 0;

  const { setNodeRef: setDropRef, isOver } = useDroppable({
    id: `drop-group-${group.id}`,
    data: { type: 'group', groupId: group.id },
  });

  const { attributes, listeners, setNodeRef: setDragRef, isDragging } = useDraggable({
    id: `drag-group-${group.id}`,
    data: { type: 'group-drag', group },
  });

  return (
    <div
      ref={setDropRef}
      className={cn(
        'rounded-md transition-colors',
        isOver && 'ring-1 ring-accent bg-accent/10',
        isDragging && 'opacity-40',
      )}
    >
      <div
        className="flex items-center gap-0.5 group/row"
        style={{ paddingLeft: `${depth * 14}px` }}
      >
        <div
          ref={setDragRef}
          {...attributes}
          {...listeners}
          className="cursor-grab p-1 text-text-muted opacity-0 group-hover/row:opacity-50 hover:!opacity-100 shrink-0 transition-opacity"
          title={t('groups.dragReparent')}
        >
          <GripVertical size={10} />
        </div>

        <button
          onClick={() => setExpanded(v => !v)}
          className={cn(
            'p-0.5 text-text-muted hover:text-text-primary shrink-0 transition-colors',
            !hasContent && 'invisible pointer-events-none',
          )}
        >
          {expanded ? <ChevronDown size={10} /> : <ChevronRight size={10} />}
        </button>

        <Link
          to={`/group/${group.id}`}
          className={cn(
            'flex flex-1 items-center gap-2 rounded-md px-2 py-1 text-[13px] transition-colors',
            isGroupActive
              ? 'bg-bg-active text-text-primary'
              : 'text-text-secondary hover:bg-bg-hover hover:text-text-primary',
          )}
        >
          <Server size={13} className="shrink-0 text-text-muted" />
          <span className="truncate flex-1 font-medium">{anonHostname(group.name)}</span>
        </Link>
      </div>

      {expanded && groupDevices.map(device => {
        const presence = livePresence[device.id] ?? device.presence ?? null;
        const isDeviceActive = location.pathname === `/devices/${device.id}`;
        return (
          <Link
            key={device.id}
            to={`/devices/${device.id}`}
            style={{ paddingLeft: `${depth * 14 + 30}px` }}
            className={cn(
              'flex items-center gap-2 rounded-md py-1 pr-2 text-[12px] transition-colors',
              isDeviceActive
                ? 'bg-bg-active text-text-primary'
                : 'text-text-secondary hover:bg-bg-hover hover:text-text-primary',
            )}
          >
            <PresenceDot presence={presence} size={7} />
            <Router size={11} className="shrink-0 text-text-muted" />
            <span className="truncate flex-1">{anonHostname(device.name)}</span>
          </Link>
        );
      })}

      {expanded && group.children.map(child => (
        <GroupSection key={child.id} group={child} depth={depth + 1} />
      ))}
    </div>
  );
}

// ── Droppable root (un-parent target) ─────────────────────────────────────────

function DroppableRoot({ children }: { children: React.ReactNode }) {
  const { setNodeRef, isOver } = useDroppable({
    id: 'drop-group-root',
    data: { type: 'group', groupId: null },
  });
  return (
    <div
      ref={setNodeRef}
      className={cn('rounded-md transition-colors', isOver && 'ring-1 ring-accent bg-accent/10')}
    >
      {children}
    </div>
  );
}

// ── Nav items ────────────────────────────────────────────────────────────────

interface NavItem {
  label: string;
  path: string;
  icon: React.ReactNode;
  adminOnly?: boolean;
  /** Visible to non-admins holding this capability (admins always see it). */
  capability?: Capability;
  /**
   * THE SCREEN IS NOT BUILT. Rendered greyed out and inert — never a <Link> —
   * so a menu item can never point at a route App.tsx does not register.
   *
   * It used to hold a milestone number ('M4', 'M5') and the tooltip read
   * "coming in M5". Those milestones shipped; the SERVER routes behind these
   * four entries are live. What is missing is client work that was never
   * scoped, and a label naming a delivered milestone turned an honest padlock
   * into a lie that survived ten milestones on the first screen of the app.
   *
   * A boolean cannot go stale the way a version number does.
   */
  notBuilt?: boolean;
}

// ── Main Sidebar ──────────────────────────────────────────────────────────────

export function Sidebar() {
  const { t } = useTranslation();
  const location = useLocation();
  const { user, isAdmin, hasCapability } = useAuthStore();

  // Spec §4.1 — the full ObliWAN navigation. Entries carrying `notBuilt`
  // are shown disabled: their screen does not exist, whatever the API does.
  const navItems: NavItem[] = [
    { label: t('nav.dashboard'),      path: '/',            icon: <LayoutDashboard size={18} /> },
    { label: t('nav.devices'),        path: '/devices',     icon: <Router size={18} />,           capability: CAPABILITIES.DEVICE_READ },
    { label: t('nav.sites'),          path: '/sites',       icon: <MapPin size={18} />,           capability: CAPABILITIES.DEVICE_READ },
    { label: t('nav.interfaces'),     path: '/interfaces',  icon: <Activity size={18} />,         capability: CAPABILITIES.DEVICE_READ },
    // M4 unlocked these two. `/backups` and `/admin/audit` still carry an M4
    // marker below: they are M4 SERVER work whose screens are not in this
    // milestone's scope, and a nav entry pointing at an unregistered route is
    // exactly what the `milestone` field exists to prevent.
    { label: t('nav.configurations'), path: '/config',      icon: <FileCode size={18} />,         capability: CAPABILITIES.CONFIG_READ },
    { label: t('nav.drift'),          path: '/drift',       icon: <GitCompareArrows size={18} />, capability: CAPABILITIES.CONFIG_READ },
    { label: t('nav.templates'),      path: '/templates',   icon: <Layers size={18} />,           capability: CAPABILITIES.TEMPLATE_WRITE },
    { label: t('nav.variables'),      path: '/variables',   icon: <Braces size={18} />,           capability: CAPABILITIES.TEMPLATE_WRITE, notBuilt: true },
    // M11 (K4). Filed next to Templates rather than next to Changements on
    // purpose: composing an intent AUTHORS configuration, it does not push it.
    // §4.1 has no row for this screen — the spec's table stops at the pages
    // known when it was written — so the capability is derived from what the
    // page does, and `capabilities.ts` already files intent under "Templates &
    // intent (M5 / K4)".
    { label: t('nav.intent'),         path: '/intent',      icon: <Cpu size={18} />,              capability: CAPABILITIES.TEMPLATE_WRITE },
    // M6 unlocks Changements: /changes and /changes/:id exist in App.tsx and
    // the kill switch lives in that screen's header, one gesture from the
    // place an operator is standing when a change goes wrong.
    { label: t('nav.changes'),        path: '/changes',     icon: <PlayCircle size={18} />,       capability: CAPABILITIES.CHANGE_APPLY },
    // M7 unlocks Déploiements, M8 Journaux, M9 Requêtes parc. `/alerts` opens
    // with them: its data (`/api/live-alerts`) has been served since M1, and
    // the entry only ever lacked a page. §4.1 gives it no capability guard.
    { label: t('nav.rollouts'),       path: '/rollouts',    icon: <Rocket size={18} />,           capability: CAPABILITIES.CHANGE_APPLY },
    { label: t('nav.query'),          path: '/query',       icon: <Search size={18} />,           capability: CAPABILITIES.CONFIG_READ },
    // M12 (K8). CONFIG_READ: mining reads snapshots and nothing else. Turning a
    // deduced draft into a real template is TEMPLATE_WRITE and is checked
    // inside the page, the same split /query uses for QUERY_RUN.
    { label: t('nav.baseline'),       path: '/baseline',    icon: <SquareStack size={18} />,      capability: CAPABILITIES.CONFIG_READ },
    { label: t('nav.backups'),        path: '/backups',     icon: <Archive size={18} />,          capability: CAPABILITIES.CONFIG_READ,    notBuilt: true },
    // M10 unlocks TR-069 / ACS. The screen covers DrayTek + Zyxel CPE only
    // (D2) and says so in its first panel — the entry is NOT a claim that the
    // ACS reaches the whole fleet.
    { label: t('nav.acs'),            path: '/acs',         icon: <RadioTower size={18} />,       capability: CAPABILITIES.ACS_ADMIN },
    { label: t('nav.alerts'),         path: '/alerts',      icon: <BellRing size={18} /> },
    { label: t('nav.logs'),           path: '/logs',        icon: <ScrollText size={18} />,       capability: CAPABILITIES.DEVICE_READ },

    // ── admin section ──
    { label: t('nav.discoveries'),   path: '/admin/discoveries',   icon: <Radar size={18} />,       adminOnly: true },
    { label: t('nav.groups'),        path: '/admin/groups',        icon: <FolderTree size={18} />,  adminOnly: true },
    { label: t('nav.users'),         path: '/admin/users',         icon: <Users size={18} />,       adminOnly: true },
    { label: t('nav.workspaces'),    path: '/admin/tenants',       icon: <Building2 size={18} />,   adminOnly: true },
    { label: t('nav.notifications'), path: '/admin/notifications', icon: <Send size={18} />,        adminOnly: true },
    { label: t('nav.audit'),         path: '/admin/audit',         icon: <ShieldCheck size={18} />, adminOnly: true, notBuilt: true },
    { label: t('nav.importExport'),  path: '/admin/import-export', icon: <PackageOpen size={18} />, adminOnly: true },
    { label: t('nav.settings'),      path: '/admin/settings',      icon: <Settings size={18} />,    adminOnly: true },
  ];

  const {
    sidebarFloating,
    toggleSidebarFloating,
    sidebarCollapsed,
    toggleSidebarCollapsed,
  } = useUiStore();
  const { tree, fetchTree } = useGroupStore();

  const [search, setSearch] = useState('');
  const [adminMenuOpen, setAdminMenuOpen] = usePersisted<boolean>('sidebar:admin-open', true);

  const admin = isAdmin();
  const canManageGroups = admin || hasCapability(CAPABILITIES.GROUP_WRITE);

  const sensors = useSensors(
    useSensor(PointerSensor, { activationConstraint: { distance: 8 } }),
  );

  useEffect(() => {
    void fetchTree();
  }, [fetchTree]);

  const handleGroupDragEnd = useCallback(
    async (event: DragEndEvent) => {
      if (!canManageGroups) return; // read-only members: no drag-to-move
      const { active, over } = event;
      if (!over) return;

      const dragData = active.data.current;
      const dropData = over.data.current;

      if (dragData?.type === 'group-drag' && dropData?.type === 'group') {
        const group = dragData.group as GroupTreeNode;
        const targetGroupId = dropData.groupId as number | null;
        if (group.id === targetGroupId) return;
        try {
          await groupsApi.move(group.id, targetGroupId);
          void fetchTree();
          toast.success(t('groups.moved', { defaultValue: 'Group moved' }));
        } catch {
          toast.error(t('groups.moveFailed', { defaultValue: 'Failed to move group' }));
        }
      }
    },
    [fetchTree, canManageGroups, t],
  );

  const filteredNavItems = navItems.filter(item => {
    if (item.adminOnly && !admin) return false;
    if (item.capability && !admin && !hasCapability(item.capability)) return false;
    if (!search) return true;
    return item.label.toLowerCase().includes(search.toLowerCase());
  });

  const topNav = filteredNavItems.filter(item => !item.adminOnly);
  const adminNav = filteredNavItems.filter(item => item.adminOnly);

  const renderGroupTree = () => (
    <DndContext sensors={sensors} onDragEnd={handleGroupDragEnd}>
      <div className="mt-2 pt-2 border-t border-border">
        <div className="px-2 py-1.5 flex items-center gap-2 text-[11px] font-mono font-medium text-text-muted uppercase tracking-[0.12em]">
          <Server size={12} />
          {t('nav.groups')}
        </div>

        <DroppableRoot>
          {tree.length === 0 ? (
            <div className="px-2 py-2 text-[12px] text-text-muted">
              {t('groups.empty', { defaultValue: 'No groups yet' })}
            </div>
          ) : (
            tree.map(group => <GroupSection key={group.id} group={group} depth={0} />)
          )}
        </DroppableRoot>
      </div>
    </DndContext>
  );

  const lockedTitle = (item: NavItem) =>
    `${item.label} — ${t('nav.screenNotBuilt', { defaultValue: 'screen not built yet (the server API exists)' })}`;

  // ── Collapsed mode (Obli Design v1) — 64 px icon-only column ─────────────
  if (sidebarCollapsed) {
    const allItems = [...topNav, ...adminNav];
    return (
      <aside className="flex h-full w-16 shrink-0 flex-col bg-bg-secondary">
        <div className="flex h-12 shrink-0 items-center justify-center">
          <button
            onClick={toggleSidebarCollapsed}
            title={t('nav.expandSidebar', 'Expand sidebar')}
            className="rounded-md p-1.5 text-text-muted transition-colors hover:bg-bg-hover hover:text-text-primary"
          >
            <ChevronsRight size={16} />
          </button>
        </div>

        <nav className="flex-1 overflow-y-auto px-2 pt-3 space-y-1">
          {allItems.map((item) => {
            if (item.notBuilt) {
              return (
                <div
                  key={item.path}
                  title={lockedTitle(item)}
                  aria-disabled="true"
                  className="relative flex h-10 w-full cursor-not-allowed items-center justify-center rounded-md text-text-muted opacity-40"
                >
                  {item.icon}
                </div>
              );
            }
            const isActive = location.pathname === item.path
              || (item.path !== '/' && location.pathname.startsWith(item.path + '/'));
            return (
              <Link
                key={item.path}
                to={item.path}
                title={item.label}
                className={cn(
                  'relative flex h-10 w-full items-center justify-center rounded-md transition-colors',
                  isActive
                    ? 'bg-accent/12 text-accent'
                    : 'text-text-muted hover:bg-bg-hover hover:text-text-primary',
                )}
              >
                {item.icon}
              </Link>
            );
          })}
        </nav>

        <div className="p-2 space-y-1">
          <Link
            to="/profile"
            title={anonUsername(user?.displayName || (user?.username?.startsWith('og_') ? user.username.slice(3) : user?.username))}
            className={cn(
              'flex h-10 w-full items-center justify-center rounded-md transition-colors',
              location.pathname === '/profile'
                ? 'bg-bg-active text-text-primary'
                : 'text-text-secondary hover:bg-bg-hover hover:text-text-primary',
            )}
          >
            <UserAvatar avatar={user?.avatar} username={user?.username ?? '?'} size={24} />
          </Link>
          <button
            onClick={() => useAuthStore.getState().logout()}
            title={t('nav.signOut')}
            className="flex h-10 w-full items-center justify-center rounded-md text-text-muted transition-colors hover:bg-bg-hover hover:text-text-primary"
          >
            <LogOut size={18} />
          </button>
        </div>
      </aside>
    );
  }

  // ── Expanded mode ───────────────────────────────────────────────────────────

  const renderNavEntry = (item: NavItem) => {
    if (item.notBuilt) {
      return (
        <div
          key={item.path}
          title={lockedTitle(item)}
          aria-disabled="true"
          className="flex select-none items-center gap-3 rounded-md px-3 py-2 text-[14px] text-text-muted opacity-40 cursor-not-allowed"
        >
          {item.icon}
          <span className="flex-1 truncate">{item.label}</span>
          <Lock size={11} className="shrink-0" />
          <span className="font-mono text-[10px] tracking-wider">{item.notBuilt}</span>
        </div>
      );
    }
    // `/devices/42` must keep the "Fleet" entry lit — the detail page belongs
    // to the same section as the list it was opened from.
    const isActive = location.pathname === item.path
      || (item.path !== '/' && location.pathname.startsWith(item.path + '/'));
    return (
      <Link
        key={item.path}
        to={item.path}
        className={cn(
          'flex items-center gap-3 rounded-md px-3 py-2 text-[14px] transition-colors',
          isActive
            ? 'bg-bg-active text-text-primary'
            : 'text-text-secondary hover:bg-bg-hover hover:text-text-primary',
        )}
      >
        {item.icon}
        {item.label}
      </Link>
    );
  };

  return (
    <aside className="flex h-full w-full flex-col bg-bg-secondary">

      {/* Sidebar head — collapse + float/pin toggles only. The logo and
          tenant selector live in the topbar (Header.tsx) so they remain
          visible when the sidebar is collapsed or floating. */}
      <div className="flex h-9 shrink-0 items-center justify-end px-3 pt-2">
        <div className="flex items-center gap-1">
          {!sidebarFloating && (
            <button
              onClick={toggleSidebarCollapsed}
              title={t('nav.collapseSidebar', 'Collapse sidebar')}
              className="rounded p-1.5 text-text-muted transition-colors hover:bg-bg-hover hover:text-text-primary"
            >
              <ChevronsLeft size={15} />
            </button>
          )}
          <button
            onClick={toggleSidebarFloating}
            title={sidebarFloating ? t('nav.pinSidebar', 'Pin sidebar') : t('nav.floatSidebar', 'Float sidebar (auto-hide)')}
            className={cn(
              'p-1.5 rounded transition-colors',
              sidebarFloating
                ? 'text-accent hover:text-accent hover:bg-accent/10'
                : 'text-text-muted hover:text-text-primary hover:bg-bg-hover',
            )}
          >
            {sidebarFloating ? <PinOff size={15} /> : <Pin size={15} />}
          </button>
        </div>
      </div>

      {/* Search */}
      <div className="px-3 py-2.5">
        <input
          type="text"
          placeholder={t('common.search')}
          value={search}
          onChange={e => setSearch(e.target.value)}
          className="w-full rounded-md bg-bg-tertiary px-3 py-2 text-[13px] text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-accent"
        />
      </div>

      {/* Main nav + group tree */}
      <div className="flex-1 overflow-y-auto px-2 min-h-0">
        <nav>{topNav.map(renderNavEntry)}</nav>
        {renderGroupTree()}
        {(admin || hasCapability(CAPABILITIES.DEVICE_READ)) && <FleetTree />}
      </div>

      {/* Admin section collapsible */}
      {admin && adminNav.length > 0 && (
        <>
          <button
            onClick={() => setAdminMenuOpen(v => !v)}
            className="flex w-full items-center gap-2 px-3 py-1.5 text-text-muted hover:text-text-secondary transition-colors"
          >
            <div className="flex-1 h-px bg-border" />
            <ChevronDown size={12} className={cn('transition-transform duration-200', !adminMenuOpen && '-rotate-90')} />
            <div className="flex-1 h-px bg-border" />
          </button>

          {adminMenuOpen && <nav className="p-2 pt-0">{adminNav.map(renderNavEntry)}</nav>}
        </>
      )}

      {/* User section */}
      <div className="border-t border-border p-2">
        <Link
          to="/profile"
          className={cn(
            'flex items-center gap-2.5 rounded-md px-2 py-1.5 transition-colors',
            location.pathname === '/profile'
              ? 'bg-accent/10'
              : 'hover:bg-bg-hover',
          )}
        >
          <UserAvatar avatar={user?.avatar} username={user?.username ?? '?'} size={20} />
          <div className="min-w-0 flex-1">
            <div className="truncate text-[13px] font-medium text-text-primary">
              {anonUsername(user?.displayName || (user?.username?.startsWith('og_') ? user.username.slice(3) : user?.username))}
            </div>
            <div className="truncate font-mono text-[10px] text-text-muted">
              {(user?.username?.startsWith('og_') ? user.username.slice(3) : user?.username) ?? ''} · {user?.role ?? ''}
            </div>
          </div>
        </Link>
        <button
          onClick={() => useAuthStore.getState().logout()}
          className="flex w-full items-center gap-3 rounded-md px-3 py-2 text-sm text-text-secondary transition-colors hover:bg-bg-hover hover:text-text-primary"
        >
          <LogOut size={18} />
          {t('nav.signOut')}
        </button>
      </div>
    </aside>
  );
}
