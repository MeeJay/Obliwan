import { useEffect } from 'react';
import { getSocket } from '../socket/socketClient';
import { useGroupStore } from '../store/groupStore';
import { useAuthStore } from '../store/authStore';
import { useLiveAlertsStore } from '../store/liveAlertsStore';
import { useDeviceStore } from '../store/deviceStore';
import { useSiteStore } from '../store/siteStore';
import { useChangeStore } from '../store/changeStore';
import { SOCKET_EVENTS } from '@obliwan/shared';
import type {
  DeviceGroup,
  LiveAlertData,
  ReachabilityVerdict,
  SitePresenceEvent,
} from '@obliwan/shared';
import type { Device, Site } from '../types/fleet';

/**
 * Global socket subscriptions, mounted once by AppLayout.
 *
 * M2 adds the fleet vocabulary that now has a store behind it: presence,
 * reachability verdicts, and site/device CRUD. Presence events mutate the
 * store IN PLACE — they never trigger a refetch. That is what makes the
 * pastille flip in under two seconds when the tunnel drops, which is the
 * acceptance criterion for this milestone.
 *
 * Still not subscribed, on purpose, because nothing consumes them yet:
 * `wan:device:transportState`, `wan:discovery:*` (the Discoveries page is a
 * deliberate pull — an admin reviewing a quarantine queue should not have rows
 * appear and move under the cursor mid-decision), `wan:drift:*`, `wan:job:*`,
 * `wan:rollout:*`, `wan:acs:*`, `wan:telemetry:*`.
 *
 * M6 adds ONE global subscription: `wan:killSwitch:changed`. It lives here
 * rather than on ChangesPage because the whole point of the kill switch is
 * that every client drops its apply controls the instant it flips, WHATEVER
 * page it is on -- a stale Apply button on a screen somebody opened five
 * minutes ago is exactly the click the switch exists to prevent. The per-job
 * `wan:job:*` frames stay page-local (`hooks/useJobSocket.ts'): they are
 * high-volume and only three screens consume them.
 */
export function useSocket() {
  const { user } = useAuthStore();
  const { addGroup, updateGroup, removeGroup, fetchTree } = useGroupStore();

  useEffect(() => {
    if (!user) return;

    const socket = getSocket();
    if (!socket) return;

    // ── Live alert (NOTIFICATION_NEW) ─────────────────────────────────────────
    // The server persists alerts in the DB and emits NOTIFICATION_NEW.
    // We add the alert to the local store; toast display is handled by LiveAlerts.tsx.
    socket.on(SOCKET_EVENTS.NOTIFICATION_NEW, (alert: LiveAlertData) => {
      useLiveAlertsStore.getState().addAlertFromServer(alert);
    });

    // ── Group events ──────────────────────────────────────────────────────────
    socket.on(SOCKET_EVENTS.GROUP_CREATED, (data: { group: DeviceGroup }) => {
      addGroup(data.group);
      void fetchTree();
    });
    socket.on(SOCKET_EVENTS.GROUP_UPDATED, (data: { group: DeviceGroup }) => {
      updateGroup(data.group.id, data.group);
      void fetchTree();
    });
    socket.on(SOCKET_EVENTS.GROUP_DELETED, (data: { groupId: number }) => {
      removeGroup(data.groupId);
      void fetchTree();
    });
    socket.on(SOCKET_EVENTS.GROUP_MOVED, (data: { group: DeviceGroup }) => {
      updateGroup(data.group.id, data.group);
      void fetchTree();
    });

    // ── PPP presence (M2 — decision D4) ───────────────────────────────────────
    // Both names carry the same `SitePresenceEvent` payload: the concentrator
    // is the source of truth and it reports one session at a time. They are
    // folded through the same reducer so the two can never diverge.
    const onPresence = (event: SitePresenceEvent) => {
      useDeviceStore.getState().applyPresenceEvent(event);
    };
    socket.on(SOCKET_EVENTS.SITE_PRESENCE, onPresence);
    socket.on(SOCKET_EVENTS.DEVICE_PRESENCE, onPresence);

    // ── K7 verdict changes ────────────────────────────────────────────────────
    socket.on(
      SOCKET_EVENTS.DEVICE_REACHABILITY,
      (data: { deviceId: number; verdict: ReachabilityVerdict; ts?: string }) => {
        if (typeof data?.deviceId !== 'number' || !data.verdict) return;
        useDeviceStore.getState().applyReachability(data);
      },
    );

    // ── Fleet CRUD ────────────────────────────────────────────────────────────
    socket.on(SOCKET_EVENTS.DEVICE_CREATED, (data: { device: Device }) => {
      if (data?.device) useDeviceStore.getState().upsertDevice(data.device);
    });
    socket.on(SOCKET_EVENTS.DEVICE_UPDATED, (data: { device: Device }) => {
      if (data?.device) useDeviceStore.getState().upsertDevice(data.device);
    });
    socket.on(SOCKET_EVENTS.DEVICE_DELETED, (data: { deviceId: number }) => {
      if (typeof data?.deviceId === 'number') useDeviceStore.getState().removeDevice(data.deviceId);
    });

    socket.on(SOCKET_EVENTS.SITE_CREATED, (data: { site: Site }) => {
      if (data?.site) useSiteStore.getState().upsertSite(data.site);
    });
    socket.on(SOCKET_EVENTS.SITE_UPDATED, (data: { site: Site }) => {
      if (data?.site) useSiteStore.getState().upsertSite(data.site);
    });
    socket.on(SOCKET_EVENTS.SITE_DELETED, (data: { siteId: number }) => {
      if (typeof data?.siteId === 'number') useSiteStore.getState().removeSite(data.siteId);
    });

    // -- Kill switch (M6) ------------------------------------------------------
    // Folded straight into the store; no refetch, so the buttons go down in the
    // same tick. The store's normaliser fails CLOSED: a frame it cannot read
    // leaves the switch engaged rather than clearing it.
    socket.on(SOCKET_EVENTS.KILL_SWITCH_CHANGED, (data: unknown) => {
      useChangeStore.getState().applyKillSwitchEvent(data);
    });

    return () => {
      socket.off(SOCKET_EVENTS.NOTIFICATION_NEW);
      socket.off(SOCKET_EVENTS.GROUP_CREATED);
      socket.off(SOCKET_EVENTS.GROUP_UPDATED);
      socket.off(SOCKET_EVENTS.GROUP_DELETED);
      socket.off(SOCKET_EVENTS.GROUP_MOVED);
      socket.off(SOCKET_EVENTS.SITE_PRESENCE, onPresence);
      socket.off(SOCKET_EVENTS.DEVICE_PRESENCE, onPresence);
      socket.off(SOCKET_EVENTS.DEVICE_REACHABILITY);
      socket.off(SOCKET_EVENTS.DEVICE_CREATED);
      socket.off(SOCKET_EVENTS.DEVICE_UPDATED);
      socket.off(SOCKET_EVENTS.DEVICE_DELETED);
      socket.off(SOCKET_EVENTS.SITE_CREATED);
      socket.off(SOCKET_EVENTS.SITE_UPDATED);
      socket.off(SOCKET_EVENTS.SITE_DELETED);
      socket.off(SOCKET_EVENTS.KILL_SWITCH_CHANGED);
    };
  }, [user, addGroup, updateGroup, removeGroup, fetchTree]);
}
