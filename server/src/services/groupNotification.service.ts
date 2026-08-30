import { groupService } from './group.service';
import { logger } from '../utils/logger';

/**
 * Consolidation of per-entity alerts into ONE group-level notification.
 *
 * A group flagged `group_notifications = true` emits a single "group is down"
 * when its first member goes down, and a single "group recovered" when the last
 * one comes back — instead of N notifications for N members.
 *
 * STATE IS IN MEMORY, BY DESIGN AND WITH A KNOWN LIMIT: on restart the map is
 * empty, so the first member to go down after a restart re-notifies. Obliguard
 * papered over this by rehydrating from its `monitors` table at boot. ObliWAN
 * has no such table in M1 — `devices` arrives with migration 002 — so
 * `initialize()` is deliberately a no-op here rather than a query against a
 * relation that does not exist. Rehydration is a two-line change once
 * `devices.presence` is available (see the TODO below).
 *
 * The API is entity-agnostic on purpose ("member", not "monitor"): in M2 the
 * members are devices, and nothing in this file needs to change.
 */

interface GroupNotifState {
  downMemberIds: Set<number>;
  downMemberNames: Map<number, string>; // id -> name, for message bodies
  notifiedDown: boolean; // true once the "group is down" notification went out
}

const groupStates = new Map<number, GroupNotifState>();

function getOrCreateState(groupId: number): GroupNotifState {
  let state = groupStates.get(groupId);
  if (!state) {
    state = {
      downMemberIds: new Set(),
      downMemberNames: new Map(),
      notifiedDown: false,
    };
    groupStates.set(groupId, state);
  }
  return state;
}

export const groupNotificationService = {
  /**
   * Rehydrate the state map at boot.
   *
   * TODO (M2): once `devices` exists, list the devices whose presence is down
   * inside each flagged group's subtree (via groupService.getDescendantIds)
   * and pre-fill the state with `notifiedDown = true`, so a restart does not
   * re-announce an outage that was already reported.
   */
  async initialize(): Promise<void> {
    // Boot-time platform-wide count: legitimately cross-tenant, and now says so
    // explicitly instead of relying on getAll() dropping its tenant filter for
    // tenant 1 (AUDIT-SEC #2 removed that implicit widening).
    const flaggedGroups = await groupService.getAll(1, { crossTenant: true });
    const count = flaggedGroups.filter((g) => g.groupNotifications).length;
    logger.info(
      `GroupNotification: ${count} group(s) with grouped notifications enabled ` +
        '(no members to track before M2)',
    );
  },

  /**
   * Is this member covered by an ancestor group with grouped notifications?
   * Returns that ancestor's id, or null when the member should notify on its own.
   *
   * VERIF-SECFIX-AUTRES #15 — `groupService.findGroupNotificationAncestor`
   * used to walk `group_closure` with NO tenant filter, and
   * `checkClosureIntegrity` only LOGS a cross-tenant edge, it does not delete
   * it. In M2 this answer names the group in the notification title: a stale
   * edge `<acme group> -> <globex group>` would announce a Globex outage under
   * an Acme group's name, through Acme's channels.
   *
   * That is now closed IN THE HELPER (the tenant filter is applied to both ends
   * of the closure edge), so the local re-confrontation that used to sit here —
   * one extra query per member state change — is gone with it, and `tenantId`
   * is mandatory: it is the tenant of the member that went down.
   */
  async shouldSuppressIndividual(
    groupId: number | null,
    tenantId: number,
  ): Promise<number | null> {
    if (groupId === null) return null;
    const ancestor = await groupService.findGroupNotificationAncestor(groupId, tenantId);
    return ancestor ? ancestor.id : null;
  },

  /**
   * Record a member going DOWN.
   * 'first_down'  -> send the group notification.
   * 'already_down'-> suppress, the group is already reported down.
   */
  handleMemberDown(
    memberId: number,
    memberName: string,
    groupNotifGroupId: number,
  ): 'first_down' | 'already_down' {
    const state = getOrCreateState(groupNotifGroupId);
    state.downMemberIds.add(memberId);
    state.downMemberNames.set(memberId, memberName);

    if (!state.notifiedDown) {
      state.notifiedDown = true;
      return 'first_down';
    }
    return 'already_down';
  },

  /**
   * Record a member coming back UP.
   * 'all_recovered' -> send the recovery notification.
   * 'still_down'    -> suppress, other members are still down.
   */
  handleMemberUp(
    memberId: number,
    groupNotifGroupId: number,
  ): 'all_recovered' | 'still_down' {
    const state = groupStates.get(groupNotifGroupId);
    if (!state) return 'still_down';

    state.downMemberIds.delete(memberId);
    state.downMemberNames.delete(memberId);

    if (state.downMemberIds.size === 0 && state.notifiedDown) {
      state.notifiedDown = false;
      return 'all_recovered';
    }
    return 'still_down';
  },

  /** Names of the members currently down in a group, for the message body. */
  getDownMemberNames(groupNotifGroupId: number): string[] {
    const state = groupStates.get(groupNotifGroupId);
    if (!state) return [];
    return Array.from(state.downMemberNames.values());
  },

  /** Forget a member entirely — it was deleted or moved to another group. */
  removeMember(memberId: number): void {
    for (const [, state] of groupStates) {
      state.downMemberIds.delete(memberId);
      state.downMemberNames.delete(memberId);
    }
  },

  /** Forget a group's state — it was deleted or its flag was toggled. */
  removeGroup(groupId: number): void {
    groupStates.delete(groupId);
  },
};
