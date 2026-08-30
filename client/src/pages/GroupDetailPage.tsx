import { useEffect, useState } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { Pencil, Trash2, ArrowLeft, FolderOpen, Bell, Globe } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { anonHostname } from '@/utils/anonymize';
import { useGroupStore } from '@/store/groupStore';
import { useAuthStore } from '@/store/authStore';
import { groupsApi } from '@/api/groups.api';
import type { DeviceGroup } from '@obliwan/shared';
import { Button } from '@/components/common/Button';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { NotificationBindingsPanel } from '@/components/notifications/NotificationBindingsPanel';
import toast from 'react-hot-toast';

/**
 * Group detail.
 *
 * M1 scope: identity, badges, edit/delete and the inherited notification
 * bindings. The device list, PPP presence timeline and per-group variables /
 * templates panels arrive with the inventory (M2) and the template engine (M5).
 */
export function GroupDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { t } = useTranslation();
  const { isAdmin, canWriteGroup } = useAuthStore();
  const { getGroup, removeGroup, fetchGroups, fetchTree } = useGroupStore();

  const groupId = parseInt(id!, 10);
  const storeGroup = getGroup(groupId);
  const canWrite = canWriteGroup(groupId);

  const [group, setGroup] = useState<DeviceGroup | null>(storeGroup ?? null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    groupsApi.getById(groupId)
      .then(setGroup)
      .catch(() => { /* fall back to the store copy */ })
      .finally(() => setLoading(false));
  }, [groupId]);

  if (loading && !group) {
    return (
      <div className="flex h-full items-center justify-center">
        <LoadingSpinner size="lg" />
      </div>
    );
  }

  if (!group) {
    return (
      <div className="flex h-full flex-col items-center justify-center">
        <p className="text-text-muted">{t('groups.notFound', { defaultValue: 'Group not found' })}</p>
        <Link to="/" className="mt-4">
          <Button variant="secondary">{t('groups.backToDashboard', { defaultValue: 'Back to dashboard' })}</Button>
        </Link>
      </div>
    );
  }

  const handleDelete = async () => {
    if (!confirm(t('groups.confirmDelete', { name: group.name }))) return;
    try {
      await groupsApi.delete(groupId);
      removeGroup(groupId);
      void fetchGroups();
      void fetchTree();
      toast.success(t('groups.deleted'));
      navigate('/');
    } catch {
      toast.error(t('groups.failedDelete'));
    }
  };

  return (
    <div className="p-6">
      {/* Back button */}
      <Link to="/" className="mb-4 inline-flex items-center gap-1 text-sm text-text-secondary hover:text-text-primary">
        <ArrowLeft size={14} />
        {t('groups.backToDashboard', { defaultValue: 'Back to dashboard' })}
      </Link>

      {/* Header */}
      <div className="mb-6 flex items-start justify-between">
        <div className="flex items-center gap-4">
          <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-accent/10">
            <FolderOpen size={24} className="text-accent" />
          </div>
          <div>
            <h1 className="text-2xl font-semibold text-text-primary">{anonHostname(group.name)}</h1>
            <div className="mt-1 flex items-center gap-2">
              {group.isGeneral && (
                <span className="inline-flex items-center gap-1 rounded-full bg-accent/10 px-2 py-0.5 text-[10px] font-medium text-accent">
                  <Globe size={10} />
                  {t('groups.generalBadge')}
                </span>
              )}
              {group.groupNotifications && (
                <span className="inline-flex items-center gap-1 rounded-full bg-yellow-500/10 px-2 py-0.5 text-[10px] font-medium text-yellow-500">
                  <Bell size={10} />
                  {t('groups.groupedBadge')}
                </span>
              )}
              {group.description && (
                <span className="text-sm text-text-muted">{group.description}</span>
              )}
            </div>
          </div>
        </div>

        {canWrite && (
          <div className="flex items-center gap-2">
            <Link to={`/group/${groupId}/edit`}>
              <Button variant="secondary" size="sm">
                <Pencil size={14} className="mr-1.5" />
                {t('common.edit')}
              </Button>
            </Link>
            <Button variant="danger" size="sm" onClick={handleDelete}>
              <Trash2 size={14} className="mr-1.5" />
              {t('common.delete')}
            </Button>
          </div>
        )}
      </div>

      {/* Devices — M2 */}
      <div className="rounded-lg border border-border bg-bg-secondary px-4 py-8 text-center text-sm text-text-muted">
        {t('groups.detail.devicesLater', {
          defaultValue: 'Devices attached to this group appear here once the inventory lands (M2).',
        })}
      </div>

      {/* Notification bindings (admin only) */}
      {isAdmin() && (
        <div className="mt-6">
          <NotificationBindingsPanel
            scope="group"
            scopeId={groupId}
            title={t('groups.detail.notifications', { defaultValue: 'Notifications' })}
          />
        </div>
      )}
    </div>
  );
}
