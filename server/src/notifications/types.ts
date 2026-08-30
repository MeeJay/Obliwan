import type { NotificationConfigField } from '@obliwan/shared';

export interface NotificationPayload {
  entityName: string;
  entityUrl?: string;
  oldStatus: string;
  newStatus: string;
  message?: string;
  timestamp: string;
  appName?: string;
  // Group notification fields
  groupName?: string;
  groupId?: number;
  downMembers?: string[];
  isGroupNotification?: boolean;
}

export interface NotificationPlugin {
  type: string;
  name: string;
  description: string;
  configFields: NotificationConfigField[];

  send(config: Record<string, unknown>, payload: NotificationPayload): Promise<void>;
  sendTest(config: Record<string, unknown>): Promise<void>;
}
