import type { NotificationPlugin, NotificationPayload } from '../types';
import nodemailer from 'nodemailer';
import { statusIcon } from '../statusIcons';

export const smtpPlugin: NotificationPlugin = {
  type: 'smtp',
  name: 'Email (SMTP)',
  description: 'Send email notifications via a global SMTP server',
  configFields: [
    { key: 'smtpServerId', label: 'SMTP Server', type: 'smtp_server_select', required: true },
    { key: 'fromOverride', label: 'From Address Override', type: 'text', required: false, placeholder: 'Leave blank to use server default' },
    { key: 'to', label: 'To Address(es)', type: 'text', required: true, placeholder: 'admin@example.com' },
  ],

  // config here is the RESOLVED config (host/port/etc injected by resolveChannelConfig)
  async send(config, payload) {
    const icon = statusIcon(payload.newStatus);
    const transport = nodemailer.createTransport({
      host: String(config.host),
      port: Number(config.port),
      secure: Boolean(config.secure),
      auth: {
        user: String(config.username),
        pass: String(config.password),
      },
    });

    await transport.sendMail({
      from: String(config.from),
      to: String(config.to),
      subject: `${icon} ${payload.entityName} is ${payload.newStatus.toUpperCase()}`,
      text: [
        `Monitor: ${payload.entityName}`,
        `Status: ${payload.oldStatus} → ${payload.newStatus}`,
        payload.message ? `Message: ${payload.message}` : '',
        payload.entityUrl ? `URL: ${payload.entityUrl}` : '',
        `Time: ${payload.timestamp}`,
      ].filter(Boolean).join('\n'),
      html: [
        `<h2>${icon} ${payload.entityName}</h2>`,
        `<p><strong>Status:</strong> ${payload.oldStatus} → <strong>${payload.newStatus.toUpperCase()}</strong></p>`,
        payload.message ? `<p>${payload.message}</p>` : '',
        payload.entityUrl ? `<p><a href="${payload.entityUrl}">${payload.entityUrl}</a></p>` : '',
        `<p><small>${payload.timestamp}</small></p>`,
      ].filter(Boolean).join('\n'),
    });
  },

  async sendTest(config) {
    await this.send(config, {
      entityName: 'Test Monitor',
      oldStatus: 'up',
      newStatus: 'down',
      message: 'Test from ObliWAN',
      timestamp: new Date().toISOString(),
    });
  },
};
