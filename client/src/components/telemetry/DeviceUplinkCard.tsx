import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Antenna, ArrowLeftRight, ShieldAlert } from 'lucide-react';
import apiClient from '@/api/client';
import type { ApiResponse } from '@obliwan/shared';
import { cn } from '@/utils/cn';

/**
 * Which WAN this site is actually on.
 *
 * Two answers, never merged: what the routing SAYS should carry traffic, and
 * what the counters show IS carrying it. When they agree there is nothing to
 * read. When they disagree the site has failed over to its SIM and the
 * configuration still believes otherwise — which is the whole reason this card
 * exists, and the reason a single "status" badge would have been useless.
 */

interface Candidate {
  ifName: string; alias: string | null; kind: string; operStatus: number;
  inBps: number | null; outBps: number | null; samples: number; carrying: boolean | null;
}
interface Asn { asn: number; name: string | null; prefix: string | null; countryCode: string | null }
interface Verdict {
  configured: string | null; observed: string | null; onBackup: boolean | null;
  reason: string; candidates: Candidate[]; windowMinutes: number;
  publicIp: string | null; asn: Asn | null; asnLookupEnabled: boolean;
}

function bps(v: number | null): string {
  if (v === null) return '—';
  if (v < 1000) return `${v} b/s`;
  if (v < 1e6) return `${(v / 1000).toFixed(1)} kb/s`;
  if (v < 1e9) return `${(v / 1e6).toFixed(1)} Mb/s`;
  return `${(v / 1e9).toFixed(2)} Gb/s`;
}

export function DeviceUplinkCard({ deviceId }: { deviceId: number }) {
  const { t } = useTranslation();
  const [v, setV] = useState<Verdict | null>(null);

  useEffect(() => {
    let alive = true;
    apiClient
      .get<ApiResponse<Verdict>>(`/devices/${deviceId}/uplink`)
      .then((r) => { if (alive) setV(r.data.data ?? null); })
      .catch(() => { if (alive) setV(null); });
    return () => { alive = false; };
  }, [deviceId]);

  if (!v) return null;

  return (
    <div className="rounded-lg border border-border bg-bg-secondary p-4">
      <h3 className="mb-2 flex items-center gap-2 text-sm font-semibold text-text-primary">
        <Antenna size={15} /> {t('uplink.title')}
      </h3>

      <div className="mb-3 flex items-start gap-2">
        {v.onBackup
          ? <ShieldAlert size={16} className="mt-0.5 shrink-0 text-status-warn" />
          : <ArrowLeftRight size={16} className="mt-0.5 shrink-0 text-text-muted" />}
        <p className={cn('text-sm', v.onBackup ? 'text-status-warn' : 'text-text-secondary')}>
          {v.reason}
        </p>
      </div>

      <dl className="mb-3 grid grid-cols-2 gap-4">
        <div>
          <dt className="text-[11px] uppercase tracking-wider text-text-muted">
            {t('uplink.configured')}
          </dt>
          <dd className="mt-0.5 font-mono text-[13px] text-text-primary">
            {v.configured ?? <span className="text-text-muted">—</span>}
          </dd>
        </div>
        <div>
          <dt className="text-[11px] uppercase tracking-wider text-text-muted">
            {t('uplink.observed')}
          </dt>
          <dd className="mt-0.5 font-mono text-[13px] text-text-primary">
            {v.observed ?? <span className="text-text-muted">—</span>}
          </dd>
        </div>
        {/* The outside view: the address the CONCENTRATOR saw this site dial in
            from, and who announces it. Independent of anything the router says
            about itself, which is why it is worth its own line. */}
        {v.publicIp && (
          <div className="col-span-2">
            <dt className="text-[11px] uppercase tracking-wider text-text-muted">
              {t('uplink.egress')}
            </dt>
            <dd className="mt-0.5 font-mono text-[13px] text-text-primary">
              {v.publicIp}
              {v.asn && (
                <span className="ml-2 text-text-secondary">
                  AS{v.asn.asn}{v.asn.name ? ` · ${v.asn.name}` : ''}
                </span>
              )}
              {!v.asn && !v.asnLookupEnabled && (
                <span className="ml-2 font-sans text-[11px] text-text-muted">
                  {t('uplink.asnDisabled')}
                </span>
              )}
            </dd>
          </div>
        )}
      </dl>

      <ul className="space-y-1">
        {v.candidates.map((c) => (
          <li key={c.ifName} className="flex flex-wrap items-baseline gap-2 text-xs">
            <span className={cn(
              'font-mono',
              c.carrying ? 'text-text-primary' : 'text-text-muted',
            )}>
              {c.ifName}
            </span>
            <span className="rounded-full border border-border px-1.5 text-[10px] text-text-muted">
              {c.kind}
            </span>
            {c.alias && <span className="text-[11px] text-text-muted">{c.alias}</span>}
            {/* `null` is not zero: a rate needs two samples, and saying "0 b/s"
                about a link nobody has measured twice is a false negative. */}
            <span className="ml-auto font-mono text-[11px] text-text-secondary">
              {c.samples < 2
                ? t('uplink.awaitingSecondSample')
                : `↓ ${bps(c.inBps)} · ↑ ${bps(c.outBps)}`}
            </span>
          </li>
        ))}
      </ul>

      <p className="mt-2 text-[11px] text-text-muted">
        {t('uplink.window', { minutes: v.windowMinutes })}
      </p>
    </div>
  );
}
