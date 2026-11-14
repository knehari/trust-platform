import { useEffect, useState } from 'react';
import { ApiError, apiGet } from './api';
import { Icon, Notice, StatusBadge, Tag } from './ui';
import { activeKeys, quotaUse, rotating, shortFingerprint, type RaSystem, type ShortLivedProfile } from './ra-policy';

function displayDate(value: string | null): string {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? value : date.toLocaleString();
}

function QuotaMeter({ used, max, label }: { used: number; max: number; label: string }) {
  const use = quotaUse(used, max);
  return <div className="ra-quota">
    <div className="ra-quota-head"><span>{label}</span><strong>{use.label}</strong></div>
    <div className={`ui-life ${use.tone === 'bad' ? 'ended' : use.tone === 'warn' ? 'late' : ''}`} role="meter"
      aria-label={`${label}: ${use.label} in the last hour`} aria-valuemin={0} aria-valuemax={Math.max(max, 0)} aria-valuenow={used}>
      <span style={{ width: `${Math.round(use.share * 100)}%` }} />
    </div>
  </div>;
}

/**
 * The RA channel of one authority, read-only (ADR-0044): the registered RA
 * systems granted its profiles, their hourly quotas and use (ADR-0039),
 * DNS zones and keys (ADR-0040), and the authority's short-lived profiles
 * (ADR-0042). The database owner sets all of it.
 */
export function RaPolicyPanel({ caId, token, onUnauthorized }: { caId: string; token: string; onUnauthorized: () => void }) {
  const [systems, setSystems] = useState<RaSystem[] | null>(null);
  const [shortLived, setShortLived] = useState<ShortLivedProfile[] | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [reload, setReload] = useState(0);
  const base = `/v1/cas/${encodeURIComponent(caId)}`;

  useEffect(() => {
    const controller = new AbortController();
    const fail = (failure: unknown) => {
      if (controller.signal.aborted) return;
      if (failure instanceof ApiError && failure.status === 401) onUnauthorized();
      else setLoadError(failure instanceof Error ? failure.message : 'Could not load the RA channel.');
    };
    apiGet<RaSystem[]>(`${base}/ra-systems`, token, controller.signal).then(setSystems).catch(fail);
    apiGet<ShortLivedProfile[]>(`${base}/short-lived-profiles`, token, controller.signal).then(setShortLived).catch(fail);
    return () => controller.abort();
  }, [base, token, reload]);

  return <section className="ui-stack" aria-labelledby="ra-title">
    <div className="ui-section-header">
      <div><h2 id="ra-title" className="sr-only">RA channel &amp; policies</h2>
        <p>Registered RA systems obtain and revoke certificates with requests they sign. Their quotas, zones and keys, and the short-lived profiles, are set by the database owner and enforced by the platform on every request.</p></div>
      <button type="button" className="ui-button ui-button-secondary ui-button-sm" onClick={() => setReload(value => value + 1)}><Icon name="refresh" size={15} />Refresh</button>
    </div>
    {loadError && <Notice tone="error" action={<button type="button" className="ui-button ui-button-secondary ui-button-sm" onClick={() => { setLoadError(null); setReload(value => value + 1); }}>Retry</button>}>{loadError}</Notice>}

    <div className="ui-card">
      <div className="ui-card-header"><div><h3>RA systems</h3><p>Granted at least one profile of this authority. Use is counted over the last hour.</p></div></div>
      {!systems && !loadError && <p className="ui-empty">Loading RA systems…</p>}
      {systems && systems.length === 0 && <p className="ui-empty">No RA system is granted a profile of this authority.</p>}
      {systems && systems.length > 0 && <div className="ui-table-wrap"><table className="ui-table" aria-label="RA systems">
        <thead><tr><th>RA system</th><th>Profiles</th><th>Hourly quotas</th><th>DNS zones</th><th>Keys</th></tr></thead>
        <tbody>{systems.map(system => {
          const active = activeKeys(system.keys);
          return <tr key={system.ra_id}>
            <td><strong>{system.display_name}</strong><div className="ui-sub mono">{system.ra_id}</div>
              <div className="ui-spaced-sm"><StatusBadge status={system.enabled ? 'ENABLED' : 'DISABLED'} /></div></td>
            <td>{system.profile_ids.map(profile => <Tag key={profile}>{profile}</Tag>)}</td>
            <td className="ra-quotas">
              <QuotaMeter label="Issuance" used={system.issuance_last_hour} max={system.max_issuance_per_hour} />
              <QuotaMeter label="Revocation" used={system.revocation_last_hour} max={system.max_revocation_per_hour} />
            </td>
            <td>{system.allowed_dns_zones
              ? system.allowed_dns_zones.map(zone => <Tag key={zone} tone="info">{zone}</Tag>)
              : <span className="ui-hint">The profiles’ zones</span>}</td>
            <td>
              {active.length === 0 && <Tag tone="bad">No usable key</Tag>}
              {rotating(system.keys) && <Tag tone="warn" title="Two unretired keys: the RA is switching keys">Rotation in progress</Tag>}
              <ul className="ra-keys">{system.keys.map(key => <li key={key.key_id} className={key.retired_at ? 'retired' : ''}>
                <span className="mono" title={key.sha256}>#{key.key_id} {shortFingerprint(key.sha256)}</span>
                <span className="ui-sub">{key.retired_at ? `Retired ${displayDate(key.retired_at)}` : `Active since ${displayDate(key.activated_at)}`}</span>
              </li>)}</ul>
            </td>
          </tr>;
        })}</tbody>
      </table></div>}
    </div>

    <div className="ui-card">
      <div className="ui-card-header"><div><h3>Short-lived profiles</h3><p>Certificates say no revocation information is available (noRevAvail), name no CRL and cannot be revoked; their validity is the control.</p></div></div>
      {!shortLived && !loadError && <p className="ui-empty">Loading…</p>}
      {shortLived && shortLived.length === 0 && <p className="ui-empty">No profile of this authority is short-lived: every certificate can be revoked and names the CRL.</p>}
      {shortLived && shortLived.length > 0 && <div className="ui-table-wrap"><table className="ui-table" aria-label="Short-lived profiles">
        <thead><tr><th>Profile</th><th>Longest validity</th><th>Set</th></tr></thead>
        <tbody>{shortLived.map(row => <tr key={row.profile_id}>
          <td><strong>{row.profile_id}</strong></td><td>{row.max_validity_days === 1 ? '1 day' : `${row.max_validity_days} days`}</td><td className="ui-nowrap">{displayDate(row.updated_at)}</td>
        </tr>)}</tbody>
      </table></div>}
    </div>
    <p className="ui-hint">Read-only. To change a quota, a zone, a key or a short-lived profile, the database owner follows “RA issuance channel” and “Short-lived certificates” in docs/development/lab-compose.md.</p>
  </section>;
}
