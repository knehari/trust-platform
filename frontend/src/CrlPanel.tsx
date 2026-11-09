import { useEffect, useRef, useState } from 'react';
import { ApiError, apiGet, apiPost } from './api';
import { Icon, Notice, StatusBadge, toast, type NoticeTone } from './ui';
import { PemBlock, writeError, type Application } from './RequestsPanel';

interface PublishedCrl {
  crl_number: number;
  this_update: string;
  next_update: string;
  crl_sha256: string;
  published_at: string;
  entry_count: number;
}

interface CrlStatus {
  distribution_point: string | null;
  latest_crl_number: number | null;
  next_update: string | null;
  renewal_due: boolean;
  expired: boolean;
}

interface CrlPublication {
  status: 'PUBLISHED' | 'RECONCILIATION_REQUIRED';
  crl_number: number;
  crl_pem: string | null;
}

function displayDate(value: string | null): string {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? value : date.toLocaleString();
}

/**
 * Revocation and CRL publication of one authority (ADR-0018, ADR-0019):
 * where the CRL is published, whether it must be renewed, the published
 * CRLs, and, for registration officers, publishing the next one.
 */
export function CrlPanel({ caId, token, canPublish, onUnauthorized, onOpenRequests }: {
  caId: string; token: string; canPublish: boolean; onUnauthorized: () => void; onOpenRequests: () => void;
}) {
  const [crls, setCrls] = useState<PublishedCrl[] | null>(null);
  const [status, setStatus] = useState<CrlStatus | null>(null);
  const [pending, setPending] = useState<number | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [notice, setNotice] = useState<{ tone: NoticeTone; text: string } | null>(null);
  const [published, setPublished] = useState<{ number: number; pem: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [reload, setReload] = useState(0);
  const key = useRef(crypto.randomUUID());
  const base = `/v1/cas/${encodeURIComponent(caId)}`;

  useEffect(() => {
    const controller = new AbortController();
    const fail = (failure: unknown) => {
      if (controller.signal.aborted) return;
      if (failure instanceof ApiError && failure.status === 401) onUnauthorized();
      else setLoadError(failure instanceof Error ? failure.message : 'Could not load CRLs.');
    };
    apiGet<PublishedCrl[]>(`${base}/crls`, token, controller.signal).then(setCrls).catch(fail);
    apiGet<CrlStatus>(`${base}/crl-status`, token, controller.signal).then(setStatus).catch(fail);
    apiGet<Application[]>(`${base}/certificate-applications`, token, controller.signal)
      .then(rows => setPending(rows.filter(row => row.status === 'REVOCATION_REQUESTED').length))
      .catch(() => setPending(null));
    return () => controller.abort();
  }, [base, token, reload]);

  async function publish() {
    setBusy(true);
    try {
      const result = await apiPost<CrlPublication>(`${base}/crls`, token, {}, key.current);
      if (result.value.crl_pem) setPublished({ number: result.value.crl_number, pem: result.value.crl_pem });
      setNotice(null);
      toast(`CRL ${result.value.crl_number} published and verified.`);
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) onUnauthorized();
      else setNotice({ tone: 'error', text: writeError(failure, 'publish the CRL') });
    } finally {
      key.current = crypto.randomUUID();
      setBusy(false);
      setReload(value => value + 1);
    }
  }

  async function download(number: number) {
    try {
      const response = await fetch(`${base}/crls/${number}`, { headers: { Authorization: `Bearer ${token}` }, credentials: 'omit', cache: 'no-store' });
      if (!response.ok) throw new ApiError(response.status, `The request failed (${response.status}).`);
      const url = URL.createObjectURL(await response.blob());
      const link = document.createElement('a');
      link.href = url;
      link.download = `crl-${number}.crl`;
      document.body.append(link);
      link.click();
      link.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 0);
    } catch (failure) {
      setNotice({ tone: 'error', text: writeError(failure, `download CRL ${number}`) });
    }
  }

  const health = !status ? null : status.expired ? 'EXPIRED' : status.latest_crl_number === null ? 'NO_CRL' : status.renewal_due ? 'RENEWAL_DUE' : 'CURRENT';

  return <section className="ui-stack" aria-labelledby="crl-title">
    <div className="ui-section-header">
      <div><h2 id="crl-title" className="sr-only">Revocation &amp; CRLs</h2>
        <p>Approved revocations appear on the next CRL. CRLs are signed once by the laboratory signer and checked before they are stored.</p></div>
      {canPublish && <button type="button" className="ui-button ui-button-primary" disabled={busy} onClick={() => void publish()}><Icon name="publish" size={16} />{busy ? 'Publishing…' : 'Publish CRL'}</button>}
    </div>
    {notice && <Notice tone={notice.tone} onDismiss={() => setNotice(null)}>{notice.text}</Notice>}
    {loadError && <Notice tone="error" action={<button type="button" className="ui-button ui-button-secondary ui-button-sm" onClick={() => { setLoadError(null); setReload(value => value + 1); }}>Retry</button>}>{loadError}</Notice>}
    {pending !== null && pending > 0 && <Notice tone="warning" action={<button type="button" className="ui-button ui-button-secondary ui-button-sm" onClick={onOpenRequests}>Review requests</button>}>
      {pending === 1 ? '1 revocation request awaits' : `${pending} revocation requests await`} a registration officer’s decision.</Notice>}

    <div className="ui-stat-grid">
      <div className="ui-stat"><span>Status</span><strong>{health ? <StatusBadge status={health} /> : '—'}</strong><small>{health === 'CURRENT' ? 'Relying parties can check revocation' : health ? 'Publish a CRL to restore checking' : 'Loading…'}</small></div>
      <div className="ui-stat"><span>Latest CRL</span><strong>{status?.latest_crl_number ?? '—'}</strong><small>{crls ? `${crls.length} published` : '—'}</small></div>
      <div className="ui-stat"><span>Next update</span><strong className="ui-stat-text">{displayDate(status?.next_update ?? null)}</strong><small>Renew before this date</small></div>
    </div>
    {status?.expired && <Notice tone="error">The latest CRL expired: relying parties may reject this authority’s certificates until a new CRL is published.</Notice>}
    {status && !status.expired && status.renewal_due && <Notice tone="warning">{status.latest_crl_number === null ? 'No CRL has been published for this authority yet.' : `CRL ${status.latest_crl_number} must be renewed before ${displayDate(status.next_update)}.`}</Notice>}
    {status && <div className="ui-card"><div className="ui-kv"><span>Public distribution point</span>{status.distribution_point
      ? <div className="ui-copy-line"><code>{status.distribution_point}</code><button type="button" className="ui-button ui-button-ghost ui-button-sm" onClick={() => void navigator.clipboard.writeText(status.distribution_point!)}><Icon name="copy" size={15} />Copy</button></div>
      : <p className="ui-hint">Not published: the database owner has not configured a distribution point for this authority.</p>}</div></div>}

    {published && <PemBlock title={`CRL ${published.number}`} pem={published.pem} filename={`crl-${published.number}.pem`}
      note="Check it with: openssl crl -in crl.pem -CAfile root.crt -noout -verify, and a certificate with: openssl verify -crl_check -CAfile root.crt -CRLfile crl.pem cert.pem." />}

    <div className="ui-card">
      <div className="ui-card-header"><div><h3>Published CRLs</h3><p>Newest first.</p></div></div>
      {!crls && !loadError && <p className="ui-empty">Loading CRLs…</p>}
      {crls && crls.length === 0 && <p className="ui-empty">No CRL published yet.</p>}
      {crls && crls.length > 0 && <div className="ui-table-wrap"><table className="ui-table" aria-label="Published CRLs">
        <thead><tr><th>CRL</th><th>Entries</th><th>Valid</th><th>SHA-256</th><th className="ui-col-actions"><span className="sr-only">Actions</span></th></tr></thead>
        <tbody>{crls.map(row => <tr key={row.crl_number}>
          <td><strong>{row.crl_number}</strong></td><td>{row.entry_count}</td><td className="ui-nowrap">{displayDate(row.this_update)}<div className="ui-sub">until {displayDate(row.next_update)}</div></td>
          <td className="mono" title={row.crl_sha256}>{row.crl_sha256.slice(0, 10)}…</td>
          <td className="ui-col-actions"><button type="button" className="ui-button ui-button-ghost ui-button-sm" aria-label={`Download CRL ${row.crl_number} (DER)`} onClick={() => void download(row.crl_number)}><Icon name="download" size={15} />DER</button></td>
        </tr>)}</tbody>
      </table></div>}
    </div>
  </section>;
}
