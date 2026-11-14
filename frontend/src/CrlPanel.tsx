import { useEffect, useRef, useState } from 'react';
import { ApiError, apiGet, apiPost } from './api';
import { Icon, Notice, StatusBadge, Tag, toast, type NoticeTone } from './ui';
import { CopyJsonButton, DetailDrawer, DrawerSection, Fact } from './DetailDrawer';
import { crlElapsed, crlState } from './crl-validity';
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
  /** The API's renewal task publishes this CA's CRL when due (migration 0035). */
  auto_renewal?: boolean;
  /** A CRL is published as soon as a revocation is recorded (migration 0040). */
  publish_on_revocation?: boolean;
  /** Revocations and voided serials not yet on the latest published CRL. */
  unpublished_entries?: number;
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
  const [detailNumber, setDetailNumber] = useState<number | null>(null);
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
      <div className="ui-stat"><span>Next update</span><strong className="ui-stat-text">{displayDate(status?.next_update ?? null)}</strong><small>{status?.auto_renewal ? 'Renewed automatically when due' : 'Renew before this date'}</small></div>
    </div>
    {status && (status.unpublished_entries ?? 0) > 0 && <Notice tone={status.publish_on_revocation && status.auto_renewal ? 'info' : 'warning'}>
      {status.unpublished_entries === 1 ? '1 revocation is' : `${status.unpublished_entries} revocations are`} not yet on the published CRL.
      {status.publish_on_revocation && status.auto_renewal ? ' The platform is publishing a new CRL now.' : ' Relying parties will see it after the next CRL is published.'}</Notice>}
    {status?.expired && <Notice tone="error">The latest CRL expired: relying parties may reject this authority’s certificates until a new CRL is published.</Notice>}
    {status && !status.expired && status.renewal_due && <Notice tone={status.auto_renewal ? 'info' : 'warning'}>{status.latest_crl_number === null ? 'No CRL has been published for this authority yet.' : `CRL ${status.latest_crl_number} must be renewed before ${displayDate(status.next_update)}.`}{status.auto_renewal ? ' The platform renews it automatically at its next renewal pass.' : ''}</Notice>}
    {status && <p className="ui-hint">{status.auto_renewal
      ? <><Icon name="refresh" size={14} /> Automatic renewal is on: the platform publishes a new CRL when the current one is within two days of its next update. Officers can still publish at any time.</>
      : 'Automatic renewal is off for this authority: a registration officer must publish before the next update.'}
      {status.publish_on_revocation !== undefined && <> {status.publish_on_revocation
        ? (status.auto_renewal ? 'A new CRL is also published as soon as a revocation is recorded.' : 'Publication on revocation is on, but needs automatic renewal to take effect.')
        : 'Revocations wait for the next scheduled or manual publication.'}</>}</p>}
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
          <td><button type="button" className="link-button" aria-label={`CRL ${row.crl_number} details`} onClick={() => setDetailNumber(row.crl_number)}><strong>{row.crl_number}</strong></button></td><td>{row.entry_count}</td><td className="ui-nowrap">{displayDate(row.this_update)}<div className="ui-sub">until {displayDate(row.next_update)}</div></td>
          <td className="mono" title={row.crl_sha256}>{row.crl_sha256.slice(0, 10)}…</td>
          <td className="ui-col-actions"><button type="button" className="ui-button ui-button-ghost ui-button-sm" onClick={() => setDetailNumber(row.crl_number)}><Icon name="info" size={15} />Details</button><button type="button" className="ui-button ui-button-ghost ui-button-sm" aria-label={`Download CRL ${row.crl_number} (DER)`} onClick={() => void download(row.crl_number)}><Icon name="download" size={15} />DER</button></td>
        </tr>)}</tbody>
      </table></div>}
    </div>
    {crls && detailNumber !== null && (() => {
      const index = crls.findIndex(row => row.crl_number === detailNumber);
      if (index < 0) return null;
      const row = crls[index];
      return <CrlDrawer key={row.crl_number} crl={row} latestNumber={status?.latest_crl_number ?? null} distributionPoint={status?.distribution_point ?? null}
        onDownload={() => void download(row.crl_number)} onClose={() => setDetailNumber(null)}
        onPrevious={index > 0 ? () => setDetailNumber(crls[index - 1].crl_number) : null}
        onNext={index < crls.length - 1 ? () => setDetailNumber(crls[index + 1].crl_number) : null}
        position={`${index + 1} of ${crls.length}`} />;
    })()}
  </section>;
}

/** Slide-over detail of one published CRL, from the metadata the API returned. */
function CrlDrawer({ crl, latestNumber, distributionPoint, onDownload, onClose, onPrevious, onNext, position }: {
  crl: PublishedCrl; latestNumber: number | null; distributionPoint: string | null; onDownload: () => void; onClose: () => void;
  onPrevious: (() => void) | null; onNext: (() => void) | null; position: string;
}) {
  const now = Date.now();
  const state = crlState(crl.crl_number, latestNumber, crl.next_update, now);
  const elapsed = crlElapsed(crl.this_update, crl.next_update, now);
  const tone = state === 'CURRENT' ? 'good' : state === 'EXPIRED' ? 'bad' : 'neutral';
  const hoursLeft = Math.round((Date.parse(crl.next_update) - now) / 3_600_000);
  const remaining = state === 'SUPERSEDED' ? `Replaced by CRL ${latestNumber}` : hoursLeft <= 0 ? 'Next update passed'
    : hoursLeft < 48 ? `${hoursLeft} hour${hoursLeft === 1 ? '' : 's'} left` : `${Math.round(hoursLeft / 24)} days left`;
  return <DetailDrawer label="CRL detail" eyebrow="Certificate revocation list" icon="revocation" tone={tone} closeLabel="Close CRL detail" onClose={onClose}
    onPrevious={onPrevious} onNext={onNext} position={position}
    title={`CRL ${crl.crl_number}`}
    subtitle={`${crl.entry_count} revoked ${crl.entry_count === 1 ? 'certificate' : 'certificates'} · published ${displayDate(crl.published_at)}`}
    badges={<StatusBadge status={state} />}
    actions={<><button type="button" className="ui-button ui-button-secondary ui-button-sm" onClick={onDownload}><Icon name="download" size={15} />Download DER</button><CopyJsonButton json={JSON.stringify(crl, null, 2)} /></>}
    summary={elapsed === null ? undefined : <div className="ui-validity">
      <div className="ui-validity-head"><span className="ui-summary-label">Validity window</span><Tag tone={tone}>{remaining}</Tag></div>
      <div className={`ui-validity-bar ui-tone-${tone}`}><span style={{ width: `${Math.max(1.5, elapsed * 100)}%` }} /><i style={{ left: `${elapsed * 100}%` }} title="Now" /></div>
      <div className="ui-validity-dates"><div><small>This update</small><strong>{displayDate(crl.this_update)}</strong></div><div><small>Next update</small><strong>{displayDate(crl.next_update)}</strong></div></div>
    </div>}
    note="Metadata recorded when the CRL was signed and checked. Relying parties verify the CRL itself against the issuing authority's certificate.">
    <DrawerSection title="Content">
      <Fact label="CRL number">{crl.crl_number}</Fact>
      <Fact label="Entries">{crl.entry_count}</Fact>
      <Fact label="State">{state === 'CURRENT' ? 'Latest CRL, before its next update' : state === 'EXPIRED' ? 'Latest CRL, past its next update' : `Superseded by CRL ${latestNumber}`}</Fact>
    </DrawerSection>
    <DrawerSection title="Integrity and publication">
      <Fact label="SHA-256" copy={crl.crl_sha256} mono>{crl.crl_sha256.match(/.{1,8}/gu)?.join(' ') ?? crl.crl_sha256}</Fact>
      <Fact label="Published">{displayDate(crl.published_at)}</Fact>
      <Fact label="Distribution point" {...(distributionPoint ? { copy: distributionPoint } : {})} mono={Boolean(distributionPoint)}>{distributionPoint ?? 'Not configured by the database owner'}</Fact>
    </DrawerSection>
  </DetailDrawer>;
}
