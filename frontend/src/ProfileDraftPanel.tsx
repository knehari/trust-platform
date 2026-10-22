import { useEffect, useRef, useState } from 'react';
import { ApiError, apiGet, apiGetPage, type ProfileDraft } from './api';
import { appendUniquePage, requireAdvancingCursor } from './pagination';
import { requireScopedRows } from './scope';
import { ProfileDraftDialog } from './ProfileDraftDialog';
import { ProfileCompareDialog } from './ProfileCompareDialog';
import type { DetailLink } from './navigation';
import { canonicalProfileRevision } from './profile-revision';

interface Props {
  caId: string;
  token: string;
  onUnauthorized: () => void;
  linkedDetail: Extract<DetailLink, { kind: 'profile' }> | null;
  onOpenDetail: (detail: Extract<DetailLink, { kind: 'profile' }>) => void;
  onCloseDetail: () => void;
}

export function ProfileDraftPanel({ caId, token, onUnauthorized, linkedDetail, onOpenDetail, onCloseDetail }: Props) {
  const [items, setItems] = useState<ProfileDraft[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [moreLoading, setMoreLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [retry, setRetry] = useState(0);
  const [lookupProfileId, setLookupProfileId] = useState('');
  const [lookupRevision, setLookupRevision] = useState('');
  const [lookupError, setLookupError] = useState<string | null>(null);
  const [selected, setSelected] = useState<ProfileDraft | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [comparisonIds, setComparisonIds] = useState<string[]>([]);
  const [showComparison, setShowComparison] = useState(false);
  const detailController = useRef<AbortController | null>(null);
  const moreController = useRef<AbortController | null>(null);
  const onUnauthorizedRef = useRef(onUnauthorized);
  onUnauthorizedRef.current = onUnauthorized;
  const onCloseDetailRef = useRef(onCloseDetail);
  onCloseDetailRef.current = onCloseDetail;

  useEffect(() => {
    setItems([]);
    setCursor(null);
    setLoading(true);
    setError(null);
    setLookupError(null);
    setLookupProfileId('');
    setLookupRevision('');
    setSelected(null);
    setDetailError(null);
    setComparisonIds([]);
    setShowComparison(false);
    detailController.current?.abort();
    moreController.current?.abort();
    const controller = new AbortController();
    void apiGetPage<ProfileDraft>(`/v1/cas/${encodeURIComponent(caId)}/profile-drafts`, token, controller.signal)
      .then(page => {
        if (controller.signal.aborted) return;
        setItems(requireScopedRows(page.items, caId));
        setCursor(page.nextCursor);
      })
      .catch(error => {
        if (controller.signal.aborted) return;
        if (error instanceof ApiError && error.status === 401) onUnauthorizedRef.current();
        else setError(error instanceof Error ? error.message : 'Could not load profile drafts.');
      })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => { controller.abort(); moreController.current?.abort(); detailController.current?.abort(); };
  }, [caId, token, retry]);

  useEffect(() => {
    if (!linkedDetail) {
      detailController.current?.abort();
      setDetailLoading(false);
      setSelected(null);
      return;
    }
    detailController.current?.abort();
    const controller = new AbortController();
    detailController.current = controller;
    setSelected(null);
    setDetailError(null);
    setDetailLoading(true);
    void apiGet<ProfileDraft>(`/v1/cas/${encodeURIComponent(caId)}/profile-drafts/${encodeURIComponent(linkedDetail.id)}/${linkedDetail.revision}`, token, controller.signal)
      .then(detail => {
        if (controller.signal.aborted) return;
        if (detail.ca_id !== caId || detail.profile_id !== linkedDetail.id || detail.revision !== linkedDetail.revision || detail.status !== 'DRAFT') {
          throw new Error('The profile proposal detail did not match the linked revision.');
        }
        setSelected(detail);
      })
      .catch(error => {
        if (controller.signal.aborted) return;
        if (error instanceof ApiError && error.status === 401) onUnauthorizedRef.current();
        else {
          setDetailError(error instanceof ApiError && error.status === 404
            ? 'No proposal with that profile ID and revision was found for this authority.'
            : error instanceof Error ? error.message : 'Could not load profile proposal detail.');
          onCloseDetailRef.current();
        }
      })
      .finally(() => { if (!controller.signal.aborted) setDetailLoading(false); });
    return () => controller.abort();
  }, [caId, token, linkedDetail?.id, linkedDetail?.revision]);

  function openDetail(item: ProfileDraft) {
    onOpenDetail({ kind: 'profile', id: item.profile_id, revision: item.revision });
  }

  function findRevision() {
    const target = canonicalProfileRevision(lookupProfileId.trim(), lookupRevision.trim());
    if (!target) {
      setLookupError('Enter a lowercase profile ID (2–64 letters, digits or hyphens) and a revision from 1 to 1000000.');
      return;
    }
    setLookupError(null);
    setDetailError(null);
    onOpenDetail({ kind: 'profile', ...target });
  }

  async function loadMore() {
    if (!cursor || moreLoading) return;
    const controller = new AbortController();
    moreController.current = controller;
    setMoreLoading(true);
    setError(null);
    try {
      const page = await apiGetPage<ProfileDraft>(`/v1/cas/${encodeURIComponent(caId)}/profile-drafts?after=${encodeURIComponent(cursor)}`, token, controller.signal);
      if (controller.signal.aborted) return;
      const rows = requireScopedRows(page.items, caId);
      setItems(current => appendUniquePage(current, rows, row => `${row.profile_id}/${row.revision}`));
      setCursor(requireAdvancingCursor(cursor, page.nextCursor));
    } catch (error) {
      if (controller.signal.aborted) return;
      if (error instanceof ApiError && error.status === 401) onUnauthorizedRef.current();
      else setError(error instanceof Error ? error.message : 'Could not load more profile drafts.');
    } finally {
      if (!controller.signal.aborted) setMoreLoading(false);
    }
  }

  function toggleComparison(item: ProfileDraft) {
    const id = `${item.profile_id}/${item.revision}`;
    setShowComparison(false);
    setComparisonIds(current => {
      if (current.includes(id)) return current.filter(value => value !== id);
      if (current.length && current[0].split('/')[0] !== item.profile_id) return [id];
      return [...current.slice(-1), id];
    });
  }

  const compared = comparisonIds.map(id => items.find(item => `${item.profile_id}/${item.revision}` === id)).filter((item): item is ProfileDraft => Boolean(item));

  return <div className="detail-content">
    <div className="table-heading"><h3>Profile proposals</h3><span>{items.length}{cursor ? '+' : ''} revisions loaded</span></div>
    <div className="subtle-panel profile-draft-notice"><b>Drafts only</b><p>These proposals are not approved or active. They cannot authorize certificate issuance. CA creation, approvals and signing remain unavailable in this console.</p></div>
    <form className="exact-lookup profile-draft-lookup" onSubmit={event => { event.preventDefault(); findRevision(); }}><label htmlFor="profile-draft-id-lookup">Find a proposal by exact profile ID and revision across this authority’s history</label><div><input id="profile-draft-id-lookup" type="search" value={lookupProfileId} onChange={event => { setLookupProfileId(event.target.value); setLookupError(null); }} placeholder="Profile ID" aria-describedby={lookupError ? 'profile-draft-lookup-error' : undefined} /><input type="text" inputMode="numeric" aria-label="Profile revision number" value={lookupRevision} onChange={event => { setLookupRevision(event.target.value); setLookupError(null); }} placeholder="Revision" aria-describedby={lookupError ? 'profile-draft-lookup-error' : undefined} /><button type="submit" disabled={detailLoading}>{detailLoading ? 'Finding…' : 'Find revision'}</button></div></form>
    {lookupError && <p id="profile-draft-lookup-error" className="lookup-error" role="alert">{lookupError}</p>}
    {loading ? <p className="profile-draft-message">Loading scoped profile proposals…</p>
      : error && items.length === 0 ? <p className="profile-draft-message" role="alert">{error} <button className="link-button" onClick={() => setRetry(value => value + 1)}>Retry</button></p>
      : items.length === 0 ? <p className="profile-draft-message">No profile proposals recorded for this authority.</p>
      : <div className="profile-draft-list">{items.map(item => <article className="profile-draft-card" key={`${item.profile_id}/${item.revision}`}>
        <div className="profile-draft-title"><div><h4>{item.display_name}</h4><span className="mono">{item.profile_id} · revision {item.revision}</span></div><span className="row-state">DRAFT</span></div>
        <dl><div><dt>Policy</dt><dd>{item.policy_version}</dd></div><div><dt>Maximum validity</dt><dd>{item.max_validity_days} days</dd></div><div><dt>Maximum DNS SANs</dt><dd>{item.max_dns_sans}</dd></div><div><dt>Proposed DNS zones</dt><dd>{item.proposed_dns_zones.join(', ')}</dd></div><div><dt>Proposed signature suites</dt><dd>{item.proposed_signature_suites.join(', ')}</dd></div><div><dt>Recorded</dt><dd>{new Date(item.created_at).toLocaleString()}</dd></div></dl>
        <div className="profile-draft-actions"><button type="button" className="link-button profile-draft-action" disabled={detailLoading} onClick={() => void openDetail(item)}>View proposal detail</button><button type="button" className="link-button profile-draft-action" aria-pressed={comparisonIds.includes(`${item.profile_id}/${item.revision}`)} onClick={() => toggleComparison(item)}>{comparisonIds.includes(`${item.profile_id}/${item.revision}`) ? 'Remove from comparison' : 'Select for comparison'}</button></div>
      </article>)}</div>}
    {comparisonIds.length > 0 && <div className="subtle-panel profile-compare-controls"><span>{comparisonIds.length}/2 revisions selected. Select two revisions of the same profile from loaded rows.</span>{compared.length === 2 && <button type="button" className="link-button" onClick={() => setShowComparison(true)}>Compare selected revisions</button>}</div>}
    {error && items.length > 0 && <p className="profile-draft-message" role="alert">{error}</p>}
    {detailLoading && <p className="profile-draft-message" role="status">Loading proposal detail…</p>}
    {detailError && <p className="profile-draft-message" role="alert">{detailError}</p>}
    {cursor && <button className="link-button pagination-action" disabled={moreLoading} onClick={() => void loadMore()}>{moreLoading ? 'Loading…' : 'Load more proposals'}</button>}
    {selected && linkedDetail?.id === selected.profile_id && linkedDetail.revision === selected.revision && <ProfileDraftDialog draft={selected} onClose={() => { setSelected(null); onCloseDetail(); }} />}
    {showComparison && compared.length === 2 && <ProfileCompareDialog first={compared[0]} second={compared[1]} onClose={() => setShowComparison(false)} />}
  </div>;
}
