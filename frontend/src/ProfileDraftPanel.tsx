import { useEffect, useRef, useState } from 'react';
import { ApiError, apiGetPage, type ProfileDraft } from './api';
import { appendUniquePage, requireAdvancingCursor } from './pagination';
import { requireScopedRows } from './scope';

interface Props {
  caId: string;
  token: string;
  onUnauthorized: () => void;
}

export function ProfileDraftPanel({ caId, token, onUnauthorized }: Props) {
  const [items, setItems] = useState<ProfileDraft[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [moreLoading, setMoreLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [retry, setRetry] = useState(0);
  const moreController = useRef<AbortController | null>(null);
  const onUnauthorizedRef = useRef(onUnauthorized);
  onUnauthorizedRef.current = onUnauthorized;

  useEffect(() => {
    setItems([]);
    setCursor(null);
    setLoading(true);
    setError(null);
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
    return () => { controller.abort(); moreController.current?.abort(); };
  }, [caId, token, retry]);

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

  return <div className="detail-content">
    <div className="table-heading"><h3>Profile proposals</h3><span>{items.length}{cursor ? '+' : ''} revisions loaded</span></div>
    <div className="subtle-panel profile-draft-notice"><b>Drafts only</b><p>These proposals are not approved or active. They cannot authorize certificate issuance. CA creation, approvals and signing remain unavailable in this console.</p></div>
    {loading ? <p className="profile-draft-message">Loading scoped profile proposals…</p>
      : error && items.length === 0 ? <p className="profile-draft-message" role="alert">{error} <button className="link-button" onClick={() => setRetry(value => value + 1)}>Retry</button></p>
      : items.length === 0 ? <p className="profile-draft-message">No profile proposals recorded for this authority.</p>
      : <div className="profile-draft-list">{items.map(item => <article className="profile-draft-card" key={`${item.profile_id}/${item.revision}`}>
        <div className="profile-draft-title"><div><h4>{item.display_name}</h4><span className="mono">{item.profile_id} · revision {item.revision}</span></div><span className="row-state">DRAFT</span></div>
        <dl><div><dt>Policy</dt><dd>{item.policy_version}</dd></div><div><dt>Maximum validity</dt><dd>{item.max_validity_days} days</dd></div><div><dt>Maximum DNS SANs</dt><dd>{item.max_dns_sans}</dd></div><div><dt>Proposed DNS zones</dt><dd>{item.proposed_dns_zones.join(', ')}</dd></div><div><dt>Proposed signature suites</dt><dd>{item.proposed_signature_suites.join(', ')}</dd></div><div><dt>Recorded</dt><dd>{new Date(item.created_at).toLocaleString()}</dd></div></dl>
      </article>)}</div>}
    {error && items.length > 0 && <p className="profile-draft-message" role="alert">{error}</p>}
    {cursor && <button className="link-button pagination-action" disabled={moreLoading} onClick={() => void loadMore()}>{moreLoading ? 'Loading…' : 'Load more proposals'}</button>}
  </div>;
}
