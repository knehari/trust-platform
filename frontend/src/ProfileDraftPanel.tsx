import { useEffect, useRef, useState } from 'react';
import { ApiError, apiGet, apiGetPage, type ProfileDraft } from './api';
import { appendUniquePage, requireAdvancingCursor } from './pagination';
import { requireProfileDraft, requireProfileDraftPage } from './profile-draft-validation';
import { ProfileDraftDialog } from './ProfileDraftDialog';
import { ProfileCompareDialog } from './ProfileCompareDialog';
import { navigationUrl, type DetailLink } from './navigation';
import { canonicalProfileId, canonicalProfileRevision } from './profile-revision';
import { MAX_CSV_ROWS, profileDraftCsv } from './selected-csv';
import { visibleProfileDrafts } from './profile-draft-filter';

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
  const [filterInput, setFilterInput] = useState('');
  const [profileFilter, setProfileFilter] = useState('');
  const [profileOrder, setProfileOrder] = useState<'oldest' | 'newest'>('oldest');
  const [filterError, setFilterError] = useState<string | null>(null);
  const [searchInput, setSearchInput] = useState('');
  const [searchTerm, setSearchTerm] = useState('');
  const [searchError, setSearchError] = useState<string | null>(null);
  const [policyInput, setPolicyInput] = useState('');
  const [policyFilter, setPolicyFilter] = useState('');
  const [policyError, setPolicyError] = useState<string | null>(null);
  const [fromInput, setFromInput] = useState('');
  const [untilInput, setUntilInput] = useState('');
  const [fromFilter, setFromFilter] = useState('');
  const [untilFilter, setUntilFilter] = useState('');
  const [rangeError, setRangeError] = useState<string | null>(null);
  const [validityInput, setValidityInput] = useState('');
  const [minValidity, setMinValidity] = useState<number | null>(null);
  const [validityError, setValidityError] = useState<string | null>(null);
  const [lookupProfileId, setLookupProfileId] = useState('');
  const [lookupRevision, setLookupRevision] = useState('');
  const [lookupError, setLookupError] = useState<string | null>(null);
  const [selected, setSelected] = useState<ProfileDraft | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [comparisonItems, setComparisonItems] = useState<ProfileDraft[]>([]);
  const [showComparison, setShowComparison] = useState(false);
  const [exportSelection, setExportSelection] = useState<string[]>([]);
  const [warningsOnly, setWarningsOnly] = useState(false);
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
    setMoreLoading(false);
    setError(null);
    setComparisonItems([]);
    setShowComparison(false);
    setExportSelection([]);
    moreController.current?.abort();
    const controller = new AbortController();
    const params = new URLSearchParams();
    if (profileFilter) {
      params.set('profile_id', profileFilter);
      params.set('order', profileOrder);
    }
    if (searchTerm) params.set('q', searchTerm);
    if (policyFilter) params.set('policy_version', policyFilter);
    if (fromFilter) params.set('from', fromFilter);
    if (untilFilter) params.set('until', untilFilter);
    if (minValidity !== null) params.set('min_validity_days', String(minValidity));
    const listUrl = `/v1/cas/${encodeURIComponent(caId)}/profile-drafts${params.size ? `?${params}` : ''}`;
    void apiGetPage<unknown>(listUrl, token, controller.signal)
      .then(page => {
        if (controller.signal.aborted) return;
        setItems(requireProfileDraftPage(page.items, caId));
        setCursor(page.nextCursor);
      })
      .catch(error => {
        if (controller.signal.aborted) return;
        if (error instanceof ApiError && error.status === 401) onUnauthorizedRef.current();
        else setError(error instanceof Error ? error.message : 'Could not load profile drafts.');
      })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => { controller.abort(); moreController.current?.abort(); };
  }, [caId, token, retry, profileFilter, profileOrder, searchTerm, policyFilter, fromFilter, untilFilter, minValidity]);

  useEffect(() => {
    if (!linkedDetail) {
      detailController.current?.abort();
      setDetailLoading(false);
      setSelected(null);
      setShowComparison(false);
      return;
    }
    detailController.current?.abort();
    const controller = new AbortController();
    detailController.current = controller;
    setSelected(null);
    setDetailError(null);
    setDetailLoading(true);
    const revisions = linkedDetail.compareRevision ? [linkedDetail.revision, linkedDetail.compareRevision] : [linkedDetail.revision];
    void Promise.all(revisions.map(revision => apiGet<unknown>(`/v1/cas/${encodeURIComponent(caId)}/profile-drafts/${encodeURIComponent(linkedDetail.id)}/${revision}`, token, controller.signal)
      .then(value => requireProfileDraft(value, caId, { id: linkedDetail.id, revision }))))
      .then(details => {
        if (controller.signal.aborted) return;
        if (details.length === 2) {
          setComparisonItems(details);
          setShowComparison(true);
        } else setSelected(details[0]);
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
  }, [caId, token, linkedDetail?.id, linkedDetail?.revision, linkedDetail?.compareRevision]);

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

  function applyProfileFilter() {
    const id = filterInput.trim();
    if (!canonicalProfileId(id)) {
      setFilterError('Enter a lowercase profile ID (2–64 letters, digits or hyphens).');
      return;
    }
    setFilterError(null);
    setProfileFilter(id);
  }

  function applySearch() {
    const value = searchInput.trim();
    if (value.length < 2 || value.length > 255 || [...value].some(char => /[\x00-\x1f\x7f]/u.test(char))) {
      setSearchError('Enter 2–255 printable characters.');
      return;
    }
    setSearchError(null);
    setSearchTerm(value);
  }

  function applyPolicyFilter() {
    const value = policyInput.trim();
    if (!value || value.length > 128 || [...value].some(char => /[\x00-\x1f\x7f]/u.test(char))) {
      setPolicyError('Enter a policy version of 1–128 printable characters.');
      return;
    }
    setPolicyError(null);
    setPolicyFilter(value);
  }

  function applyRecordedRange() {
    if (!fromInput && !untilInput) {
      setRangeError('Choose at least one UTC date.');
      return;
    }
    if (fromInput && untilInput && fromInput >= untilInput) {
      setRangeError('The before date must be later than the from date.');
      return;
    }
    setRangeError(null);
    setFromFilter(fromInput ? `${fromInput}T00:00:00.000Z` : '');
    setUntilFilter(untilInput ? `${untilInput}T00:00:00.000Z` : '');
  }

  function applyValidityFilter() {
    const value = Number(validityInput);
    if (!/^\d{1,3}$/u.test(validityInput) || !Number.isInteger(value) || value < 1 || value > 825) {
      setValidityError('Enter a whole number from 1 to 825 days.');
      return;
    }
    setValidityError(null);
    setMinValidity(value);
  }

  async function loadMore() {
    if (!cursor || moreLoading) return;
    const controller = new AbortController();
    moreController.current = controller;
    setMoreLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams({ after: cursor });
      if (profileFilter) {
        params.set('profile_id', profileFilter);
        params.set('order', profileOrder);
      }
      if (searchTerm) params.set('q', searchTerm);
      if (policyFilter) params.set('policy_version', policyFilter);
      if (fromFilter) params.set('from', fromFilter);
      if (untilFilter) params.set('until', untilFilter);
      if (minValidity !== null) params.set('min_validity_days', String(minValidity));
      const page = await apiGetPage<unknown>(`/v1/cas/${encodeURIComponent(caId)}/profile-drafts?${params}`, token, controller.signal);
      if (controller.signal.aborted) return;
      const rows = requireProfileDraftPage(page.items, caId);
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
    if (item.ca_id !== caId || item.status !== 'DRAFT') return;
    setShowComparison(false);
    setComparisonItems(current => {
      if (current.some(value => value.profile_id === item.profile_id && value.revision === item.revision)) return current.filter(value => value.profile_id !== item.profile_id || value.revision !== item.revision);
      if (current.length && current[0].profile_id !== item.profile_id) return [item];
      return [...current.slice(-1), item];
    });
  }

  const comparisonSelected = (item: ProfileDraft) => comparisonItems.some(value => value.profile_id === item.profile_id && value.revision === item.revision);

  function openComparison() {
    if (comparisonItems.length !== 2) return;
    onOpenDetail({ kind: 'profile', id: comparisonItems[0].profile_id, revision: comparisonItems[0].revision, compareRevision: comparisonItems[1].revision });
  }

  async function copyComparisonLink() {
    if (comparisonItems.length !== 2) return;
    const url = navigationUrl('profiles', caId, { kind: 'profile', id: comparisonItems[0].profile_id, revision: comparisonItems[0].revision, compareRevision: comparisonItems[1].revision });
    await navigator.clipboard.writeText(new URL(url, window.location.origin).href);
  }

  function toggleExport(item: ProfileDraft) {
    const key = `${item.profile_id}/${item.revision}`;
    setExportSelection(current => current.includes(key) ? current.filter(value => value !== key)
      : current.length < MAX_CSV_ROWS ? [...current, key] : current);
  }

  function downloadSelected() {
    const rows = items.filter(item => exportSelection.includes(`${item.profile_id}/${item.revision}`));
    if (rows.length === 0) return;
    const url = URL.createObjectURL(new Blob(['\uFEFF', profileDraftCsv(rows)], { type: 'text/csv;charset=utf-8' }));
    const link = document.createElement('a');
    link.href = url;
    link.download = `trust-profile-proposals-${caId}.csv`;
    document.body.append(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 0);
  }

  const visibleItems = visibleProfileDrafts(items, warningsOnly);

  return <div className="detail-content">
    <div className="table-heading"><h3>Profile proposals</h3><span>{items.length}{cursor ? '+' : ''} revisions loaded</span></div>
    <div className="subtle-panel profile-draft-notice"><b>Drafts only</b><p>These proposals are not approved or active. They cannot authorize certificate issuance. CA creation, approvals and signing remain unavailable in this console.</p></div>
    <div className="subtle-panel profile-compare-controls"><span>{exportSelection.length}/{MAX_CSV_ROWS} loaded proposals selected for metadata CSV export.</span><button type="button" className="link-button" disabled={exportSelection.length === 0} onClick={downloadSelected}>Export selected proposals CSV</button>{exportSelection.length > 0 && <button type="button" className="link-button" onClick={() => setExportSelection([])}>Clear selection</button>}</div>
    <form className="exact-lookup profile-draft-filter" onSubmit={event => { event.preventDefault(); applySearch(); }}><label htmlFor="profile-draft-search">Search profile ID, display name or policy prefix across this authority’s history</label><div><input id="profile-draft-search" type="search" value={searchInput} onChange={event => { setSearchInput(event.target.value); setSearchError(null); }} placeholder="At least 2 characters" aria-describedby={searchError ? 'profile-draft-search-error' : undefined} /><button type="submit">Search proposals</button>{searchTerm && <button type="button" className="profile-filter-clear" onClick={() => { setSearchInput(''); setSearchTerm(''); setSearchError(null); }}>Clear search</button>}</div></form>
    {searchError && <p id="profile-draft-search-error" className="lookup-error" role="alert">{searchError}</p>}
    <form className="exact-lookup profile-draft-filter" onSubmit={event => { event.preventDefault(); applyPolicyFilter(); }}><label htmlFor="profile-draft-policy-filter">Filter the full authority history by exact policy version</label><div><input id="profile-draft-policy-filter" type="search" value={policyInput} onChange={event => { setPolicyInput(event.target.value); setPolicyError(null); }} placeholder="Policy version" aria-describedby={policyError ? 'profile-draft-policy-error' : undefined} /><button type="submit">Filter policy</button>{policyFilter && <button type="button" className="profile-filter-clear" onClick={() => { setPolicyInput(''); setPolicyFilter(''); setPolicyError(null); }}>Clear policy</button>}</div></form>
    {policyError && <p id="profile-draft-policy-error" className="lookup-error" role="alert">{policyError}</p>}
    <form className="exact-lookup profile-draft-filter" onSubmit={event => { event.preventDefault(); applyRecordedRange(); }}><label>Filter recorded UTC dates across the full authority history</label><div><input type="date" aria-label="Recorded from UTC date" value={fromInput} onChange={event => { setFromInput(event.target.value); setRangeError(null); }} /><input type="date" aria-label="Recorded before UTC date" value={untilInput} onChange={event => { setUntilInput(event.target.value); setRangeError(null); }} /><button type="submit">Filter dates</button>{(fromFilter || untilFilter) && <button type="button" className="profile-filter-clear" onClick={() => { setFromInput(''); setUntilInput(''); setFromFilter(''); setUntilFilter(''); setRangeError(null); }}>Clear dates</button>}</div></form>
    {rangeError && <p className="lookup-error" role="alert">{rangeError}</p>}
    <form className="exact-lookup profile-draft-filter" onSubmit={event => { event.preventDefault(); applyValidityFilter(); }}><label htmlFor="profile-draft-validity-filter">Minimum proposed maximum validity across the full authority history</label><div><input id="profile-draft-validity-filter" type="number" min="1" max="825" step="1" value={validityInput} onChange={event => { setValidityInput(event.target.value); setValidityError(null); }} placeholder="Days" /><button type="submit">Filter validity</button>{minValidity !== null && <button type="button" className="profile-filter-clear" onClick={() => { setValidityInput(''); setMinValidity(null); setValidityError(null); }}>Clear validity</button>}</div></form>
    {validityError && <p className="lookup-error" role="alert">{validityError}</p>}
    <form className="exact-lookup profile-draft-filter" onSubmit={event => { event.preventDefault(); applyProfileFilter(); }}><label htmlFor="profile-draft-id-filter">Show all recorded revisions of a profile in this authority</label><div><input id="profile-draft-id-filter" type="search" value={filterInput} onChange={event => { setFilterInput(event.target.value); setFilterError(null); }} placeholder="Profile ID" aria-describedby={filterError ? 'profile-draft-filter-error' : undefined} /><button type="submit">Filter revisions</button>{profileFilter && <button type="button" className="profile-filter-clear" onClick={() => { setFilterInput(''); setFilterError(null); setProfileOrder('oldest'); setProfileFilter(''); }}>Clear filter</button>}</div>{profileFilter && <label className="profile-order-label" htmlFor="profile-draft-order">Revision order <select id="profile-draft-order" value={profileOrder} onChange={event => setProfileOrder(event.target.value as 'oldest' | 'newest')}><option value="oldest">Oldest first</option><option value="newest">Newest first</option></select></label>}</form>
    {filterError && <p id="profile-draft-filter-error" className="lookup-error" role="alert">{filterError}</p>}
    <form className="exact-lookup profile-draft-lookup" onSubmit={event => { event.preventDefault(); findRevision(); }}><label htmlFor="profile-draft-id-lookup">Find a proposal by exact profile ID and revision across this authority’s history</label><div><input id="profile-draft-id-lookup" type="search" value={lookupProfileId} onChange={event => { setLookupProfileId(event.target.value); setLookupError(null); }} placeholder="Profile ID" aria-describedby={lookupError ? 'profile-draft-lookup-error' : undefined} /><input type="text" inputMode="numeric" aria-label="Profile revision number" value={lookupRevision} onChange={event => { setLookupRevision(event.target.value); setLookupError(null); }} placeholder="Revision" aria-describedby={lookupError ? 'profile-draft-lookup-error' : undefined} /><button type="submit" disabled={detailLoading}>{detailLoading ? 'Finding…' : 'Find revision'}</button></div></form>
    {lookupError && <p id="profile-draft-lookup-error" className="lookup-error" role="alert">{lookupError}</p>}
    <label className="profile-compare-filter"><input type="checkbox" checked={warningsOnly} onChange={event => { setWarningsOnly(event.target.checked); setExportSelection([]); }} /> Show proposals with advisory syntax warnings among loaded revisions only ({visibleProfileDrafts(items, true).length}/{items.length})</label>
    {loading ? <p className="profile-draft-message">Loading scoped profile proposals…</p>
      : error && items.length === 0 ? <p className="profile-draft-message" role="alert">{error} <button className="link-button" onClick={() => setRetry(value => value + 1)}>Retry</button></p>
      : items.length === 0 ? <p className="profile-draft-message">{searchTerm ? `No proposals match “${searchTerm}” in this authority.` : profileFilter ? `No revisions recorded for ${profileFilter} in this authority.` : policyFilter || fromFilter || untilFilter || minValidity !== null ? 'No proposals match the active filters in this authority.' : 'No profile proposals recorded for this authority.'}</p>
      : visibleItems.length === 0 ? <p className="profile-draft-message">No advisory syntax warnings in the loaded revisions.{cursor ? ' Load more proposals to inspect further history.' : ''}</p>
      : <div className="profile-draft-list">{visibleItems.map(item => <article className="profile-draft-card" key={`${item.profile_id}/${item.revision}`}>
        <div className="profile-draft-title"><div><h4>{item.display_name}</h4><span className="mono">{item.profile_id} · revision {item.revision}</span></div><span className="row-state">DRAFT</span></div>
        <dl><div><dt>Policy</dt><dd>{item.policy_version}</dd></div><div><dt>Maximum validity</dt><dd>{item.max_validity_days} days</dd></div><div><dt>Maximum DNS SANs</dt><dd>{item.max_dns_sans}</dd></div><div><dt>Proposed DNS zones</dt><dd>{item.proposed_dns_zones.join(', ')}</dd></div><div><dt>Proposed signature suites</dt><dd>{item.proposed_signature_suites.join(', ')}</dd></div><div><dt>Recorded</dt><dd>{new Date(item.created_at).toLocaleString()}</dd></div></dl>
        <div className="profile-draft-actions"><button type="button" className="link-button profile-draft-action" disabled={detailLoading} onClick={() => void openDetail(item)}>View proposal detail</button><button type="button" className="link-button profile-draft-action" aria-pressed={comparisonSelected(item)} onClick={() => toggleComparison(item)}>{comparisonSelected(item) ? 'Remove from comparison' : 'Select for comparison'}</button><button type="button" className="link-button profile-draft-action" aria-pressed={exportSelection.includes(`${item.profile_id}/${item.revision}`)} disabled={exportSelection.length >= MAX_CSV_ROWS && !exportSelection.includes(`${item.profile_id}/${item.revision}`)} onClick={() => toggleExport(item)}>{exportSelection.includes(`${item.profile_id}/${item.revision}`) ? 'Remove from CSV' : 'Select for CSV'}</button></div>
      </article>)}</div>}
    {comparisonItems.length > 0 && <div className="subtle-panel profile-compare-controls"><span>{comparisonItems.length}/2 revisions selected. Select another revision of the same profile from the list or its exact detail.</span>{comparisonItems.length === 2 && <button type="button" className="link-button" onClick={openComparison}>Compare selected revisions</button>}</div>}
    {error && items.length > 0 && <p className="profile-draft-message" role="alert">{error}</p>}
    {detailLoading && <p className="profile-draft-message" role="status">Loading proposal detail…</p>}
    {detailError && <p className="profile-draft-message" role="alert">{detailError}</p>}
    {cursor && <button className="link-button pagination-action" disabled={moreLoading} onClick={() => void loadMore()}>{moreLoading ? 'Loading…' : 'Load more proposals'}</button>}
    {selected && linkedDetail?.id === selected.profile_id && linkedDetail.revision === selected.revision && <ProfileDraftDialog draft={selected} comparisonSelected={comparisonSelected(selected)} onToggleComparison={() => toggleComparison(selected)} onClose={() => { setSelected(null); onCloseDetail(); }} />}
    {showComparison && comparisonItems.length === 2 && <ProfileCompareDialog first={comparisonItems[0]} second={comparisonItems[1]} onCopyLink={copyComparisonLink} onClose={() => { setShowComparison(false); if (linkedDetail?.compareRevision) onCloseDetail(); }} />}
  </div>;
}
