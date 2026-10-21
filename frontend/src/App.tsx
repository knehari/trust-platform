import { useEffect, useMemo, useRef, useState } from 'react';
import type { User } from 'oidc-client-ts';
import { ApiError, apiGet, apiGetPage, type AuditEvent, type Certificate, type CertificateAuthority } from './api';
import { sortLoadedAuditEvents, type AuditSort } from './audit-sort';
import { filterLoadedCertificates } from './certificate-filter';
import { sortLoadedCertificates, type CertificateSort } from './certificate-sort';
import { auditMetadataJson, certificateMetadataJson } from './metadata-copy';
import { navigationUrl, readNavigation, type DetailLink, type Section } from './navigation';
import { oidcConfigurationError, userManager } from './oidc';
import { appendUniquePage, requireAdvancingCursor } from './pagination';
import { requireExactRecord, requireScopedRows, visibleScopedRows } from './scope';
import { canonicalSerialHex } from './serial';
import { canonicalUuid } from './uuid';

function displayDate(value: string | null): string {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? value : date.toLocaleString();
}

function shortId(value: string): string {
  return value.length <= 16 ? value : `${value.slice(0, 8)}…${value.slice(-4)}`;
}

export function App() {
  const [user, setUser] = useState<User | null>(null);
  const [sessionLoading, setSessionLoading] = useState(true);
  const [sessionError, setSessionError] = useState<string | null>(null);
  const [cas, setCas] = useState<CertificateAuthority[]>([]);
  const [caFilter, setCaFilter] = useState('');
  const [caSearchInput, setCaSearchInput] = useState('');
  const [caQuery, setCaQuery] = useState<string | null>(null);
  const [caSearchError, setCaSearchError] = useState<string | null>(null);
  const [selectedCaId, setSelectedCaId] = useState<string | null>(null);
  const [section, setSection] = useState<Section>(() => readNavigation(window.location.search).section);
  const [routeDetail, setRouteDetail] = useState<DetailLink | null>(() => readNavigation(window.location.search).detail);
  const historyNavigation = useRef(false);
  const [navigationReady, setNavigationReady] = useState(false);
  const [viewLinkStatus, setViewLinkStatus] = useState('');
  const [casLoading, setCasLoading] = useState(false);
  const [caCursor, setCaCursor] = useState<string | null>(null);
  const [caMoreLoading, setCaMoreLoading] = useState(false);
  const [caMoreError, setCaMoreError] = useState<string | null>(null);
  const caKey = useRef('');
  const caMoreController = useRef<AbortController | null>(null);
  const [caLookupInput, setCaLookupInput] = useState('');
  const [caLookupResult, setCaLookupResult] = useState<CertificateAuthority | null>(null);
  const [caLookupError, setCaLookupError] = useState<string | null>(null);
  const [caLookupLoading, setCaLookupLoading] = useState(false);
  const caLookupController = useRef<AbortController | null>(null);
  const [certificateLoading, setCertificateLoading] = useState(false);
  const [auditLoading, setAuditLoading] = useState(false);
  const [certificateError, setCertificateError] = useState<string | null>(null);
  const [auditError, setAuditError] = useState<string | null>(null);
  const [dataError, setDataError] = useState<string | null>(null);
  const [linkedCaError, setLinkedCaError] = useState<string | null>(null);
  const [linkedDetailError, setLinkedDetailError] = useState<string | null>(null);
  const [certificates, setCertificates] = useState<Certificate[]>([]);
  const [selectedCertificate, setSelectedCertificate] = useState<Certificate | null>(null);
  const [certificateFilter, setCertificateFilter] = useState('');
  const [cnSearchInput, setCnSearchInput] = useState('');
  const [cnSearchTerm, setCnSearchTerm] = useState<string | null>(null);
  const [cnSearchError, setCnSearchError] = useState<string | null>(null);
  const [certificateSort, setCertificateSort] = useState<CertificateSort>('newest');
  const [lookupInput, setLookupInput] = useState('');
  const [lookupResult, setLookupResult] = useState<Certificate | null>(null);
  const [lookupError, setLookupError] = useState<string | null>(null);
  const [lookupLoading, setLookupLoading] = useState(false);
  const lookupController = useRef<AbortController | null>(null);
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [selectedAuditEvent, setSelectedAuditEvent] = useState<AuditEvent | null>(null);
  const [auditFilter, setAuditFilter] = useState('');
  const [auditFrom, setAuditFrom] = useState('');
  const [auditUntil, setAuditUntil] = useState('');
  const [auditEventType, setAuditEventType] = useState('');
  const [auditQuery, setAuditQuery] = useState('');
  const [auditFilterError, setAuditFilterError] = useState<string | null>(null);
  const [auditSort, setAuditSort] = useState<AuditSort>('newest');
  const [auditLookupInput, setAuditLookupInput] = useState('');
  const [auditLookupResult, setAuditLookupResult] = useState<AuditEvent | null>(null);
  const [auditLookupError, setAuditLookupError] = useState<string | null>(null);
  const [auditLookupLoading, setAuditLookupLoading] = useState(false);
  const auditLookupController = useRef<AbortController | null>(null);
  const [certificateCursor, setCertificateCursor] = useState<string | null>(null);
  const [auditCursor, setAuditCursor] = useState<string | null>(null);
  const [certificateMoreLoading, setCertificateMoreLoading] = useState(false);
  const [auditMoreLoading, setAuditMoreLoading] = useState(false);
  const [certificateMoreError, setCertificateMoreError] = useState<string | null>(null);
  const [auditMoreError, setAuditMoreError] = useState<string | null>(null);
  const detailKey = useRef('');
  const certificateMoreController = useRef<AbortController | null>(null);
  const auditMoreController = useRef<AbortController | null>(null);
  const [reload, setReload] = useState(0);
  const [certificateReload, setCertificateReload] = useState(0);
  const [auditReload, setAuditReload] = useState(0);

  const clearSession = () => {
    setUser(null);
    setCas([]);
    setCaQuery(null);
    setCaSearchInput('');
    setSelectedCaId(null);
    caLookupController.current?.abort();
    setCaLookupResult(null);
    setCertificates([]);
    setSelectedCertificate(null);
    lookupController.current?.abort();
    setLookupResult(null);
    setAuditEvents([]);
    setSelectedAuditEvent(null);
    setRouteDetail(null);
    auditLookupController.current?.abort();
    setAuditLookupResult(null);
  };

  const rejectSession = () => {
    clearSession();
    setSessionError('Your session is no longer valid. Sign in again.');
    void userManager?.removeUser().catch(() => {});
  };

  const handleReadError = (error: unknown, fallback: string, show: (message: string) => void) => {
    if (error instanceof ApiError && error.status === 401) {
      rejectSession();
      return;
    }
    show(error instanceof Error ? error.message : fallback);
  };

  useEffect(() => {
    let cancelled = false;
    const removeExpired = userManager?.events.addAccessTokenExpired(() => {
      if (!cancelled) {
        clearSession();
        setSessionError('Your session has expired. Sign in again.');
      }
    });
    const removeUnloaded = userManager?.events.addUserUnloaded(() => {
      if (!cancelled) clearSession();
    });
    async function restoreSession() {
      if (!userManager) { setSessionLoading(false); return; }
      try {
        const current = window.location.pathname === '/auth/callback'
          ? await userManager.signinRedirectCallback()
          : await userManager.getUser();
        if (window.location.pathname === '/auth/callback') {
          const destination = typeof current?.state === 'string' ? readNavigation(current.state) : readNavigation('');
          window.history.replaceState({}, '', navigationUrl(destination.section, destination.caId, destination.detail));
          if (!cancelled) { setSection(destination.section); setRouteDetail(destination.detail); }
        }
        if (!cancelled) setUser(current && !current.expired ? current : null);
      } catch {
        if (!cancelled) setSessionError('Could not complete sign-in. Try again.');
      } finally {
        if (!cancelled) setSessionLoading(false);
      }
    }
    void restoreSession();
    return () => {
      cancelled = true;
      removeExpired?.();
      removeUnloaded?.();
    };
  }, []);

  useEffect(() => {
    if (!user || user.expired) return;
    setNavigationReady(false);
    caKey.current = `${user.access_token}/${reload}/${caQuery ?? ''}`;
    caMoreController.current?.abort();
    setCaMoreLoading(false);
    setCaMoreError(null);
    setCaCursor(null);
    setCas([]);
    setSelectedCaId(null);
    setCertificates([]);
    setAuditEvents([]);
    setSelectedCertificate(null);
    setSelectedAuditEvent(null);
    setCaFilter('');
    const controller = new AbortController();
    const linkedCaId = caQuery ? null : readNavigation(window.location.search).caId;
    setCasLoading(true);
    setDataError(null);
    setLinkedCaError(null);
    async function loadAuthorities() {
      let firstPage: CertificateAuthority[] = [];
      try {
        const path = caQuery ? `/v1/cas?q=${encodeURIComponent(caQuery)}` : '/v1/cas';
        const page = await apiGetPage<CertificateAuthority>(path, user!.access_token, controller.signal);
        if (controller.signal.aborted) return;
        firstPage = page.items;
        setCas(firstPage);
        setCaCursor(page.nextCursor);
      } catch (error) {
        if (controller.signal.aborted) return;
        handleReadError(error, 'Could not load authorities.', setDataError);
        if (error instanceof ApiError && error.status === 401) return;
      }
      if (linkedCaId && !firstPage.some(ca => ca.ca_id === linkedCaId)) {
        try {
          const ca = await apiGet<CertificateAuthority>(`/v1/cas/${linkedCaId}`, user!.access_token, controller.signal);
          if (controller.signal.aborted) return;
          requireExactRecord(ca, linkedCaId, 'ca_id', linkedCaId);
          setCaLookupResult(ca);
          setSelectedCaId(linkedCaId);
          return;
        } catch (error) {
          if (controller.signal.aborted) return;
          if (error instanceof ApiError && error.status === 401) {
            handleReadError(error, 'Could not open linked authority.', setDataError);
            return;
          }
          setLinkedCaError('The linked authority is unavailable for this session. Showing an authority in your scope instead.');
        }
      }
      if (!controller.signal.aborted) setSelectedCaId(linkedCaId && firstPage.some(ca => ca.ca_id === linkedCaId) ? linkedCaId : firstPage[0]?.ca_id ?? null);
    }
    void loadAuthorities().finally(() => {
      if (!controller.signal.aborted) {
        setCasLoading(false);
        setNavigationReady(true);
      }
    });
    return () => { controller.abort(); caMoreController.current?.abort(); };
  }, [user, reload, caQuery]);

  useEffect(() => {
    if (!navigationReady || !user || user.expired) return;
    const next = navigationUrl(section, selectedCaId, routeDetail);
    if (`${window.location.pathname}${window.location.search}` !== next) {
      if (historyNavigation.current) window.history.replaceState({}, '', next);
      else window.history.pushState({}, '', next);
    }
    historyNavigation.current = false;
  }, [navigationReady, user, section, selectedCaId, routeDetail]);

  useEffect(() => {
    const onPopState = () => {
      const destination = readNavigation(window.location.search);
      historyNavigation.current = true;
      setSection(destination.section);
      setSelectedCaId(destination.caId);
      setRouteDetail(destination.detail);
      setSelectedCertificate(null);
      setSelectedAuditEvent(null);
      setLinkedCaError(null);
      setLinkedDetailError(null);
    };
    window.addEventListener('popstate', onPopState);
    return () => window.removeEventListener('popstate', onPopState);
  }, []);

  useEffect(() => {
    if (!navigationReady || !user || user.expired || !selectedCaId || cas.some(ca => ca.ca_id === selectedCaId) || caLookupResult?.ca_id === selectedCaId) return;
    const controller = new AbortController();
    void apiGet<CertificateAuthority>(`/v1/cas/${selectedCaId}`, user.access_token, controller.signal)
      .then(ca => { if (!controller.signal.aborted) setCaLookupResult(requireExactRecord(ca, selectedCaId, 'ca_id', selectedCaId)); })
      .catch(error => {
        if (controller.signal.aborted) return;
        handleReadError(error, 'Could not restore the authority.', setLinkedCaError);
        setSelectedCaId(null);
        setRouteDetail(null);
      });
    return () => controller.abort();
  }, [navigationReady, user, selectedCaId, cas, caLookupResult]);

  useEffect(() => {
    if (!navigationReady || !user || user.expired || !selectedCaId || !routeDetail) return;
    if (routeDetail.kind === 'certificate' && selectedCertificate?.ca_id === selectedCaId && selectedCertificate.request_id === routeDetail.id) return;
    if (routeDetail.kind === 'audit' && selectedAuditEvent?.ca_id === selectedCaId && selectedAuditEvent.event_id === routeDetail.id) return;
    const controller = new AbortController();
    const path = routeDetail.kind === 'certificate'
      ? `/v1/cas/${selectedCaId}/certificates/${routeDetail.id}`
      : `/v1/cas/${selectedCaId}/audit/${routeDetail.id}`;
    void apiGet<Certificate | AuditEvent>(path, user.access_token, controller.signal)
      .then(record => {
        if (controller.signal.aborted) return;
        if (routeDetail.kind === 'certificate') {
          const certificate = requireExactRecord(record as Certificate, selectedCaId, 'request_id', routeDetail.id);
          setLookupResult(certificate); setSelectedCertificate(certificate);
        } else {
          const event = requireExactRecord(record as AuditEvent, selectedCaId, 'event_id', routeDetail.id);
          setAuditLookupResult(event); setSelectedAuditEvent(event);
        }
      })
      .catch(error => {
        if (controller.signal.aborted) return;
        handleReadError(error, 'Could not open the linked detail.', setLinkedDetailError);
        setRouteDetail(null);
      });
    return () => controller.abort();
  }, [navigationReady, user, selectedCaId, routeDetail, selectedCertificate, selectedAuditEvent]);

  function openCertificate(certificate: Certificate) {
    setLinkedDetailError(null);
    setSelectedCertificate(certificate);
    setRouteDetail({ kind: 'certificate', id: certificate.request_id });
  }

  function openAuditEvent(event: AuditEvent) {
    setLinkedDetailError(null);
    setSelectedAuditEvent(event);
    setRouteDetail({ kind: 'audit', id: event.event_id });
  }

  function closeDetail() {
    setSelectedCertificate(null);
    setSelectedAuditEvent(null);
    setRouteDetail(null);
  }

  useEffect(() => setViewLinkStatus(''), [section, selectedCaId]);

  async function copyViewLink() {
    if (!navigationReady) return;
    const url = new URL(navigationUrl(section, selectedCaId, routeDetail), window.location.origin).href;
    try {
      await navigator.clipboard.writeText(url);
      setViewLinkStatus('View link copied.');
    } catch {
      setViewLinkStatus('Could not copy the link. Use the address bar instead.');
    }
  }

  useEffect(() => {
    caLookupController.current?.abort();
    setCaLookupInput('');
    setCaLookupResult(null);
    setCaLookupError(null);
    setCaLookupLoading(false);
    return () => caLookupController.current?.abort();
  }, [user, reload]);

  async function loadMoreCas() {
    if (!user || user.expired || !caCursor || casLoading || caMoreLoading) return;
    const key = caKey.current;
    const controller = new AbortController();
    caMoreController.current = controller;
    setCaMoreLoading(true);
    setCaMoreError(null);
    try {
      const search = caQuery ? `&q=${encodeURIComponent(caQuery)}` : '';
      const page = await apiGetPage<CertificateAuthority>(`/v1/cas?after=${encodeURIComponent(caCursor)}${search}`, user.access_token, controller.signal);
      if (caKey.current === key) {
        const nextCursor = requireAdvancingCursor(caCursor, page.nextCursor);
        setCas(current => appendUniquePage(current, page.items, ca => ca.ca_id));
        setCaCursor(nextCursor);
      }
    } catch (error) {
      if (!controller.signal.aborted && caKey.current === key) handleReadError(error, 'Could not load more authorities.', setCaMoreError);
    } finally {
      if (caKey.current === key) setCaMoreLoading(false);
    }
  }

  useEffect(() => {
    detailKey.current = `${selectedCaId ?? ''}/${reload}`;
    certificateMoreController.current?.abort();
    auditMoreController.current?.abort();
    setCertificateMoreLoading(false);
    setAuditMoreLoading(false);
    setCertificateMoreError(null);
    setAuditMoreError(null);
    setDataError(null);
    return () => { certificateMoreController.current?.abort(); auditMoreController.current?.abort(); };
  }, [user, selectedCaId, reload]);

  useEffect(() => {
    certificateMoreController.current?.abort();
    certificateMoreController.current = null;
    setCertificateMoreLoading(false);
    setCertificateMoreError(null);
    setCertificateLoading(false);
    setCertificateCursor(null);
    setCertificates([]);
    setCertificateError(null);
    if (!user || user.expired || !selectedCaId) return;
    const controller = new AbortController();
    setCertificateLoading(true);
    const search = cnSearchTerm ? `?cn=${encodeURIComponent(cnSearchTerm)}` : '';
    void apiGetPage<Certificate>(`/v1/cas/${encodeURIComponent(selectedCaId)}/certificates${search}`, user.access_token, controller.signal)
      .then(page => {
        if (controller.signal.aborted) return;
        setCertificates(requireScopedRows(page.items, selectedCaId));
        setCertificateCursor(page.nextCursor);
      })
      .catch(error => { if (!controller.signal.aborted) handleReadError(error, 'Could not load certificates.', setCertificateError); })
      .finally(() => { if (!controller.signal.aborted) setCertificateLoading(false); });
    return () => controller.abort();
  }, [user, selectedCaId, reload, certificateReload, cnSearchTerm]);

  useEffect(() => {
    auditMoreController.current?.abort();
    auditMoreController.current = null;
    setAuditMoreLoading(false);
    setAuditMoreError(null);
    setAuditLoading(false);
    setAuditCursor(null);
    setAuditEvents([]);
    setAuditError(null);
    if (!user || user.expired || !selectedCaId) return;
    const controller = new AbortController();
    setAuditLoading(true);
    void apiGetPage<AuditEvent>(`/v1/cas/${encodeURIComponent(selectedCaId)}/audit${auditQuery ? `?${auditQuery}` : ''}`, user.access_token, controller.signal)
      .then(page => {
        if (controller.signal.aborted) return;
        setAuditEvents(requireScopedRows(page.items, selectedCaId));
        setAuditCursor(page.nextCursor);
      })
      .catch(error => { if (!controller.signal.aborted) handleReadError(error, 'Could not load audit events.', setAuditError); })
      .finally(() => { if (!controller.signal.aborted) setAuditLoading(false); });
    return () => controller.abort();
  }, [user, selectedCaId, reload, auditReload, auditQuery]);

  async function loadOlder(kind: 'certificates' | 'audit') {
    const cursor = kind === 'certificates' ? certificateCursor : auditCursor;
    if (!user || user.expired || !selectedCaId || !cursor || (kind === 'certificates' ? certificateLoading || certificateMoreLoading : auditLoading || auditMoreLoading)) return;
    const key = detailKey.current;
    const controller = new AbortController();
    if (kind === 'certificates') {
      certificateMoreController.current = controller;
      setCertificateMoreLoading(true);
      setCertificateMoreError(null);
    } else {
      auditMoreController.current = controller;
      setAuditMoreLoading(true);
      setAuditMoreError(null);
    }
    try {
      const search = kind === 'certificates' && cnSearchTerm ? `&cn=${encodeURIComponent(cnSearchTerm)}` : kind === 'audit' && auditQuery ? `&${auditQuery}` : '';
      const path = `/v1/cas/${encodeURIComponent(selectedCaId)}/${kind}?before=${encodeURIComponent(cursor)}${search}`;
      if (kind === 'certificates') {
        const page = await apiGetPage<Certificate>(path, user.access_token, controller.signal);
        if (!controller.signal.aborted && certificateMoreController.current === controller && detailKey.current === key) {
          const scopedPage = requireScopedRows(page.items, selectedCaId);
          const nextCursor = requireAdvancingCursor(cursor, page.nextCursor);
          setCertificates(current => appendUniquePage(current, scopedPage, cert => cert.request_id));
          setCertificateCursor(nextCursor);
        }
      } else {
        const page = await apiGetPage<AuditEvent>(path, user.access_token, controller.signal);
        if (!controller.signal.aborted && auditMoreController.current === controller && detailKey.current === key) {
          const scopedPage = requireScopedRows(page.items, selectedCaId);
          const nextCursor = requireAdvancingCursor(cursor, page.nextCursor);
          setAuditEvents(current => appendUniquePage(current, scopedPage, event => event.event_id));
          setAuditCursor(nextCursor);
        }
      }
    } catch (error) {
      if (!controller.signal.aborted && (kind === 'certificates' ? certificateMoreController.current : auditMoreController.current) === controller && detailKey.current === key) {
        handleReadError(error, 'Could not load older records.', kind === 'certificates' ? setCertificateMoreError : setAuditMoreError);
      }
    } finally {
      if ((kind === 'certificates' ? certificateMoreController.current : auditMoreController.current) === controller) {
        if (kind === 'certificates') {
          certificateMoreController.current = null;
          setCertificateMoreLoading(false);
        } else {
          auditMoreController.current = null;
          setAuditMoreLoading(false);
        }
      }
    }
  }

  useEffect(() => {
    setCertificateFilter('');
    setCnSearchInput('');
    setCnSearchTerm(null);
    setCnSearchError(null);
  }, [selectedCaId]);
  useEffect(() => {
    lookupController.current?.abort();
    setLookupInput('');
    setLookupResult(null);
    setLookupError(null);
    setLookupLoading(false);
    return () => lookupController.current?.abort();
  }, [user, selectedCaId, reload]);
  useEffect(() => {
    setAuditFilter('');
    setAuditFrom(''); setAuditUntil(''); setAuditEventType('');
    setAuditQuery(''); setAuditFilterError(null);
  }, [selectedCaId]);
  useEffect(() => {
    auditLookupController.current?.abort();
    setAuditLookupInput('');
    setAuditLookupResult(null);
    setAuditLookupError(null);
    setAuditLookupLoading(false);
    return () => auditLookupController.current?.abort();
  }, [user, selectedCaId, reload]);
  const scopedCertificates = useMemo(() => visibleScopedRows(certificates, selectedCaId), [certificates, selectedCaId]);
  const scopedAuditEvents = useMemo(() => visibleScopedRows(auditEvents, selectedCaId), [auditEvents, selectedCaId]);
  const filteredCertificates = useMemo(() => {
    return filterLoadedCertificates(scopedCertificates, certificateFilter);
  }, [scopedCertificates, certificateFilter]);
  const sortedCertificates = useMemo(() => sortLoadedCertificates(filteredCertificates, certificateSort), [filteredCertificates, certificateSort]);
  const filteredAuditEvents = useMemo(() => {
    const query = auditFilter.trim().toLowerCase();
    return query ? scopedAuditEvents.filter(event => [event.event_id, event.event_type, event.decision, event.policy_version ?? ''].some(value => value.toLowerCase().includes(query))) : scopedAuditEvents;
  }, [scopedAuditEvents, auditFilter]);
  const sortedAuditEvents = useMemo(() => sortLoadedAuditEvents(filteredAuditEvents, auditSort), [filteredAuditEvents, auditSort]);
  const filteredCas = useMemo(() => {
    const query = caFilter.trim().toLowerCase();
    return query ? cas.filter(ca => [ca.ca_id, ca.display_name, ca.policy_version].some(value => value.toLowerCase().includes(query))) : cas;
  }, [cas, caFilter]);
  const selectedCa = useMemo(() => cas.find(ca => ca.ca_id === selectedCaId) ?? (caLookupResult?.ca_id === selectedCaId ? caLookupResult : null), [cas, caLookupResult, selectedCaId]);
  const name = user?.profile.preferred_username ?? user?.profile.name ?? user?.profile.sub ?? 'Operator';

  function searchAuthorities() {
    const query = caSearchInput.trim();
    if (query.length < 2 || query.length > 255) {
      setCaSearchError('Enter 2–255 characters of an authority name or policy.');
      return;
    }
    setCaSearchError(null);
    setRouteDetail(null);
    setCaQuery(query);
  }

  function authoritySearchForm(id: string) {
    return <form className="exact-lookup" onSubmit={event => { event.preventDefault(); searchAuthorities(); }}>
      <label htmlFor={id}>Search name or policy across all authorized authorities</label>
      <div><input id={id} type="search" value={caSearchInput} onChange={event => { setCaSearchInput(event.target.value); setCaSearchError(null); }} placeholder="Name or policy prefix" /><button type="submit">Search</button>{caQuery && <button type="button" onClick={() => { setCaSearchInput(''); setCaQuery(null); }}>Clear</button>}</div>
      {caSearchError && <p className="lookup-error" role="alert">{caSearchError}</p>}
      {caQuery && <p className="lookup-result">Searching your full CA scope for “{caQuery}”.</p>}
    </form>;
  }

  async function findAuthority() {
    if (!user || user.expired) return;
    const caId = canonicalUuid(caLookupInput);
    caLookupController.current?.abort();
    setCaLookupLoading(false);
    setCaLookupError(null);
    if (!caId) {
      setCaLookupError('Enter a complete authority UUID (plain, braced or urn:uuid form).');
      return;
    }
    const controller = new AbortController();
    caLookupController.current = controller;
    setCaLookupLoading(true);
    try {
      const ca = await apiGet<CertificateAuthority>(`/v1/cas/${caId}`, user.access_token, controller.signal);
      if (controller.signal.aborted) return;
      requireExactRecord(ca, caId, 'ca_id', caId);
      setCaLookupResult(ca);
      setSelectedCaId(ca.ca_id);
      setSection('authorities');
    } catch (error) {
      if (controller.signal.aborted) return;
      handleReadError(error, 'Could not find the authority.', setCaLookupError);
    } finally {
      if (!controller.signal.aborted) setCaLookupLoading(false);
    }
  }

  async function findCertificate() {
    if (!user || user.expired || !selectedCaId) return;
    const identifier = lookupInput.trim();
    const requestId = canonicalUuid(identifier);
    const serialHex = requestId ? null : canonicalSerialHex(identifier);
    lookupController.current?.abort();
    setLookupLoading(false);
    setLookupResult(null);
    setLookupError(null);
    if (!requestId && !serialHex) {
      setLookupError('Enter a complete request UUID or a positive hex serial (for example, 010001, 0x10001 or 01:00:01).');
      return;
    }
    const controller = new AbortController();
    lookupController.current = controller;
    setLookupLoading(true);
    try {
      const path = requestId
        ? `/v1/cas/${encodeURIComponent(selectedCaId)}/certificates/${requestId}`
        : `/v1/cas/${encodeURIComponent(selectedCaId)}/certificates/by-serial/${serialHex}`;
      const certificate = await apiGet<Certificate>(path, user.access_token, controller.signal);
      if (controller.signal.aborted) return;
      requireExactRecord(certificate, selectedCaId, requestId ? 'request_id' : 'serial_hex', requestId ?? serialHex!);
      setLookupResult(certificate);
      openCertificate(certificate);
    } catch (error) {
      if (controller.signal.aborted) return;
      if (error instanceof ApiError && error.status === 404) setLookupError('No certificate with that request ID or serial was found for this authority.');
      else handleReadError(error, 'Could not find the certificate.', setLookupError);
    } finally {
      if (!controller.signal.aborted) setLookupLoading(false);
    }
  }

  async function findAuditEvent() {
    if (!user || user.expired || !selectedCaId) return;
    const eventId = canonicalUuid(auditLookupInput);
    auditLookupController.current?.abort();
    setAuditLookupLoading(false);
    setAuditLookupResult(null);
    setAuditLookupError(null);
    if (!eventId) {
      setAuditLookupError('Enter a complete event UUID (plain, braced or urn:uuid form).');
      return;
    }
    const controller = new AbortController();
    auditLookupController.current = controller;
    setAuditLookupLoading(true);
    try {
      const event = await apiGet<AuditEvent>(`/v1/cas/${encodeURIComponent(selectedCaId)}/audit/${eventId}`, user.access_token, controller.signal);
      if (controller.signal.aborted) return;
      requireExactRecord(event, selectedCaId, 'event_id', eventId);
      setAuditLookupResult(event);
      openAuditEvent(event);
    } catch (error) {
      if (controller.signal.aborted) return;
      if (error instanceof ApiError && error.status === 404) setAuditLookupError('No audit event with that ID was found for this authority.');
      else handleReadError(error, 'Could not find the audit event.', setAuditLookupError);
    } finally {
      if (!controller.signal.aborted) setAuditLookupLoading(false);
    }
  }

  if (sessionLoading) return <div className="center-state"><span className="spinner" /> Establishing secure session…</div>;

  if (oidcConfigurationError || sessionError || !user || user.expired) {
    return <div className="login-layout">
      <div className="login-brand"><div className="brand-mark">S</div><span>SOVEREIGN <b>TRUST</b></span></div>
      <div className="login-card">
        <div className="eyebrow">MANAGEMENT CONSOLE · LABORATORY</div>
        <h1>Clear oversight for every certificate authority.</h1>
        <p>Review CA inventory, certificate metadata and audit activity through a scoped, read-only session.</p>
        {(oidcConfigurationError || sessionError) && <div className="notice error" role="alert">{oidcConfigurationError || sessionError}</div>}
        <button className="primary-button" disabled={!userManager} onClick={() => {
          const destination = readNavigation(window.location.search);
          void userManager?.signinRedirect({ state: navigationUrl(destination.section, destination.caId, destination.detail).slice(1) })
            .catch(() => setSessionError('OIDC sign-in could not start. Check the local test issuer.'));
        }}>
          Sign in with your organization <span aria-hidden="true">↗</span>
        </button>
        <div className="login-footnote">Access is limited to the authorities assigned to your account. No signing keys are available in this console.</div>
      </div>
      <div className="login-footer">PRIVATE LABORATORY SYSTEM · NOT A PRODUCTION TRUST SERVICE</div>
    </div>;
  }

  return <div className="app-shell">
    <aside className="sidebar">
      <div className="brand"><div className="brand-mark">S</div><span>SOVEREIGN<br /><b>TRUST</b></span></div>
      <div className="workspace-tag"><span className="status-dot" /> LAB WORKSPACE</div>
      <nav aria-label="Main navigation" className="nav">
        <div className="nav-label">WORKSPACE</div>
        <button className={section === 'overview' ? 'active' : ''} aria-current={section === 'overview' ? 'page' : undefined} onClick={() => setSection('overview')}><span>▦</span> Overview</button>
        <button className={section === 'authorities' ? 'active' : ''} aria-current={section === 'authorities' ? 'page' : undefined} onClick={() => setSection('authorities')}><span>◇</span> Authorities <small>{cas.length}{caCursor ? '+' : ''}</small></button>
        <button className={section === 'certificates' ? 'active' : ''} aria-current={section === 'certificates' ? 'page' : undefined} onClick={() => setSection('certificates')}><span>▤</span> Certificates</button>
        <button className={section === 'audit' ? 'active' : ''} aria-current={section === 'audit' ? 'page' : undefined} onClick={() => setSection('audit')}><span>◷</span> Audit trail</button>
      </nav>
      <div className="sidebar-bottom"><div className="sidebar-note">Read-only access<br /><span>Changes and issuance are unavailable in this laboratory console.</span></div><div className="version">TRUST PLATFORM · V0.1 LAB</div></div>
    </aside>
    <div className="main-column">
      <header className="topbar"><div className="breadcrumb">Workspace <span>/</span> {section === 'overview' ? 'Overview' : section === 'authorities' ? 'Authorities' : section === 'certificates' ? 'Certificates' : 'Audit trail'}</div><div className="top-actions"><span className="read-badge">READ ONLY</span><button className="icon-button" title="Refresh data" aria-label="Refresh scoped data" onClick={() => setReload(value => value + 1)}>↻</button><div className="user-avatar" title={name}>{String(name).slice(0, 1).toUpperCase()}</div><button className="text-button" onClick={() => void userManager?.signoutRedirect()}>Sign out</button></div></header>
      <main className="content">
        <div className="page-heading"><div><div className="eyebrow">TRUST OPERATIONS / {section.toUpperCase()}</div><h1>{section === 'overview' ? 'Good to see you.' : section === 'authorities' ? 'Certificate authorities' : section === 'certificates' ? 'Certificate inventory' : 'Audit trail'}</h1><p>{section === 'overview' ? 'A current view of the authorities in your approved scope.' : section === 'authorities' ? 'Inspect policy references and public CA metadata.' : section === 'certificates' ? 'Issued certificate metadata for the selected authority.' : 'Recent recorded events for the selected authority.'}</p></div><div className="view-link-tools"><div className="page-date">{new Date().toLocaleDateString(undefined, { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })}</div><button type="button" className="copy-view-link" disabled={!navigationReady} onClick={() => void copyViewLink()}>Copy view link</button>{viewLinkStatus && <span className="view-link-status" role="status">{viewLinkStatus}</span>}</div></div>
        {dataError && <div className="notice error" role="alert">{dataError} <button onClick={() => setReload(value => value + 1)}>Retry</button></div>}
        {linkedCaError && <div className="notice error" role="alert">{linkedCaError} <button onClick={() => setLinkedCaError(null)}>Dismiss</button></div>}
        {linkedDetailError && <div className="notice error" role="alert">{linkedDetailError} <button onClick={() => setLinkedDetailError(null)}>Dismiss</button></div>}
        {casLoading && <div className="notice loading"><span className="spinner" /> Loading scoped authorities…</div>}
        {section === 'overview' && !casLoading && cas.length === 0 && !dataError && !caQuery && <div className="empty-state"><div className="empty-icon">◇</div><h2>No authorities in your scope</h2><p>Ask an administrator to grant you the reader role and a CA scope, then refresh this page.</p></div>}
        {(cas.length > 0 || caQuery || (section !== 'overview' && !casLoading)) && <>
          {section === 'overview' && <>
            <div className="metric-grid"><Metric label="AUTHORITIES IN SCOPE" value={`${cas.length}${caCursor ? '+' : ''}`} detail="Authorities loaded" icon="◇" /><Metric label="SELECTED CA CERTIFICATES" value={certificateLoading ? '…' : certificateError ? '—' : String(scopedCertificates.length)} detail="Records loaded" icon="▤" /><Metric label="RECENT AUDIT EVENTS" value={auditLoading ? '…' : auditError ? '—' : String(scopedAuditEvents.length)} detail="Records loaded" icon="◷" /></div>
            <div className="section-head"><div><h2>Your authorities</h2><p>Choose an authority to inspect its records.</p></div><button className="link-button" onClick={() => setSection('authorities')}>View all authorities →</button></div>
            {authoritySearchForm("overview-ca-search")}<label className="filter-field"><span>Filter loaded authorities</span><input type="search" value={caFilter} onChange={event => setCaFilter(event.target.value)} placeholder="Name, authority ID or policy" /></label>{filteredCas.length === 0 ? <p className="filter-empty">{caQuery && cas.length === 0 ? 'No authorized authority matches that name or policy prefix.' : 'No matching authority among loaded records.'}</p> : <AuthorityList cas={filteredCas} selectedCaId={selectedCaId} onSelect={id => { setSelectedCaId(id); setSection('authorities'); }} />}
            {caCursor && (caMoreError ? <LoadFailure message={caMoreError} onRetry={() => void loadMoreCas()} /> : <button className="link-button pagination-action" disabled={caMoreLoading} onClick={() => void loadMoreCas()}>{caMoreLoading ? 'Loading…' : 'Load more authorities'}</button>)}
          </>}
          {section !== 'overview' && <div className="workspace-grid"><div className="authority-panel"><div className="panel-heading"><span>AUTHORITIES LOADED</span><span>{cas.length}{caCursor ? '+' : ''}</span></div><form className="exact-lookup authority-lookup" onSubmit={event => { event.preventDefault(); void findAuthority(); }}><label htmlFor="authority-id-lookup">Go to an authority by exact ID</label><div><input id="authority-id-lookup" type="search" value={caLookupInput} onChange={event => { caLookupController.current?.abort(); setCaLookupLoading(false); setCaLookupInput(event.target.value); setCaLookupError(null); }} placeholder="Authority UUID" aria-describedby={caLookupError ? 'authority-lookup-error' : undefined} /><button type="submit" disabled={caLookupLoading}>{caLookupLoading ? 'Finding…' : 'Find'}</button></div></form>{caLookupError && <p id="authority-lookup-error" className="lookup-error authority-lookup-message" role="alert">{caLookupError}</p>}{caLookupResult && !cas.some(ca => ca.ca_id === caLookupResult.ca_id) && <p className="lookup-result authority-lookup-message">Selected: <button className="link-button" onClick={() => { setSelectedCaId(caLookupResult.ca_id); setSection('authorities'); }}>{caLookupResult.display_name}</button></p>}{authoritySearchForm("side-ca-search")}<label className="filter-field authority-filter"><span>Filter loaded authorities</span><input type="search" value={caFilter} onChange={event => setCaFilter(event.target.value)} placeholder="Name, ID or policy" /></label>{filteredCas.length === 0 ? <p className="filter-empty">{cas.length === 0 ? 'No authorities loaded. Find one by exact ID or retry the inventory.' : 'No matching authority among loaded records.'}</p> : <AuthorityList cas={filteredCas} selectedCaId={selectedCaId} onSelect={setSelectedCaId} compact />}{caCursor && (caMoreError ? <LoadFailure message={caMoreError} onRetry={() => void loadMoreCas()} /> : <button className="link-button pagination-action" disabled={caMoreLoading} onClick={() => void loadMoreCas()}>{caMoreLoading ? 'Loading…' : 'Load more authorities'}</button>)}</div><div className="detail-panel">
            {!selectedCa && <EmptyDetail title="No authority selected" detail="Select a loaded authority or find one by exact ID." />}
            {selectedCa && <><div className="detail-header"><div><div className="eyebrow">CERTIFICATE AUTHORITY</div><h2>{selectedCa.display_name}</h2><span className="mono muted">{selectedCa.ca_id}</span></div><span className="state-pill"><span className="status-dot" /> LAB RECORD</span></div>
              {section === 'authorities' && <div className="detail-content"><div className="detail-grid"><Info label="POLICY VERSION" value={selectedCa.policy_version} /><Info label="CREATED" value={displayDate(selectedCa.created_at)} /><Info label="PARENT AUTHORITY" value={selectedCa.parent_ca_id ? shortId(selectedCa.parent_ca_id) : 'Root / not recorded'} /><Info label="AUTHORITY ID" value={shortId(selectedCa.ca_id)} /></div><div className="subtle-panel"><b>About this record</b><p>This console shows database metadata. It does not assert that a public CA certificate, signing key or policy publication has been independently verified.</p></div><div className="quick-links"><button onClick={() => setSection('certificates')}>View certificates →</button><button onClick={() => setSection('audit')}>View audit trail →</button></div></div>}
              {section === 'certificates' && <div className="detail-content"><div className="table-heading"><h3>Certificates</h3><span>{certificateFilter.trim() ? `${filteredCertificates.length} of ${scopedCertificates.length} loaded records` : `${scopedCertificates.length} records loaded`}</span></div><form className="exact-lookup" onSubmit={event => { event.preventDefault(); const query = cnSearchInput.trim(); if (query.length < 2 || query.length > 255) { setCnSearchError('Enter at least two and at most 255 CN characters.'); return; } setCnSearchError(null); setCnSearchTerm(query); }}><label htmlFor="certificate-cn-search">Search CN prefix across this authority’s full certificate history</label><div><input id="certificate-cn-search" type="search" value={cnSearchInput} onChange={event => { setCnSearchInput(event.target.value); setCnSearchError(null); }} placeholder="First characters of a CN" aria-describedby={cnSearchError ? 'certificate-cn-search-error' : undefined} /><button type="submit">Search</button>{cnSearchTerm && <button type="button" onClick={() => { setCnSearchInput(''); setCnSearchTerm(null); }}>Clear</button>}</div></form>{cnSearchError && <p id="certificate-cn-search-error" className="lookup-error" role="alert">{cnSearchError}</p>}{cnSearchTerm && <p className="lookup-result">Showing CN prefix matches for <strong>{cnSearchTerm}</strong> across the authority’s history.</p>}<form className="exact-lookup" onSubmit={event => { event.preventDefault(); void findCertificate(); }}><label htmlFor="certificate-request-lookup">Find a certificate by exact request ID or serial across this authority's history</label><div><input id="certificate-request-lookup" type="search" value={lookupInput} onChange={event => { lookupController.current?.abort(); setLookupLoading(false); setLookupInput(event.target.value); setLookupResult(null); setLookupError(null); }} placeholder="Request UUID or serial hex" aria-describedby={lookupError ? 'certificate-lookup-error' : undefined} /><button type="submit" disabled={lookupLoading}>{lookupLoading ? 'Finding…' : 'Find'}</button></div></form>{lookupError && <p id="certificate-lookup-error" className="lookup-error" role="alert">{lookupError}</p>}{lookupResult?.ca_id === selectedCaId && <p className="lookup-result">Found serial <span className="mono">{lookupResult.serial_hex}</span> <button className="link-button" onClick={() => openCertificate(lookupResult)}>View detail</button></p>}{certificateLoading ? <LoadingRows /> : certificateError ? <LoadFailure message={certificateError} onRetry={() => setCertificateReload(value => value + 1)} /> : scopedCertificates.length === 0 ? <EmptyDetail title="No certificates recorded" detail="No certificate metadata matches this CN prefix in the selected authority, or no certificates are recorded." /> : <><label className="filter-field"><span>Sort loaded certificates</span><select value={certificateSort} onChange={event => setCertificateSort(event.target.value as CertificateSort)}><option value="newest">Newest signed first</option><option value="oldest">Oldest signed first</option><option value="cn">CN A–Z</option><option value="serial">Serial hex A–Z</option></select></label><label className="filter-field"><span>Filter loaded certificates</span><input type="search" value={certificateFilter} onChange={event => setCertificateFilter(event.target.value)} placeholder="CN, serial, fingerprint, request ID or state" /></label>{filteredCertificates.length === 0 ? <p className="filter-empty">No matching certificate among loaded records. Find by exact request ID or serial above to search the full history.</p> : <div className="table-wrap"><table className="certificate-table"><thead><tr><th>CN</th><th>SERIAL</th><th>STATE</th><th>SIGNED</th><th>FINGERPRINT SHA-256</th></tr></thead><tbody>{sortedCertificates.map(cert => <tr key={cert.request_id}><td className="certificate-cn" title={cert.subject_cn ?? 'CN not recorded'}>{cert.subject_cn ? <button className="record-link" onClick={() => openCertificate(cert)} aria-label={`View certificate for ${cert.subject_cn}`}>{cert.subject_cn}</button> : <span className="muted">—</span>}</td><td className="mono"><button className="record-link" onClick={() => openCertificate(cert)} aria-label={`View certificate ${cert.serial_hex}`}>{shortId(cert.serial_hex)}</button></td><td><span className="row-state">{cert.state}</span></td><td>{displayDate(cert.signed_at)}</td><td className="mono" title={cert.fingerprint_sha256}>{shortId(cert.fingerprint_sha256)}</td></tr>)}</tbody></table></div>}{certificateCursor && (certificateMoreError ? <LoadFailure message={certificateMoreError} onRetry={() => void loadOlder('certificates')} /> : <button className="link-button pagination-action" disabled={certificateMoreLoading} onClick={() => void loadOlder('certificates')}>{certificateMoreLoading ? 'Loading…' : 'Load older certificates'}</button>)}</>}</div>}
              {section === 'audit' && <div className="detail-content"><div className="table-heading"><h3>Recent events</h3><span>{auditFilter.trim() ? `${filteredAuditEvents.length} of ${scopedAuditEvents.length} loaded records` : `${scopedAuditEvents.length} records loaded`}</span></div><form className="exact-lookup" onSubmit={event => { event.preventDefault(); if (auditFrom && auditUntil && auditFrom >= auditUntil) { setAuditFilterError('The end date must be after the start date.'); return; } if (auditEventType.trim().length > 128) { setAuditFilterError('Event type is too long.'); return; } const params = new URLSearchParams(); if (auditFrom) params.set('from', `${auditFrom}T00:00:00.000Z`); if (auditUntil) params.set('until', `${auditUntil}T00:00:00.000Z`); if (auditEventType.trim()) params.set('event_type', auditEventType.trim()); setAuditFilterError(null); setAuditQuery(params.toString()); }}><label>Filter the full audit history</label><div><input type="date" aria-label="From date inclusive" value={auditFrom} onChange={event => setAuditFrom(event.target.value)} /><input type="date" aria-label="Before date exclusive" value={auditUntil} onChange={event => setAuditUntil(event.target.value)} /><input type="search" aria-label="Exact event type" placeholder="Exact event type" value={auditEventType} onChange={event => setAuditEventType(event.target.value)} /><button type="submit">Apply</button>{auditQuery && <button type="button" onClick={() => { setAuditFrom(''); setAuditUntil(''); setAuditEventType(''); setAuditQuery(''); }}>Clear</button>}</div></form>{auditFilterError && <p className="lookup-error" role="alert">{auditFilterError}</p>}{auditQuery && <p className="lookup-result">Server filters are active for this authority’s full audit history.</p>}<form className="exact-lookup" onSubmit={event => { event.preventDefault(); void findAuditEvent(); }}><label htmlFor="audit-event-lookup">Find an event by exact ID across this authority's history</label><div><input id="audit-event-lookup" type="search" value={auditLookupInput} onChange={event => { auditLookupController.current?.abort(); setAuditLookupLoading(false); setAuditLookupInput(event.target.value); setAuditLookupResult(null); setAuditLookupError(null); }} placeholder="Event UUID" aria-describedby={auditLookupError ? 'audit-lookup-error' : undefined} /><button type="submit" disabled={auditLookupLoading}>{auditLookupLoading ? 'Finding…' : 'Find'}</button></div></form>{auditLookupError && <p id="audit-lookup-error" className="lookup-error" role="alert">{auditLookupError}</p>}{auditLookupResult?.ca_id === selectedCaId && <p className="lookup-result">Found event <span className="mono">{auditLookupResult.event_id}</span> <button className="link-button" onClick={() => openAuditEvent(auditLookupResult)}>View detail</button></p>}{auditLoading ? <LoadingRows /> : auditError ? <LoadFailure message={auditError} onRetry={() => setAuditReload(value => value + 1)} /> : scopedAuditEvents.length === 0 ? <EmptyDetail title="No audit events recorded" detail="No events are available for this authority in the laboratory database." /> : <><label className="filter-field"><span>Sort loaded audit events</span><select value={auditSort} onChange={event => setAuditSort(event.target.value as AuditSort)}><option value="newest">Newest recorded first</option><option value="oldest">Oldest recorded first</option><option value="type">Event type A–Z</option><option value="decision">Decision A–Z</option></select></label><label className="filter-field"><span>Filter loaded audit events</span><input type="search" value={auditFilter} onChange={event => setAuditFilter(event.target.value)} placeholder="Event ID, type, decision or policy" /></label>{filteredAuditEvents.length === 0 ? <p className="filter-empty">No matching event among loaded records.</p> : <div className="timeline">{sortedAuditEvents.map(event => <div className="timeline-item" key={event.event_id}><span className="timeline-dot" /><div><button className="record-link" onClick={() => openAuditEvent(event)} aria-label={`View audit event ${event.event_id}`}>{event.event_type}</button><p>{event.decision}</p><small>{displayDate(event.recorded_at)} · Policy {event.policy_version ?? 'not recorded'}</small></div></div>)}</div>}{auditCursor && (auditMoreError ? <LoadFailure message={auditMoreError} onRetry={() => void loadOlder('audit')} /> : <button className="link-button pagination-action" disabled={auditMoreLoading} onClick={() => void loadOlder('audit')}>{auditMoreLoading ? 'Loading…' : 'Load older audit events'}</button>)}</>}</div>}
            </>}
          </div></div>}
        </>}
      </main>
      {selectedCertificate?.ca_id === selectedCaId && section === 'certificates' && (scopedCertificates.some(cert => cert.request_id === selectedCertificate.request_id) || lookupResult?.request_id === selectedCertificate.request_id) && <CertificateDialog certificate={selectedCertificate} onClose={closeDetail} />}
      {selectedAuditEvent?.ca_id === selectedCaId && section === 'audit' && (scopedAuditEvents.some(event => event.event_id === selectedAuditEvent.event_id) || auditLookupResult?.event_id === selectedAuditEvent.event_id) && <AuditDialog event={selectedAuditEvent} onClose={closeDetail} />}
    </div>
  </div>;
}

function MetadataDialog({ titleId, title, eyebrow, fields, copyJson, note, onClose }: { titleId: string; title: string; eyebrow: string; fields: { label: string; value: string; copyable?: boolean }[]; copyJson: string; note: string; onClose: () => void }) {
  const dialog = useRef<HTMLDialogElement>(null);
  const [copyFeedback, setCopyFeedback] = useState('');
  async function copyValue(label: string, value: string, visible = true) {
    try {
      await navigator.clipboard.writeText(value);
      setCopyFeedback(`${label} copied.`);
    } catch {
      setCopyFeedback(visible ? `Could not copy ${label}. Select the value to copy it manually.` : `Could not copy ${label}.`);
    }
  }
  useEffect(() => {
    const element = dialog.current;
    element?.showModal();
    return () => element?.close();
  }, []);
  return <dialog ref={dialog} className="certificate-dialog" aria-labelledby={titleId} onClose={onClose}>
    <div className="dialog-heading"><div><div className="eyebrow">{eyebrow}</div><h2 id={titleId}>{title}</h2></div><button type="button" className="dialog-close" aria-label={`Close ${title.toLowerCase()}`} onClick={() => dialog.current?.close()}><span aria-hidden="true">×</span></button></div>
    <div className="detail-grid">{fields.map(field => <div className="info-cell" key={field.label}><span>{field.label}</span><div className="metadata-value"><strong>{field.value}</strong>{field.copyable && <button type="button" className="link-button" aria-label={`Copy ${field.label.toLowerCase()}`} onClick={() => void copyValue(field.label, field.value)}>Copy</button>}</div></div>)}</div>
    <button type="button" className="metadata-copy-json" onClick={() => void copyValue('metadata JSON', copyJson, false)}>Copy metadata JSON</button>
    {copyFeedback && <p className="copy-feedback" role="status">{copyFeedback}</p>}
    <p className="dialog-note">{note}</p>
  </dialog>;
}

function CertificateDialog({ certificate, onClose }: { certificate: Certificate; onClose: () => void }) {
  return <MetadataDialog titleId="certificate-dialog-title" title="Certificate detail" eyebrow="CERTIFICATE METADATA" onClose={onClose}
    copyJson={certificateMetadataJson(certificate)}
    fields={[{ label: 'CN', value: certificate.subject_cn || 'Not recorded' }, { label: 'SERIAL', value: certificate.serial_hex, copyable: true }, { label: 'FINGERPRINT SHA-256', value: certificate.fingerprint_sha256, copyable: true }, { label: 'REQUEST ID', value: certificate.request_id, copyable: true }, { label: 'STATE', value: certificate.state }, { label: 'SIGNED', value: displayDate(certificate.signed_at) }, { label: 'PUBLISHED', value: displayDate(certificate.published_at) }]}
    note="Database metadata only. Certificate contents and cryptographic validity are not shown or verified here." />;
}

function AuditDialog({ event, onClose }: { event: AuditEvent; onClose: () => void }) {
  return <MetadataDialog titleId="audit-dialog-title" title="Audit event detail" eyebrow="AUDIT METADATA" onClose={onClose}
    copyJson={auditMetadataJson(event)}
    fields={[{ label: 'EVENT ID', value: event.event_id, copyable: true }, { label: 'EVENT TYPE', value: event.event_type }, { label: 'DECISION', value: event.decision }, { label: 'POLICY VERSION', value: event.policy_version ?? 'Not recorded' }, { label: 'RECORDED', value: displayDate(event.recorded_at) }]}
    note="Database metadata only. This view does not include actor identity or independent audit integrity proof." />;
}

function Metric({ label, value, detail, icon }: { label: string; value: string; detail: string; icon: string }) {
  return <div className="metric"><div className="metric-top"><span>{label}</span><span className="metric-icon">{icon}</span></div><strong>{value}</strong><small>{detail}</small></div>;
}

function AuthorityList({ cas, selectedCaId, onSelect, compact = false }: { cas: CertificateAuthority[]; selectedCaId: string | null; onSelect: (id: string) => void; compact?: boolean }) {
  return <div className={compact ? 'authority-list compact' : 'authority-list'}>{cas.map(ca => <button key={ca.ca_id} className={ca.ca_id === selectedCaId ? 'authority-row selected' : 'authority-row'} aria-pressed={ca.ca_id === selectedCaId} onClick={() => onSelect(ca.ca_id)}><span className="ca-emblem">◇</span><span className="ca-text"><strong>{ca.display_name}</strong><small>{shortId(ca.ca_id)} · Policy {ca.policy_version}</small></span><span className="row-arrow">→</span></button>)}</div>;
}

function Info({ label, value }: { label: string; value: string }) {
  return <div className="info-cell"><span>{label}</span><strong>{value}</strong></div>;
}

function LoadingRows() { return <div className="loading-detail"><span className="spinner" /> Loading records…</div>; }
function LoadFailure({ message, onRetry }: { message: string; onRetry: () => void }) {
  return <div className="notice error" role="alert">{message} <button onClick={onRetry}>Retry</button></div>;
}
function EmptyDetail({ title, detail }: { title: string; detail: string }) { return <div className="empty-detail"><div>□</div><strong>{title}</strong><p>{detail}</p></div>; }
