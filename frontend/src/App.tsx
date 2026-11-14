import { Fragment, useEffect, useMemo, useRef, useState } from 'react';
import type { User } from 'oidc-client-ts';
import { ApiError, apiGet, apiGetPage, type AuditEvent, type Certificate, type CertificateAuthority } from './api';
import { sortLoadedAuditEvents, type AuditSort } from './audit-sort';
import { prepareAuditQuery } from './audit-query';
import { filterLoadedCertificates } from './certificate-filter';
import { sortLoadedCertificates, type CertificateSort } from './certificate-sort';
import { recordedValidityStatus } from './certificate-validity';
import { normalizeLiteralPrefix, validLiteralPrefix } from './literal-prefix';
import { auditMetadataJson, certificateMetadataJson } from './metadata-copy';
import { navGroupOf, navigationUrl, readNavigation, visibleNavGroups, type DetailLink, type NavGroupId, type Section } from './navigation';
import { oidcConfigurationError, userManager } from './oidc';
import { appendUniquePage, requireAdvancingCursor } from './pagination';
import { requireExactRecord, requireScopedRows, visibleScopedRows } from './scope';
import { auditCsv, certificateCsv, MAX_CSV_ROWS } from './selected-csv';
import { canonicalSerialHex } from './serial';
import { canonicalUuid } from './uuid';
import { ProfileDraftPanel } from './ProfileDraftPanel';
import { CaProposalPanel } from './CaProposalPanel';
import { OverviewDashboard } from './OverviewDashboard';
import { applyTheme, nextTheme, storedTheme, type ThemeChoice } from './theme';
import { CopyJsonButton, DetailDrawer, DrawerSection, Fact } from './DetailDrawer';
import { CATEGORY_LABELS, describeEvent, explainOutcome, outcomeGroup, type EventCategory, type OutcomeGroup } from './labels';
import { dayLabel, lifetimeElapsed } from './dashboard';
import { CommandPalette, type PaletteItem } from './CommandPalette';
import { reasonName } from './RequestsPanel';
import { RequestsPanel } from './RequestsPanel';
import { CrlPanel } from './CrlPanel';
import { RaPolicyPanel } from './RaPolicyPanel';
import { CA_ADMINISTRATOR_ROLE, CA_APPROVER_ROLE, CA_READER_ROLE, CERTIFICATE_REQUESTER_ROLE, REGISTRATION_OFFICER_ROLE, readOnlyRoles, tokenRoles } from './roles';
import { addWithin, headerState, toggleOne, toggleVisible } from './selection';
import { Disclosure, EventLabel, FilterChips, Toaster, HeaderCheckbox, Icon, Notice, OutcomeBadge, StatusBadge, Tag, TimeAgo, type IconName } from './ui';

const isMac = typeof navigator !== 'undefined' && /Mac|iPhone|iPad/u.test(navigator.platform || navigator.userAgent);

function displayDate(value: string | null): string {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? value : date.toLocaleString();
}

function shortId(value: string): string {
  return value.length <= 16 ? value : `${value.slice(0, 8)}…${value.slice(-4)}`;
}

// Sidebar icon of each PKI component group.
const GROUP_ICONS: Record<NavGroupId, IconName> = { supervision: 'overview', ca: 'authority', ra: 'request', va: 'revocation' };

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
  const [sanSearchInput, setSanSearchInput] = useState('');
  const [sanSearchTerm, setSanSearchTerm] = useState<string | null>(null);
  const [sanSearchError, setSanSearchError] = useState<string | null>(null);
  const [expiryBeforeInput, setExpiryBeforeInput] = useState('');
  const [expiryBeforeTerm, setExpiryBeforeTerm] = useState<string | null>(null);
  const [certificateSort, setCertificateSort] = useState<CertificateSort>('newest');
  const certificateOrder = certificateSort === 'oldest' ? 'oldest' : 'newest';
  const [lookupInput, setLookupInput] = useState('');
  const [lookupResult, setLookupResult] = useState<Certificate | null>(null);
  const [lookupError, setLookupError] = useState<string | null>(null);
  const [lookupLoading, setLookupLoading] = useState(false);
  const lookupController = useRef<AbortController | null>(null);
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [selectedAuditEvent, setSelectedAuditEvent] = useState<AuditEvent | null>(null);
  const [auditFilter, setAuditFilter] = useState('');
  const [auditCategory, setAuditCategory] = useState<'all' | EventCategory>('all');
  const [auditOutcome, setAuditOutcome] = useState<'all' | OutcomeGroup>('all');
  const [auditFrom, setAuditFrom] = useState('');
  const [auditUntil, setAuditUntil] = useState('');
  const [auditEventType, setAuditEventType] = useState('');
  const [auditDecision, setAuditDecision] = useState('');
  const [auditPolicyVersion, setAuditPolicyVersion] = useState('');
  const [auditQuery, setAuditQuery] = useState('');
  const [auditFilterError, setAuditFilterError] = useState<string | null>(null);
  const [auditSort, setAuditSort] = useState<AuditSort>('newest');
  const auditOrder = auditSort === 'oldest' ? 'oldest' : 'newest';
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
  const [selectedCertificateIds, setSelectedCertificateIds] = useState<string[]>([]);
  const [selectedAuditIds, setSelectedAuditIds] = useState<string[]>([]);
  const [validityClock, setValidityClock] = useState(() => Date.now());
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [collapsedGroups, setCollapsedGroups] = useState<NavGroupId[]>([]);
  const [theme, setTheme] = useState<ThemeChoice>(() => storedTheme());
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') { event.preventDefault(); setPaletteOpen(value => !value); }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  useEffect(() => {
    const timer = window.setInterval(() => setValidityClock(Date.now()), 60_000);
    return () => window.clearInterval(timer);
  }, []);

  const clearSession = () => {
    setUser(null);
    setCas([]);
    setCaQuery(null);
    setCaSearchInput('');
    setSelectedCaId(null);
    caLookupController.current?.abort();
    setCaLookupResult(null);
    setCertificates([]);
    setSelectedCertificateIds([]);
    setSelectedCertificate(null);
    lookupController.current?.abort();
    setLookupResult(null);
    setAuditEvents([]);
    setSelectedAuditIds([]);
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
    // Only readers list authorities; other roles never see a refused read.
    if (!tokenRoles(user.access_token).includes(CA_READER_ROLE)) {
      setCasLoading(false);
      setNavigationReady(true);
      return () => controller.abort();
    }
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
    if (routeDetail.kind === 'profile') return; // ProfileDraftPanel owns its exact revision read.
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
    const params = new URLSearchParams({ order: certificateOrder });
    if (cnSearchTerm) params.set('cn', cnSearchTerm);
    if (sanSearchTerm) params.set('san_dns', sanSearchTerm);
    if (expiryBeforeTerm) params.set('not_after_before', `${expiryBeforeTerm}T00:00:00.000Z`);
    void apiGetPage<Certificate>(`/v1/cas/${encodeURIComponent(selectedCaId)}/certificates?${params}`, user.access_token, controller.signal)
      .then(page => {
        if (controller.signal.aborted) return;
        setCertificates(requireScopedRows(page.items, selectedCaId));
        setCertificateCursor(page.nextCursor);
      })
      .catch(error => { if (!controller.signal.aborted) handleReadError(error, 'Could not load certificates.', setCertificateError); })
      .finally(() => { if (!controller.signal.aborted) setCertificateLoading(false); });
    return () => controller.abort();
  }, [user, selectedCaId, reload, certificateReload, cnSearchTerm, sanSearchTerm, expiryBeforeTerm, certificateOrder]);

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
    const query = auditQuery ? `${auditQuery}&order=${auditOrder}` : `order=${auditOrder}`;
    void apiGetPage<AuditEvent>(`/v1/cas/${encodeURIComponent(selectedCaId)}/audit?${query}`, user.access_token, controller.signal)
      .then(page => {
        if (controller.signal.aborted) return;
        setAuditEvents(requireScopedRows(page.items, selectedCaId));
        setAuditCursor(page.nextCursor);
      })
      .catch(error => { if (!controller.signal.aborted) handleReadError(error, 'Could not load audit events.', setAuditError); })
      .finally(() => { if (!controller.signal.aborted) setAuditLoading(false); });
    return () => controller.abort();
  }, [user, selectedCaId, reload, auditReload, auditQuery, auditOrder]);

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
      const search = kind === 'certificates'
        ? `${cnSearchTerm ? `&cn=${encodeURIComponent(cnSearchTerm)}` : ''}${sanSearchTerm ? `&san_dns=${encodeURIComponent(sanSearchTerm)}` : ''}${expiryBeforeTerm ? `&not_after_before=${encodeURIComponent(`${expiryBeforeTerm}T00:00:00.000Z`)}` : ''}&order=${certificateOrder}`
        : `${auditQuery ? `&${auditQuery}` : ''}&order=${auditOrder}`;
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
    setSanSearchInput('');
    setSanSearchTerm(null);
    setSanSearchError(null);
    setExpiryBeforeInput('');
    setExpiryBeforeTerm(null);
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
    setAuditDecision(''); setAuditPolicyVersion('');
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
    return scopedAuditEvents.filter(event => (!query || [event.event_id, event.event_type, describeEvent(event.event_type).label, event.decision, event.policy_version ?? ''].some(value => value.toLowerCase().includes(query)))
      && (auditCategory === 'all' || describeEvent(event.event_type).category === auditCategory)
      && (auditOutcome === 'all' || outcomeGroup(event.decision) === auditOutcome));
  }, [scopedAuditEvents, auditFilter, auditCategory, auditOutcome]);
  const auditCategoryCounts = useMemo(() => {
    const counts = new Map<EventCategory, number>();
    for (const event of scopedAuditEvents) { const category = describeEvent(event.event_type).category; counts.set(category, (counts.get(category) ?? 0) + 1); }
    return counts;
  }, [scopedAuditEvents]);
  const auditOutcomeCounts = useMemo(() => {
    const counts = new Map<OutcomeGroup, number>();
    for (const event of scopedAuditEvents) { const group = outcomeGroup(event.decision); counts.set(group, (counts.get(group) ?? 0) + 1); }
    return counts;
  }, [scopedAuditEvents]);
  const sortedAuditEvents = useMemo(() => sortLoadedAuditEvents(filteredAuditEvents, auditSort), [filteredAuditEvents, auditSort]);
  const selectedCertificateRows = sortedCertificates.filter(cert => selectedCertificateIds.includes(cert.request_id));
  const selectedAuditRows = sortedAuditEvents.filter(event => selectedAuditIds.includes(event.event_id));
  useEffect(() => setSelectedCertificateIds([]), [user, selectedCaId, reload, cnSearchTerm, sanSearchTerm, expiryBeforeTerm, certificateOrder]);
  useEffect(() => setSelectedAuditIds([]), [user, selectedCaId, reload, auditQuery, auditOrder]);
  const filteredCas = useMemo(() => {
    const query = caFilter.trim().toLowerCase();
    return query ? cas.filter(ca => [ca.ca_id, ca.display_name, ca.policy_version].some(value => value.toLowerCase().includes(query))) : cas;
  }, [cas, caFilter]);
  const selectedCa = useMemo(() => cas.find(ca => ca.ca_id === selectedCaId) ?? (caLookupResult?.ca_id === selectedCaId ? caLookupResult : null), [cas, caLookupResult, selectedCaId]);
  const name = user?.profile.preferred_username ?? user?.profile.name ?? user?.profile.sub ?? 'Operator';
  const readOnly = !user || readOnlyRoles(tokenRoles(user.access_token));

  function toggleExportRow(kind: 'certificate' | 'audit', id: string) {
    const update = (current: string[]) => toggleOne(id, current, MAX_CSV_ROWS);
    if (kind === 'certificate') setSelectedCertificateIds(update);
    else setSelectedAuditIds(update);
  }

  function selectRows(kind: 'certificate' | 'audit', mode: 'toggle-visible' | 'all-filtered') {
    const ids = kind === 'certificate' ? sortedCertificates.map(cert => cert.request_id) : sortedAuditEvents.map(event => event.event_id);
    const update = (current: string[]) => mode === 'toggle-visible' ? toggleVisible(ids, current, MAX_CSV_ROWS) : addWithin(current, ids, MAX_CSV_ROWS);
    if (kind === 'certificate') setSelectedCertificateIds(update);
    else setSelectedAuditIds(update);
  }

  function downloadSelectedCsv(kind: 'certificate' | 'audit') {
    if (!user || user.expired || !selectedCaId) return;
    const rows = kind === 'certificate' ? selectedCertificateRows : selectedAuditRows;
    if (rows.length === 0 || rows.length > MAX_CSV_ROWS) return;
    const content = kind === 'certificate' ? certificateCsv(selectedCertificateRows) : auditCsv(selectedAuditRows);
    const url = URL.createObjectURL(new Blob(['\uFEFF', content], { type: 'text/csv;charset=utf-8' }));
    const link = document.createElement('a');
    link.href = url;
    link.download = `trust-${kind}-${selectedCaId}.csv`;
    document.body.append(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 0);
  }

  function searchAuthorities() {
    const query = normalizeLiteralPrefix(caSearchInput);
    if (!validLiteralPrefix(query)) {
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
        <p>Sign in with your organization account. What you can see and do follows your roles and the grants of each authority.</p>
        {(oidcConfigurationError || sessionError) && <div className="notice error" role="alert">{oidcConfigurationError || sessionError}</div>}
        <button className="primary-button" disabled={!userManager} onClick={() => {
          const destination = readNavigation(window.location.search);
          void userManager?.signinRedirect({ state: navigationUrl(destination.section, destination.caId, destination.detail).slice(1) })
            .catch(() => setSessionError('OIDC sign-in could not start. Check the configured identity provider.'));
        }}>
          Sign in with your organization <span aria-hidden="true">↗</span>
        </button>
        <div className="login-footnote">You sign in on your identity provider’s page; this console never sees your password.</div>
      </div>
      <div className="login-footer">PRIVATE LABORATORY SYSTEM · NOT A PRODUCTION TRUST SERVICE</div>
    </div>;
  }

  const roles = tokenRoles(user.access_token);
  const isReader = roles.includes(CA_READER_ROLE);
  const isRequester = roles.includes(CERTIFICATE_REQUESTER_ROLE);
  const isOfficer = roles.includes(REGISTRATION_OFFICER_ROLE);
  const isCaAdmin = roles.includes(CA_ADMINISTRATOR_ROLE);
  const isCaApprover = roles.includes(CA_APPROVER_ROLE);
  const navItems: { id: Section; label: string; icon: IconName; show: boolean; count?: string }[] = [
    { id: 'overview', label: 'Overview', icon: 'overview', show: true },
    { id: 'authorities', label: 'Authorities', icon: 'authority', show: isReader || isCaAdmin || isCaApprover, count: isReader ? `${cas.length}${caCursor ? '+' : ''}` : undefined },
    { id: 'profiles', label: 'Profiles', icon: 'profile', show: isReader },
    { id: 'requests', label: 'Requests', icon: 'request', show: isRequester || isOfficer },
    { id: 'certificates', label: 'Certificates', icon: 'certificate', show: isReader },
    { id: 'revocation', label: 'Revocation & CRLs', icon: 'revocation', show: isReader },
    { id: 'channels', label: 'RA channel', icon: 'key', show: isReader },
    { id: 'audit', label: 'Audit trail', icon: 'audit', show: isReader },
  ];
  const navGroups = visibleNavGroups(navItems.filter(item => item.show).map(item => item.id));
  const activeGroup = navGroupOf(section);
  const activeGroupLabel = navGroups.find(group => group.id === activeGroup)?.label;
  const paletteItems: PaletteItem[] = [
    ...navItems.filter(item => item.show).map(item => ({ id: `section-${item.id}`, group: navGroups.find(group => group.id === navGroupOf(item.id))?.label ?? 'Sections', label: item.label, icon: item.icon, hint: section === item.id ? 'Current' : undefined, run: () => setSection(item.id) })),
    ...cas.map(ca => ({ id: `ca-${ca.ca_id}`, group: 'Authorities', label: ca.display_name, icon: 'authority' as IconName, hint: `${shortId(ca.ca_id)} · ${ca.policy_version}`, run: () => { setSelectedCaId(ca.ca_id); if (section === 'overview') setSection('authorities'); } })),
  ];
  const headings: Record<Section, [string, string]> = {
    overview: [`Welcome, ${name}.`, 'What needs your attention and how the selected authority is doing.'],
    authorities: ['Certificate authorities', 'Authorities in your scope and, for CA administrators and approvers, the CA lifecycle.'],
    profiles: ['Profile proposals', 'Certificate-profile revisions of the selected authority and their approval workflow.'],
    requests: ['Certificate requests', 'Submit, decide, issue and revoke certificates of the selected authority.'],
    certificates: ['Certificate inventory', 'Issued certificate metadata of the selected authority.'],
    revocation: ['Revocation & CRLs', 'CRL status, publication and history of the selected authority.'],
    channels: ['RA channel & policies', 'RA systems, their quotas, zones and keys, and the short-lived profiles of the selected authority (read-only).'],
    audit: ['Audit trail', 'Recorded events of the selected authority.'],
  };
  const needsAuthority = section !== 'overview' && !(section === 'authorities' && !isReader);
  const certificateServerFilters = [cnSearchTerm, sanSearchTerm, expiryBeforeTerm].filter(Boolean).length;
  const certificateHeader = headerState(sortedCertificates.map(cert => cert.request_id), selectedCertificateIds);
  const auditHeader = headerState(sortedAuditEvents.map(event => event.event_id), selectedAuditIds);

  function selectionBar(kind: 'certificate' | 'audit', selected: number, filtered: number) {
    const noun = kind === 'certificate' ? 'certificates' : 'events';
    return <div className="ui-selection-bar">
      <span>{selected > 0 ? <><strong>{selected}</strong> selected</> : `Select ${noun} to export them (up to ${MAX_CSV_ROWS}).`}</span>
      {filtered > selected && <button type="button" className="ui-button ui-button-ghost ui-button-sm" onClick={() => selectRows(kind, 'all-filtered')}>Select all {Math.min(filtered, MAX_CSV_ROWS)} {auditFilter.trim() || certificateFilter.trim() ? 'filtered' : 'loaded'}</button>}
      {selected > 0 && <button type="button" className="ui-button ui-button-ghost ui-button-sm" onClick={() => kind === 'certificate' ? setSelectedCertificateIds([]) : setSelectedAuditIds([])}>Clear selection</button>}
      <button type="button" className="ui-button ui-button-secondary ui-button-sm ui-push-right" disabled={selected === 0} onClick={() => downloadSelectedCsv(kind)}><Icon name="download" size={15} />Export selected CSV</button>
    </div>;
  }

  return <div className="app-shell">
    <aside className="sidebar">
      <div className="brand"><div className="brand-mark">S</div><span>SOVEREIGN<br /><b>TRUST</b></span></div>
      <div className="workspace-tag"><span className="status-dot" /> LAB WORKSPACE</div>
      <nav aria-label="Main navigation" className="nav">
        {navGroups.map(group => {
          const current = group.id === activeGroup;
          const open = current || !collapsedGroups.includes(group.id);
          return <div key={group.id} className={`nav-group${open ? '' : ' collapsed'}`}>
            <button type="button" className="nav-group-head" aria-expanded={open} aria-controls={`nav-group-${group.id}`}
              aria-disabled={current || undefined} title={current ? 'Contains the current page' : undefined}
              onClick={() => { if (!current) setCollapsedGroups(list => list.includes(group.id) ? list.filter(id => id !== group.id) : [...list, group.id]); }}>
              <Icon name={GROUP_ICONS[group.id]} /><span className="nav-text">{group.label}</span><span className="nav-chevron" aria-hidden="true"><Icon name="chevron" size={14} /></span>
            </button>
            <div className="nav-group-items" id={`nav-group-${group.id}`}>
              {group.sections.map(id => {
                const item = navItems.find(candidate => candidate.id === id)!;
                return <button key={id} className={`nav-item${section === id ? ' active' : ''}`} aria-current={section === id ? 'page' : undefined} onClick={() => setSection(id)}>
                  <span className="nav-text">{item.label}</span>{item.count !== undefined && <span className="nav-count" title={`${item.count} loaded`}>{item.count}</span>}
                </button>;
              })}
            </div>
          </div>;
        })}
      </nav>
      <div className="sidebar-bottom"><div className="sidebar-note">{readOnly ? <>Read-only access<br /><span>Your roles allow consultation only.</span></> : <>Laboratory access<br /><span>Actions follow your roles and the server-side grants of each authority; the API checks every request.</span></>}</div><div className="version">TRUST PLATFORM · V0.1 LAB</div></div>
    </aside>
    <div className="main-column">
      <header className="topbar"><div className="breadcrumb">Workspace <span>/</span> {activeGroupLabel && <span className="crumb-group">{activeGroupLabel} <span>/</span> </span>}{navItems.find(item => item.id === section)?.label}{needsAuthority && selectedCa && <><span>/</span> {selectedCa.display_name}</>}</div>
        <div className="top-actions"><button type="button" className="ui-search-trigger" onClick={() => setPaletteOpen(true)} aria-keyshortcuts="Control+K Meta+K"><Icon name="search" size={15} />Go to…<span className="ui-kbd">{isMac ? '⌘K' : 'Ctrl K'}</span></button><span className="read-badge">{readOnly ? 'READ ONLY' : 'LAB ACCESS'}</span>
          <button type="button" className="ui-icon-button" aria-label={`Theme: ${theme}. Switch to ${nextTheme(theme)}`} title={`Theme: ${theme} (click for ${nextTheme(theme)})`} onClick={() => { const next = nextTheme(theme); setTheme(next); applyTheme(next); }}><Icon name={theme === 'dark' ? 'moon' : theme === 'light' ? 'sun' : 'monitor'} /></button>
          <button className="ui-icon-button" title="Refresh data" aria-label="Refresh scoped data" onClick={() => setReload(value => value + 1)}><Icon name="refresh" /></button>
          <div className="ui-user"><div className="user-avatar" aria-hidden="true">{String(name).slice(0, 1).toUpperCase()}</div><span>{name}</span></div>
          <button className="ui-button ui-button-ghost ui-button-sm" onClick={() => void userManager?.signoutRedirect()}><Icon name="signOut" size={15} />Sign out</button></div></header>
      <main className="content">
        <div className="page-heading"><div>{activeGroupLabel && <div className="eyebrow nav-eyebrow">{activeGroupLabel}</div>}<h1>{headings[section][0]}</h1><p>{headings[section][1]}</p></div><div className="view-link-tools"><button type="button" className="ui-button ui-button-ghost ui-button-sm" disabled={!navigationReady} onClick={() => void copyViewLink()}><Icon name="link" size={15} />Copy view link</button>{viewLinkStatus && <span className="view-link-status" role="status">{viewLinkStatus}</span>}</div></div>
        {dataError && <Notice tone="error" action={<button className="ui-button ui-button-secondary ui-button-sm" onClick={() => setReload(value => value + 1)}>Retry</button>}>{dataError}</Notice>}
        {linkedCaError && <Notice tone="error" onDismiss={() => setLinkedCaError(null)}>{linkedCaError}</Notice>}
        {linkedDetailError && <Notice tone="error" onDismiss={() => setLinkedDetailError(null)}>{linkedDetailError}</Notice>}
        {casLoading && <div className="notice loading"><span className="spinner" /> Loading scoped authorities…</div>}

        {section === 'overview' && <>
          {selectedCa && user && <OverviewDashboard key={selectedCa.ca_id} ca={selectedCa} certificates={scopedCertificates} auditEvents={scopedAuditEvents} now={validityClock} token={user.access_token}
            isOfficer={isOfficer} isRequester={isRequester} isReader={isReader} onNavigate={setSection} onUnauthorized={rejectSession}
            certificatesComplete={!certificateCursor} auditComplete={!auditCursor} />}
          {selectedCa && <h2 className="ui-section-title">Shortcuts</h2>}
          <div className="ui-role-grid">
            {(isCaAdmin || isCaApprover) && <RoleCard icon="authority" title="CA lifecycle" text={isCaAdmin ? 'Propose authorities, register their roots, activate, suspend or retire them.' : 'Approve CA proposals and changes with your registered key.'} action="Open CA lifecycle" onOpen={() => setSection('authorities')} />}
            {isRequester && <RoleCard icon="request" title="Request certificates" text="Submit a CSR for an active profile, collect issued certificates and ask for revocation." action="Open requests" onOpen={() => setSection('requests')} />}
            {isOfficer && <RoleCard icon="check" title="Registration decisions" text="Approve or reject requests and revocations, issue certificates and publish CRLs." action="Open requests" onOpen={() => setSection('requests')} />}
            {isOfficer && <RoleCard icon="revocation" title="Publish CRLs" text="Check whether the CRL must be renewed and publish the next one." action="Open CRLs" onOpen={() => setSection('revocation')} />}
            {isReader && <RoleCard icon="audit" title="Audit trail" text="Review and export recorded events of an authority." action="Open audit trail" onOpen={() => setSection('audit')} />}
          </div>
          {isReader && !casLoading && cas.length === 0 && !dataError && !caQuery && <div className="empty-state"><div className="empty-icon"><Icon name="authority" size={30} /></div><h2>No authorities in your scope</h2><p>Ask an administrator to grant you a CA scope, then refresh this page.</p></div>}
          {isReader && (cas.length > 0 || caQuery) && <>
            <div className="section-head"><div><h2>Your authorities</h2><p>Choose an authority to inspect its records.</p></div><button className="ui-button ui-button-ghost ui-button-sm" onClick={() => setSection('authorities')}>View all authorities<Icon name="chevron" size={15} /></button></div>
            <label className="filter-field"><span>Filter loaded authorities</span><input type="search" value={caFilter} onChange={event => setCaFilter(event.target.value)} placeholder="Name, authority ID or policy" /></label>{filteredCas.length === 0 ? <p className="filter-empty">{caQuery && cas.length === 0 ? 'No authorized authority matches that name or policy prefix.' : 'No matching authority among loaded records.'}</p> : <AuthorityList cas={filteredCas} selectedCaId={selectedCaId} onSelect={id => { setSelectedCaId(id); setSection('authorities'); }} />}
            {caCursor && (caMoreError ? <LoadFailure message={caMoreError} onRetry={() => void loadMoreCas()} /> : <button className="ui-button ui-button-secondary pagination-action" disabled={caMoreLoading} onClick={() => void loadMoreCas()}>{caMoreLoading ? 'Loading…' : 'Load more authorities'}</button>)}
          </>}
        </>}

        {section === 'authorities' && (isCaAdmin || isCaApprover) && <div className="ui-block"><CaProposalPanel key={reload} token={user.access_token} canAdminister={isCaAdmin} canApprove={isCaApprover} onUnauthorized={rejectSession} /></div>}

        {needsAuthority && isReader && <div className="workspace-grid"><div className="authority-panel">
          <div className="panel-heading"><span>AUTHORITIES</span><span>{cas.length}{caCursor ? '+' : ''}</span></div>
          <label className="filter-field authority-filter"><span className="sr-only">Filter loaded authorities</span><input type="search" value={caFilter} onChange={event => setCaFilter(event.target.value)} placeholder="Filter by name, ID or policy" /></label>
          {filteredCas.length === 0 ? <p className="filter-empty">{cas.length === 0 ? 'No authorities loaded.' : 'No matching authority among loaded records.'}</p> : <AuthorityList cas={filteredCas} selectedCaId={selectedCaId} onSelect={setSelectedCaId} compact />}
          {caCursor && (caMoreError ? <LoadFailure message={caMoreError} onRetry={() => void loadMoreCas()} /> : <button className="ui-button ui-button-ghost ui-button-sm pagination-action" disabled={caMoreLoading} onClick={() => void loadMoreCas()}>{caMoreLoading ? 'Loading…' : 'Load more authorities'}</button>)}
          <details className="ui-disclosure authority-more"><summary>Search all authorities</summary>
            {authoritySearchForm('side-ca-search')}
            <form className="exact-lookup" onSubmit={event => { event.preventDefault(); void findAuthority(); }}><label htmlFor="authority-id-lookup">Go to an authority by exact ID</label><div><input id="authority-id-lookup" type="search" value={caLookupInput} onChange={event => { caLookupController.current?.abort(); setCaLookupLoading(false); setCaLookupInput(event.target.value); setCaLookupError(null); }} placeholder="Authority UUID" aria-describedby={caLookupError ? 'authority-lookup-error' : undefined} /><button type="submit" disabled={caLookupLoading}>{caLookupLoading ? 'Finding…' : 'Find'}</button></div></form>
            {caLookupError && <p id="authority-lookup-error" className="lookup-error" role="alert">{caLookupError}</p>}
            {caLookupResult && !cas.some(ca => ca.ca_id === caLookupResult.ca_id) && <p className="lookup-result">Selected: <button className="link-button" onClick={() => setSelectedCaId(caLookupResult.ca_id)}>{caLookupResult.display_name}</button></p>}
          </details>
        </div><div className="detail-panel">
          {!selectedCa && <EmptyDetail title="No authority selected" detail="Select an authority on the left, or search all authorities." />}
          {selectedCa && <><div className="detail-header"><div><div className="eyebrow">CERTIFICATE AUTHORITY</div><h2>{selectedCa.display_name}</h2><span className="mono muted">{selectedCa.ca_id}</span></div>{selectedCa.operational_state ? <StatusBadge status={selectedCa.operational_state} /> : <span className="state-pill">OWNER RECORD</span>}</div>
            {section === 'authorities' && <div className="detail-content"><div className="detail-grid"><Info label="POLICY VERSION" value={selectedCa.policy_version} /><Info label="CREATED" value={displayDate(selectedCa.created_at)} /><Info label="PARENT AUTHORITY" value={selectedCa.parent_ca_id ? shortId(selectedCa.parent_ca_id) : 'Root / not recorded'} /><Info label="AUTHORITY ID" value={shortId(selectedCa.ca_id)} /><Info label="OPERATIONAL STATE" value={selectedCa.operational_state ?? 'Not managed by the CA lifecycle'} /></div><p className="ui-hint ui-spaced">Database metadata only: this view does not assert that a CA certificate, signing key or policy publication has been independently verified.</p><div className="ui-actions"><button className="ui-button ui-button-secondary ui-button-sm" onClick={() => setSection('profiles')}><Icon name="profile" size={15} />Profiles</button>{(isRequester || isOfficer) && <button className="ui-button ui-button-secondary ui-button-sm" onClick={() => setSection('requests')}><Icon name="request" size={15} />Requests</button>}<button className="ui-button ui-button-secondary ui-button-sm" onClick={() => setSection('certificates')}><Icon name="certificate" size={15} />Certificates</button><button className="ui-button ui-button-secondary ui-button-sm" onClick={() => setSection('revocation')}><Icon name="revocation" size={15} />CRLs</button><button className="ui-button ui-button-secondary ui-button-sm" onClick={() => setSection('audit')}><Icon name="audit" size={15} />Audit trail</button></div></div>}
            {section === 'profiles' && (selectedCa?.operational_state === 'SUSPENDED' || selectedCa?.operational_state === 'RETIRED') && <div className="detail-content ui-tight"><Notice tone="warning">This authority is {selectedCa.operational_state}: its profile revisions cannot be activated{selectedCa.operational_state === 'RETIRED' ? ', and its active revisions were retired with it' : ' until it is reactivated'}.</Notice></div>}
            {section === 'profiles' && <ProfileDraftPanel key={`${selectedCaId}/${reload}`} caId={selectedCaId!} token={user.access_token} onUnauthorized={rejectSession} linkedDetail={routeDetail?.kind === 'profile' ? routeDetail : null} onOpenDetail={detail => setRouteDetail(detail)} onCloseDetail={closeDetail} />}
            {section === 'requests' && <div className="detail-content"><RequestsPanel key={`${selectedCaId}/${reload}`} caId={selectedCaId!} token={user.access_token} canRequest={isRequester} canDecide={isOfficer} onUnauthorized={rejectSession} /></div>}
            {section === 'channels' && <div className="detail-content"><RaPolicyPanel key={`${selectedCaId}/${reload}`} caId={selectedCaId!} token={user.access_token} onUnauthorized={rejectSession} /></div>}
            {section === 'revocation' && <div className="detail-content"><CrlPanel key={`${selectedCaId}/${reload}`} caId={selectedCaId!} token={user.access_token} canPublish={isOfficer} onUnauthorized={rejectSession} onOpenRequests={() => setSection('requests')} /></div>}
            {section === 'certificates' && <div className="detail-content">
              <div className="table-heading"><h3>Certificates</h3><span>{certificateFilter.trim() ? `${filteredCertificates.length} of ${scopedCertificates.length} loaded records` : `${scopedCertificates.length} records loaded`}</span></div>
              <div className="ui-toolbar">
                <label className="ui-field ui-field-grow"><span>Filter loaded certificates</span><input type="search" value={certificateFilter} onChange={event => setCertificateFilter(event.target.value)} placeholder="CN, serial, fingerprint, request ID or state" /></label>
                <label className="ui-field"><span>Sort loaded certificates</span><select value={certificateSort} onChange={event => setCertificateSort(event.target.value as CertificateSort)}><option value="newest">Newest signed first (all pages)</option><option value="oldest">Oldest signed first (all pages)</option><option value="cn">CN A–Z (loaded rows)</option><option value="serial">Serial hex A–Z (loaded rows)</option></select></label>
              </div>
              <Disclosure active={certificateServerFilters > 0} summary={<><Icon name="filter" size={15} />Search the full history{certificateServerFilters > 0 && ` (${certificateServerFilters} active)`}</>}><div className="ui-search-grid">
                <form className="exact-lookup" onSubmit={event => { event.preventDefault(); const query = normalizeLiteralPrefix(cnSearchInput); if (!validLiteralPrefix(query)) { setCnSearchError('Enter at least two and at most 255 CN characters.'); return; } setCnSearchError(null); setCnSearchTerm(query); }}><label htmlFor="certificate-cn-search">CN prefix</label><div><input id="certificate-cn-search" type="search" value={cnSearchInput} onChange={event => { setCnSearchInput(event.target.value); setCnSearchError(null); }} placeholder="First characters of a CN" aria-describedby={cnSearchError ? 'certificate-cn-search-error' : undefined} /><button type="submit">Search</button>{cnSearchTerm && <button type="button" onClick={() => { setCnSearchInput(''); setCnSearchTerm(null); }}>Clear</button>}</div>{cnSearchError && <p id="certificate-cn-search-error" className="lookup-error" role="alert">{cnSearchError}</p>}{cnSearchTerm && <p className="lookup-result">Showing CN prefix matches for <strong>{cnSearchTerm}</strong> across the authority’s history.</p>}</form>
                <form className="exact-lookup" onSubmit={event => { event.preventDefault(); const query = sanSearchInput.trim(); if (!/^[a-zA-Z0-9.*_-]{1,253}$/.test(query)) { setSanSearchError('Enter an exact ASCII DNS SAN (1–253 characters).'); return; } setSanSearchError(null); setSanSearchTerm(query); }}><label htmlFor="certificate-san-search">Exact DNS SAN</label><div><input id="certificate-san-search" type="search" value={sanSearchInput} onChange={event => { setSanSearchInput(event.target.value); setSanSearchError(null); }} placeholder="Exact DNS name" aria-describedby={sanSearchError ? 'certificate-san-search-error' : undefined} /><button type="submit">Search SAN</button>{sanSearchTerm && <button type="button" onClick={() => { setSanSearchInput(''); setSanSearchTerm(null); }}>Clear SAN</button>}</div>{sanSearchError && <p id="certificate-san-search-error" className="lookup-error" role="alert">{sanSearchError}</p>}{sanSearchTerm && <p className="lookup-result">Showing exact DNS SAN <strong>{sanSearchTerm}</strong> across the authority’s history. Historical records without verified SAN metadata are excluded.</p>}</form>
                <form className="exact-lookup" onSubmit={event => { event.preventDefault(); setExpiryBeforeTerm(expiryBeforeInput || null); }}><label htmlFor="certificate-expiry-before">Valid until before (UTC, exclusive)</label><div><input id="certificate-expiry-before" type="date" value={expiryBeforeInput} onChange={event => setExpiryBeforeInput(event.target.value)} /><button type="submit">Apply date</button>{expiryBeforeTerm && <button type="button" onClick={() => { setExpiryBeforeInput(''); setExpiryBeforeTerm(null); }}>Clear date</button>}</div>{expiryBeforeTerm && <p className="lookup-result">Showing certificates with a recorded valid-until before <strong>{expiryBeforeTerm} UTC</strong>. Unknown dates are excluded; this is not a trust or revocation check.</p>}</form>
                <form className="exact-lookup" onSubmit={event => { event.preventDefault(); void findCertificate(); }}><label htmlFor="certificate-request-lookup">Request ID or serial</label><div><input id="certificate-request-lookup" type="search" value={lookupInput} onChange={event => { lookupController.current?.abort(); setLookupLoading(false); setLookupInput(event.target.value); setLookupResult(null); setLookupError(null); }} placeholder="Request UUID or serial hex" aria-describedby={lookupError ? 'certificate-lookup-error' : undefined} /><button type="submit" disabled={lookupLoading}>{lookupLoading ? 'Finding…' : 'Find'}</button></div>{lookupError && <p id="certificate-lookup-error" className="lookup-error" role="alert">{lookupError}</p>}{lookupResult?.ca_id === selectedCaId && <p className="lookup-result">Found serial <span className="mono">{lookupResult.serial_hex}</span> <button type="button" className="link-button" onClick={() => openCertificate(lookupResult)}>View detail</button></p>}</form>
              </div></Disclosure>
              {certificateLoading ? <LoadingRows /> : certificateError ? <LoadFailure message={certificateError} onRetry={() => setCertificateReload(value => value + 1)} /> : scopedCertificates.length === 0 ? <EmptyDetail title="No certificates recorded" detail="No certificate metadata matches the active server filters in this authority, or no certificates are recorded." /> : filteredCertificates.length === 0 ? <p className="filter-empty">No matching certificate among loaded records. Search the full history above.</p> : <>
                {selectionBar('certificate', selectedCertificateRows.length, sortedCertificates.length)}
                <div className="table-wrap"><table className="certificate-table ui-table"><thead><tr><th className="selection-column"><HeaderCheckbox state={certificateHeader} label="Select all visible certificates" onChange={() => selectRows('certificate', 'toggle-visible')} /></th><th>Common name</th><th>Serial</th><th>State</th><th>Recorded period</th><th>Signed</th><th>SHA-256</th></tr></thead><tbody>{sortedCertificates.map(cert => <tr key={cert.request_id} className={[selectedCertificateIds.includes(cert.request_id) ? 'ui-row-selected' : '', cert.revoked_at ? 'ui-row-revoked' : ''].filter(Boolean).join(' ') || undefined}><td><input type="checkbox" aria-label={`Select certificate ${cert.serial_hex} for CSV export`} checked={selectedCertificateIds.includes(cert.request_id)} disabled={!selectedCertificateIds.includes(cert.request_id) && selectedCertificateIds.length >= MAX_CSV_ROWS} onChange={() => toggleExportRow('certificate', cert.request_id)} /></td><td className="certificate-cn" title={cert.subject_cn ?? 'CN not recorded'}>{cert.subject_cn ? <button className="record-link" onClick={() => openCertificate(cert)} aria-label={`View certificate for ${cert.subject_cn}`}>{cert.subject_cn}</button> : <span className="muted">—</span>}</td><td className="mono"><button className="record-link" onClick={() => openCertificate(cert)} aria-label={`View certificate ${cert.serial_hex}`}>{shortId(cert.serial_hex)}</button></td><td>{cert.revoked_at ? <><StatusBadge status="REVOKED" /><div className="ui-sub ui-nowrap" title={displayDate(cert.revoked_at)}>{reasonName(cert.revocation_reason ?? null)} · {new Date(cert.revoked_at).toLocaleDateString()}</div></> : <StatusBadge status={cert.state} />}</td><td>{(() => { const period = recordedValidityStatus(cert, validityClock); return <Tag tone={period === 'Within period' ? 'good' : period === 'Period ended' ? 'bad' : period === 'Not yet in period' ? 'info' : 'neutral'} title="Based only on recorded X.509 dates; this is not a trust or revocation check">{period}</Tag>; })()}{(() => { const elapsed = lifetimeElapsed(cert, validityClock); return elapsed === null ? null : <div className={`ui-life${elapsed >= 1 ? ' ended' : elapsed > 0.85 ? ' late' : ''}`} title={`${Math.round(elapsed * 100)}% of the recorded lifetime elapsed`}><span style={{ width: `${Math.max(2, elapsed * 100)}%` }} /></div>; })()}</td><td className="ui-nowrap">{cert.signed_at ? <TimeAgo value={cert.signed_at} now={new Date(validityClock)} /> : <span className="ui-sub">Not signed</span>}</td><td className="mono" title={cert.fingerprint_sha256}>{shortId(cert.fingerprint_sha256)}</td></tr>)}</tbody></table></div>
                <p className="ui-hint">State shows a recorded revocation first, then the issuance state. Relying parties learn of a revocation from the next published CRL.</p>
              </>}
              {certificateCursor && (certificateMoreError ? <LoadFailure message={certificateMoreError} onRetry={() => void loadOlder('certificates')} /> : <button className="ui-button ui-button-secondary ui-button-sm pagination-action" disabled={certificateMoreLoading} onClick={() => void loadOlder('certificates')}>{certificateMoreLoading ? 'Loading…' : 'Load older certificates'}</button>)}
            </div>}
            {section === 'audit' && <div className="detail-content">
              <div className="table-heading"><h3>Recent events</h3><span>{auditFilter.trim() ? `${filteredAuditEvents.length} of ${scopedAuditEvents.length} loaded records` : `${scopedAuditEvents.length} records loaded`}</span></div>
              <div className="ui-toolbar">
                <label className="ui-field ui-field-grow"><span>Filter loaded audit events</span><input type="search" value={auditFilter} onChange={event => setAuditFilter(event.target.value)} placeholder="Event ID, type, decision or policy" /></label>
                <label className="ui-field"><span>Sort loaded audit events</span><select value={auditSort} onChange={event => setAuditSort(event.target.value as AuditSort)}><option value="newest">Newest recorded first (all pages)</option><option value="oldest">Oldest recorded first (all pages)</option><option value="type">Event type A–Z (loaded rows)</option><option value="decision">Decision A–Z (loaded rows)</option></select></label>
              </div>
              <div className="ui-chip-rows">
                <FilterChips label="Filter loaded events by outcome" value={auditOutcome} onChange={setAuditOutcome} options={[
                  { id: 'all', label: 'All outcomes', count: scopedAuditEvents.length },
                  { id: 'allowed', label: 'Allowed', count: auditOutcomeCounts.get('allowed') ?? 0, tone: 'good' },
                  { id: 'denied', label: 'Denied', count: auditOutcomeCounts.get('denied') ?? 0, tone: 'bad' },
                  { id: 'attention', label: 'Needs attention', count: auditOutcomeCounts.get('attention') ?? 0, tone: 'warn' },
                  { id: 'other', label: 'Results & transitions', count: auditOutcomeCounts.get('other') ?? 0, tone: 'neutral' },
                ]} />
                <FilterChips label="Filter loaded events by category" value={auditCategory} onChange={setAuditCategory} options={[
                  { id: 'all' as const, label: 'All categories', count: scopedAuditEvents.length },
                  ...(Object.keys(CATEGORY_LABELS) as EventCategory[]).filter(category => auditCategoryCounts.get(category)).map(category => ({ id: category, label: CATEGORY_LABELS[category], count: auditCategoryCounts.get(category) ?? 0 })),
                ]} />
              </div>
              <Disclosure active={Boolean(auditQuery)} summary={<><Icon name="filter" size={15} />Filter the full history{auditQuery && ' (active)'}</>}>
                <form className="exact-lookup" onSubmit={event => { event.preventDefault(); const result = prepareAuditQuery({ from: auditFrom, until: auditUntil, eventType: auditEventType, decision: auditDecision, policyVersion: auditPolicyVersion }); setAuditFilterError(result.error); if (result.query !== null) setAuditQuery(result.query); }}><label>Server-side filters</label><div className="ui-filter-row"><input type="date" aria-label="From date inclusive" value={auditFrom} onChange={event => setAuditFrom(event.target.value)} /><input type="date" aria-label="Before date exclusive" value={auditUntil} onChange={event => setAuditUntil(event.target.value)} /><input type="search" aria-label="Exact event type" placeholder="Exact event type" value={auditEventType} onChange={event => setAuditEventType(event.target.value)} /><input type="search" aria-label="Exact decision" placeholder="Exact decision" value={auditDecision} onChange={event => setAuditDecision(event.target.value)} /><input type="search" aria-label="Exact policy version" placeholder="Exact policy version" value={auditPolicyVersion} onChange={event => setAuditPolicyVersion(event.target.value)} /><button type="submit">Apply</button>{auditQuery && <button type="button" onClick={() => { setAuditFrom(''); setAuditUntil(''); setAuditEventType(''); setAuditDecision(''); setAuditPolicyVersion(''); setAuditQuery(''); }}>Clear</button>}</div></form>
                {auditFilterError && <p className="lookup-error" role="alert">{auditFilterError}</p>}{auditQuery && <p className="lookup-result">Server filters are active for this authority’s full audit history.</p>}
                <form className="exact-lookup" onSubmit={event => { event.preventDefault(); void findAuditEvent(); }}><label htmlFor="audit-event-lookup">Find an event by exact ID</label><div><input id="audit-event-lookup" type="search" value={auditLookupInput} onChange={event => { auditLookupController.current?.abort(); setAuditLookupLoading(false); setAuditLookupInput(event.target.value); setAuditLookupResult(null); setAuditLookupError(null); }} placeholder="Event UUID" aria-describedby={auditLookupError ? 'audit-lookup-error' : undefined} /><button type="submit" disabled={auditLookupLoading}>{auditLookupLoading ? 'Finding…' : 'Find'}</button></div></form>
                {auditLookupError && <p id="audit-lookup-error" className="lookup-error" role="alert">{auditLookupError}</p>}{auditLookupResult?.ca_id === selectedCaId && <p className="lookup-result">Found event <span className="mono">{auditLookupResult.event_id}</span> <button type="button" className="link-button" onClick={() => openAuditEvent(auditLookupResult)}>View detail</button></p>}
              </Disclosure>
              {auditLoading ? <LoadingRows /> : auditError ? <LoadFailure message={auditError} onRetry={() => setAuditReload(value => value + 1)} /> : scopedAuditEvents.length === 0 ? <EmptyDetail title="No audit events recorded" detail="No events match the active server filters, or no events are recorded for this authority." /> : filteredAuditEvents.length === 0 ? <p className="filter-empty">No matching event among loaded records.</p> : <>
                {selectionBar('audit', selectedAuditRows.length, sortedAuditEvents.length)}
                <div className="table-wrap"><table className="ui-table ui-table-compact" aria-label="Audit events"><thead><tr><th className="selection-column"><HeaderCheckbox state={auditHeader} label="Select all visible audit events" onChange={() => selectRows('audit', 'toggle-visible')} /></th><th>When</th><th>Event</th><th>Outcome</th><th>Policy</th></tr></thead>
                  <tbody>{sortedAuditEvents.map((event, index) => <Fragment key={event.event_id}>{(auditSort === 'newest' || auditSort === 'oldest') && (index === 0 || dayLabel(sortedAuditEvents[index - 1].recorded_at, new Date(validityClock)) !== dayLabel(event.recorded_at, new Date(validityClock))) && <tr className="ui-group-row" aria-hidden="true"><td colSpan={5}>{dayLabel(event.recorded_at, new Date(validityClock))}</td></tr>}<tr className={selectedAuditIds.includes(event.event_id) ? 'ui-row-selected ui-row-clickable' : 'ui-row-clickable'} onClick={clicked => { if (!(clicked.target as HTMLElement).closest('input, button, a')) openAuditEvent(event); }}><td><input type="checkbox" aria-label={`Select audit event ${event.event_id} for CSV export`} checked={selectedAuditIds.includes(event.event_id)} disabled={!selectedAuditIds.includes(event.event_id) && selectedAuditIds.length >= MAX_CSV_ROWS} onChange={() => toggleExportRow('audit', event.event_id)} /></td><td className="ui-nowrap"><TimeAgo value={event.recorded_at} now={new Date(validityClock)} /></td><td><button type="button" className="ui-row-button" onClick={() => openAuditEvent(event)} aria-label={`View audit event ${event.event_id}`}><EventLabel type={event.event_type} /></button></td><td><OutcomeBadge decision={event.decision} /></td><td>{event.policy_version ? <span className="ui-chip">{event.policy_version}</span> : <span className="ui-sub" title="No policy version recorded for this event">—<span className="sr-only">No policy version recorded</span></span>}</td></tr></Fragment>)}</tbody></table></div>
              </>}
              {auditCursor && (auditMoreError ? <LoadFailure message={auditMoreError} onRetry={() => void loadOlder('audit')} /> : <button className="ui-button ui-button-secondary ui-button-sm pagination-action" disabled={auditMoreLoading} onClick={() => void loadOlder('audit')}>{auditMoreLoading ? 'Loading…' : 'Load older audit events'}</button>)}
            </div>}
          </>}
        </div></div>}
        {needsAuthority && !isReader && section !== 'authorities' && section !== 'requests' && <div className="empty-state"><div className="empty-icon"><Icon name="authority" size={30} /></div><h2>Not in your roles</h2><p>This view needs the reader role and an authority in your scope.</p></div>}
        {section === 'requests' && !isReader && (isRequester || isOfficer) && <div className="empty-state"><div className="empty-icon"><Icon name="request" size={30} /></div><h2>No authority to choose</h2><p>Requests are listed per authority; your account also needs the reader role and an authority in its scope.</p></div>}
      </main>
      {selectedCertificate?.ca_id === selectedCaId && section === 'certificates' && (scopedCertificates.some(cert => cert.request_id === selectedCertificate.request_id) || lookupResult?.request_id === selectedCertificate.request_id) && <CertificateDialog certificate={selectedCertificate} now={validityClock} onClose={closeDetail} {...neighbours(sortedCertificates, cert => cert.request_id === selectedCertificate.request_id, openCertificate)} />}
      {selectedAuditEvent?.ca_id === selectedCaId && section === 'audit' && (scopedAuditEvents.some(event => event.event_id === selectedAuditEvent.event_id) || auditLookupResult?.event_id === selectedAuditEvent.event_id) && <AuditDialog event={selectedAuditEvent} now={validityClock} onClose={closeDetail} {...neighbours(sortedAuditEvents, row => row.event_id === selectedAuditEvent.event_id, openAuditEvent)} />}
    </div>
    <Toaster />
    <CommandPalette items={paletteItems} open={paletteOpen} onClose={() => setPaletteOpen(false)} />
  </div>;
}

function RoleCard({ icon, title, text, action, onOpen }: { icon: IconName; title: string; text: string; action: string; onOpen: () => void }) {
  return <div className="ui-role-card"><div className="ui-role-icon"><Icon name={icon} size={20} /></div><h3>{title}</h3><p>{text}</p><button type="button" className="ui-button ui-button-secondary ui-button-sm" onClick={onOpen}>{action}<Icon name="chevron" size={15} /></button></div>;
}

const DAY_MS = 86_400_000;

/** Previous/next handlers and a position label for a record within a list. */
function neighbours<T>(rows: T[], isCurrent: (row: T) => boolean, open: (row: T) => void) {
  const index = rows.findIndex(isCurrent);
  if (index < 0) return { onPrevious: null, onNext: null, position: '' };
  return {
    onPrevious: index > 0 ? () => open(rows[index - 1]) : null,
    onNext: index < rows.length - 1 ? () => open(rows[index + 1]) : null,
    position: `${index + 1} of ${rows.length}`,
  };
}

function ValiditySummary({ certificate, now }: { certificate: Certificate; now: number }) {
  const elapsed = lifetimeElapsed(certificate, now);
  if (elapsed === null) return <div className="ui-validity">
    <div className="ui-validity-head"><span className="ui-summary-label">Recorded validity</span><Tag tone="neutral">Not recorded</Tag></div>
    <p className="ui-sub">No X.509 validity dates are recorded for this certificate.</p>
  </div>;
  const end = Date.parse(certificate.not_after!);
  const start = Date.parse(certificate.not_before!);
  const days = Math.round((end - now) / DAY_MS);
  const status = now < start ? 'Not yet valid' : days > 0 ? `${days} day${days === 1 ? '' : 's'} remaining` : `Ended ${-days} day${days === -1 ? '' : 's'} ago`;
  const tone = now < start ? 'info' : days <= 0 ? 'bad' : days <= 30 ? 'warn' : 'good';
  return <div className="ui-validity">
    <div className="ui-validity-head"><span className="ui-summary-label">Recorded validity</span><Tag tone={tone}>{status}</Tag></div>
    <div className={`ui-validity-bar ui-tone-${tone}`}><span style={{ width: `${Math.max(1.5, elapsed * 100)}%` }} /><i style={{ left: `${Math.min(100, Math.max(0, elapsed * 100))}%` }} title="Now" /></div>
    <div className="ui-validity-dates"><div><small>Not before</small><strong>{displayDate(certificate.not_before)}</strong></div><div><small>Not after</small><strong>{displayDate(certificate.not_after)}</strong></div></div>
  </div>;
}

function CertificateDialog({ certificate, now, onClose, onPrevious, onNext, position }: { certificate: Certificate; now: number; onClose: () => void; onPrevious: (() => void) | null; onNext: (() => void) | null; position: string }) {
  const period = recordedValidityStatus(certificate, now);
  return <DetailDrawer label="Certificate detail" eyebrow="Certificate" icon="certificate" tone="good" closeLabel="Close certificate detail" onClose={onClose}
    onPrevious={onPrevious} onNext={onNext} position={position}
    title={certificate.subject_cn || 'Common name not recorded'}
    subtitle={<span className="mono">Serial {certificate.serial_hex}</span>}
    badges={<>{certificate.revoked_at && <StatusBadge status="REVOKED" />}<StatusBadge status={certificate.state} /><Tag tone={period === 'Within period' ? 'good' : period === 'Period ended' ? 'bad' : period === 'Not yet in period' ? 'info' : 'neutral'}>{period}</Tag></>}
    actions={<CopyJsonButton json={certificateMetadataJson(certificate)} />}
    summary={<>{certificate.revoked_at && <div className="ui-revoked-banner"><Icon name="revocation" size={18} /><div><strong>Revoked {new Date(certificate.revoked_at).toLocaleString()}</strong><span>Reason: {reasonName(certificate.revocation_reason ?? null)}. Relying parties learn of it from the next published CRL.</span></div></div>}<ValiditySummary certificate={certificate} now={now} /></>}
    note="For actual lab issuance, validity and SAN come from independently verified DER. This database may include synthetic fixtures. The recorded period is not a live path or revocation check.">
    <DrawerSection title="Subject">
      <Fact label="DNS names (SAN)">{certificate.san_dns?.length ? <span className="ui-chip-list">{certificate.san_dns.map(name => <span key={name} className="ui-chip">{name}</span>)}</span> : certificate.san_dns ? 'None' : 'Not recorded'}</Fact>
      <Fact label="Recorded period">{period}</Fact>
    </DrawerSection>
    <DrawerSection title="Identifiers">
      <Fact label="Serial" copy={certificate.serial_hex} mono>{certificate.serial_hex}</Fact>
      <Fact label="Fingerprint SHA-256" copy={certificate.fingerprint_sha256} mono>{certificate.fingerprint_sha256.match(/.{1,8}/gu)?.join(' ') ?? certificate.fingerprint_sha256}</Fact>
      <Fact label="Request ID" copy={certificate.request_id} mono>{certificate.request_id}</Fact>
    </DrawerSection>
    <DrawerSection title="Lifecycle">
      <Fact label="Issuance state"><StatusBadge status={certificate.state} /></Fact>
      <Fact label="Revocation">{certificate.revoked_at ? <>{displayDate(certificate.revoked_at)} · {reasonName(certificate.revocation_reason ?? null)}</> : 'None recorded'}</Fact>
      <Fact label="Signed">{certificate.signed_at ? <TimeAgo value={certificate.signed_at} now={new Date(now)} /> : 'Not signed'}</Fact>
      <Fact label="Published">{certificate.published_at ? <TimeAgo value={certificate.published_at} now={new Date(now)} /> : 'Not recorded'}</Fact>
    </DrawerSection>
  </DetailDrawer>;
}

function AuditDialog({ event, now, onClose, onPrevious, onNext, position }: { event: AuditEvent; now: number; onClose: () => void; onPrevious: (() => void) | null; onNext: (() => void) | null; position: string }) {
  const described = describeEvent(event.event_type);
  const group = outcomeGroup(event.decision);
  return <DetailDrawer label="Audit event detail" eyebrow={`Audit event · ${CATEGORY_LABELS[described.category]}`} icon={CATEGORY_ICON[described.category]}
    tone={group === 'denied' ? 'bad' : group === 'attention' ? 'warn' : group === 'allowed' ? 'good' : 'info'}
    closeLabel="Close audit event detail" onClose={onClose} onPrevious={onPrevious} onNext={onNext} position={position}
    title={described.label} subtitle={<code>{event.event_type}</code>}
    badges={<><OutcomeBadge decision={event.decision} />{event.policy_version && <span className="ui-chip">policy {event.policy_version}</span>}{event.chain_sealed === true && <Tag tone="good" title="Sealed into the tamper-evident audit chain">Sealed</Tag>}{event.chain_sealed === false && <Tag tone="warn" title="Not yet sealed: the next sealing pass will add it to the chain">Not yet sealed</Tag>}</>}
    actions={<CopyJsonButton json={auditMetadataJson(event)} />}
    summary={<div className="ui-outcome-summary"><span className="ui-summary-label">What happened</span><p>{explainOutcome(event.decision)}</p><TimeAgo value={event.recorded_at} now={new Date(now)} /></div>}
    note="Database metadata only. This view does not include actor identity. A seal shows the event is in the hash chain; integrity is proven only by the independent verification tool against a head exported earlier.">
    <DrawerSection title="Record">
      <Fact label="Event ID" copy={event.event_id} mono>{event.event_id}</Fact>
      <Fact label="Recorded decision" mono>{event.decision || '—'}</Fact>
      <Fact label="Policy version">{event.policy_version ?? 'Not recorded'}</Fact>
      <Fact label="Recorded at">{displayDate(event.recorded_at)}</Fact>
      <Fact label="Authority ID" copy={event.ca_id} mono>{event.ca_id}</Fact>
    </DrawerSection>
    <DrawerSection title="Tamper evidence">
      <Fact label="Audit chain seal">{event.chain_sealed === true ? 'Sealed into the hash chain' : event.chain_sealed === false ? 'Not yet sealed (waiting for the next sealing pass)' : 'Not reported by this API version'}</Fact>
    </DrawerSection>
  </DetailDrawer>;
}

const CATEGORY_ICON: Record<EventCategory, IconName> = {
  certificate: 'certificate', request: 'request', signing: 'key', crl: 'revocation', profile: 'profile', authority: 'authority', policy: 'policy', other: 'info',
};

function AuthorityList({ cas, selectedCaId, onSelect, compact = false }: { cas: CertificateAuthority[]; selectedCaId: string | null; onSelect: (id: string) => void; compact?: boolean }) {
  return <div className={compact ? 'authority-list compact' : 'authority-list'}>{cas.map(ca => <button key={ca.ca_id} className={ca.ca_id === selectedCaId ? 'authority-row selected' : 'authority-row'} aria-pressed={ca.ca_id === selectedCaId} onClick={() => onSelect(ca.ca_id)}><span className="ca-emblem"><Icon name="authority" size={17} /></span><span className="ca-text"><strong>{ca.display_name}</strong><small>{shortId(ca.ca_id)} · Policy {ca.policy_version}{ca.operational_state && ca.operational_state !== 'ACTIVE' ? ` · ${ca.operational_state}` : ''}</small></span><span className="row-arrow"><Icon name="chevron" size={16} /></span></button>)}</div>;
}

function Info({ label, value }: { label: string; value: string }) {
  return <div className="info-cell"><span>{label}</span><strong>{value}</strong></div>;
}

function LoadingRows() { return <div className="ui-skeleton" role="status" aria-label="Loading records">{[0, 1, 2, 3, 4].map(row => <div key={row} className="ui-skeleton-row" style={{ opacity: 1 - row * .15 }} />)}</div>; }
function LoadFailure({ message, onRetry }: { message: string; onRetry: () => void }) {
  return <Notice tone="error" action={<button type="button" className="ui-button ui-button-secondary ui-button-sm" onClick={onRetry}>Retry</button>}>{message}</Notice>;
}
function EmptyDetail({ title, detail }: { title: string; detail: string }) { return <div className="empty-detail"><div><Icon name="info" size={26} /></div><strong>{title}</strong><p>{detail}</p></div>; }
