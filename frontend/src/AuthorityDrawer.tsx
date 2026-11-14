import { useEffect, useState } from 'react';
import { ApiError, apiGet, type CertificateAuthority } from './api';
import { CopyJsonButton, DetailDrawer, DrawerSection, Fact } from './DetailDrawer';
import { Icon, StatusBadge } from './ui';

interface CrlStatus {
  distribution_point: string | null;
  latest_crl_number: number | null;
  next_update: string | null;
  renewal_due: boolean;
  expired: boolean;
  auto_renewal?: boolean;
  publish_on_revocation?: boolean;
}

function displayDate(value: string | null | undefined): string {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? value : date.toLocaleString();
}

/**
 * Slide-over detail of one authority: the metadata the API returned for it and
 * the status of its CRL. Display only; the API decides every action.
 */
export function AuthorityDrawer({ ca, token, parentName, onClose, onPrevious, onNext, position, onOpen, onUnauthorized }: {
  ca: CertificateAuthority; token: string; parentName: string | null; onClose: () => void;
  onPrevious: (() => void) | null; onNext: (() => void) | null; position: string;
  onOpen: (view: 'certificates' | 'profiles' | 'revocation' | 'audit') => void; onUnauthorized: () => void;
}) {
  const [crl, setCrl] = useState<CrlStatus | null>(null);
  const [crlError, setCrlError] = useState<string | null>(null);
  useEffect(() => {
    const controller = new AbortController();
    setCrl(null);
    setCrlError(null);
    apiGet<CrlStatus>(`/v1/cas/${encodeURIComponent(ca.ca_id)}/crl-status`, token, controller.signal).then(setCrl).catch(failure => {
      if (controller.signal.aborted) return;
      if (failure instanceof ApiError && failure.status === 401) onUnauthorized();
      else setCrlError(failure instanceof Error ? failure.message : 'Could not load the CRL status.');
    });
    return () => controller.abort();
  }, [ca.ca_id, token]);

  const state = ca.operational_state ?? null;
  const tone = state === 'SUSPENDED' ? 'warn' : state === 'RETIRED' ? 'neutral' : 'good';
  const crlHealth = !crl ? null : crl.expired ? 'EXPIRED' : crl.latest_crl_number === null ? 'NO_CRL' : crl.renewal_due ? 'RENEWAL_DUE' : 'CURRENT';
  return <DetailDrawer label="Authority detail" eyebrow="Certificate authority" icon="authority" tone={tone} closeLabel="Close authority detail" onClose={onClose}
    onPrevious={onPrevious} onNext={onNext} position={position}
    title={ca.display_name}
    subtitle={<span className="mono">{ca.ca_id}</span>}
    badges={<>{state ? <StatusBadge status={state} /> : <span className="ui-badge ui-badge-neutral"><span className="ui-badge-dot" aria-hidden="true" />Owner-created</span>}{crlHealth && <StatusBadge status={crlHealth} />}</>}
    actions={<>
      <button type="button" className="ui-button ui-button-secondary ui-button-sm" onClick={() => onOpen('certificates')}><Icon name="certificate" size={15} />Certificates</button>
      <button type="button" className="ui-button ui-button-secondary ui-button-sm" onClick={() => onOpen('profiles')}><Icon name="profile" size={15} />Profiles</button>
      <button type="button" className="ui-button ui-button-secondary ui-button-sm" onClick={() => onOpen('revocation')}><Icon name="revocation" size={15} />CRLs</button>
      <button type="button" className="ui-button ui-button-secondary ui-button-sm" onClick={() => onOpen('audit')}><Icon name="audit" size={15} />Audit trail</button>
      <CopyJsonButton json={JSON.stringify(ca, null, 2)} />
    </>}
    note="Database metadata only: this panel does not assert that a CA certificate, signing key or policy publication has been independently verified.">
    <DrawerSection title="Identity">
      <Fact label="Authority ID" copy={ca.ca_id} mono>{ca.ca_id}</Fact>
      <Fact label="Parent authority">{ca.parent_ca_id ? <>{parentName ?? 'Not in your scope'} <span className="mono ui-sub">{ca.parent_ca_id}</span></> : 'Root / not recorded'}</Fact>
      <Fact label="Policy version">{ca.policy_version}</Fact>
      <Fact label="Created">{displayDate(ca.created_at)}</Fact>
    </DrawerSection>
    <DrawerSection title="Lifecycle">
      <Fact label="Operational state">{state ? <StatusBadge status={state} /> : 'Not managed by the CA lifecycle'}</Fact>
    </DrawerSection>
    <DrawerSection title="Revocation publication">
      {crlError && <Fact label="CRL status">{crlError}</Fact>}
      {!crl && !crlError && <Fact label="CRL status">Loading…</Fact>}
      {crl && <>
        <Fact label="CRL status">{crlHealth && <StatusBadge status={crlHealth} />}</Fact>
        <Fact label="Latest CRL">{crl.latest_crl_number ?? 'None published'}</Fact>
        <Fact label="Next update">{displayDate(crl.next_update)}</Fact>
        <Fact label="Distribution point" {...(crl.distribution_point ? { copy: crl.distribution_point } : {})} mono={Boolean(crl.distribution_point)}>{crl.distribution_point ?? 'Not configured by the database owner'}</Fact>
        <Fact label="Automatic renewal">{crl.auto_renewal === undefined ? 'Not reported' : crl.auto_renewal ? 'On' : 'Off'}</Fact>
        <Fact label="Publish on revocation">{crl.publish_on_revocation === undefined ? 'Not reported' : crl.publish_on_revocation ? 'On' : 'Off'}</Fact>
      </>}
    </DrawerSection>
  </DetailDrawer>;
}
