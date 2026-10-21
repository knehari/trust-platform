import type { AuditEvent, Certificate } from './api';

export function certificateMetadataJson(certificate: Certificate): string {
  return JSON.stringify({
    ca_id: certificate.ca_id,
    request_id: certificate.request_id,
    serial_hex: certificate.serial_hex,
    subject_cn: certificate.subject_cn,
    not_before: certificate.not_before,
    not_after: certificate.not_after,
    san_dns: certificate.san_dns,
    fingerprint_sha256: certificate.fingerprint_sha256,
    state: certificate.state,
    signed_at: certificate.signed_at,
    published_at: certificate.published_at,
  }, null, 2);
}

export function auditMetadataJson(event: AuditEvent): string {
  return JSON.stringify({
    ca_id: event.ca_id,
    event_id: event.event_id,
    event_type: event.event_type,
    decision: event.decision,
    policy_version: event.policy_version,
    recorded_at: event.recorded_at,
  }, null, 2);
}
