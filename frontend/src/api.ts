export interface CertificateAuthority {
  ca_id: string;
  parent_ca_id: string | null;
  display_name: string;
  policy_version: string;
  created_at: string;
}

export interface Certificate {
  ca_id: string;
  serial_hex: string;
  fingerprint_sha256: string;
  request_id: string;
  state: string;
  signed_at: string;
  published_at: string | null;
  subject_cn: string | null;
  not_before: string | null;
  not_after: string | null;
  san_dns: string[] | null;
}

export interface AuditEvent {
  event_id: string;
  ca_id: string;
  event_type: string;
  decision: string;
  policy_version: string | null;
  recorded_at: string;
}

export type ProfileLifecycleStatus = 'DRAFT' | 'SUBMITTED' | 'APPROVED' | 'REJECTED' | 'ACTIVE' | 'SUPERSEDED' | 'RETIRED';

export interface ProfileDraft {
  ca_id: string;
  profile_id: string;
  revision: number;
  display_name: string;
  policy_version: string;
  max_validity_days: number;
  max_dns_sans: number;
  proposed_dns_zones: string[];
  proposed_signature_suites: string[];
  created_by: string;
  created_at: string;
  /** No state authorizes issuance: no issuance path reads ACTIVE yet (ADR-0012). */
  status: ProfileLifecycleStatus;
  submitted_at: string | null;
  approval_count: number;
  decided_at: string | null;
  activated_at: string | null;
  ended_at: string | null;
  proposal_warnings: string[];
  snapshot_sha256: string;
}

export class ApiError extends Error {
  readonly status: number;
  readonly requestId: string | null;

  constructor(status: number, message: string, requestId: string | null = null) {
    super(message);
    this.status = status;
    this.requestId = requestId;
  }
}

export interface ApiPage<T> {
  items: T[];
  nextCursor: string | null;
}

async function apiResponse(path: string, token: string, signal?: AbortSignal): Promise<Response> {
  const response = await fetch(path, {
    method: 'GET',
    headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
    credentials: 'omit',
    cache: 'no-store',
    signal,
  });
  if (!response.ok) {
    const rawRequestId = response.headers.get('x-request-id');
    const requestId = rawRequestId && /^[0-9]{1,10}-[0-9]{1,20}$/.test(rawRequestId) ? rawRequestId : null;
    const message = response.status === 401 ? 'Your session has expired. Sign in again.'
      : response.status === 403 ? 'Your role or CA scope does not allow this view.'
      : response.status === 503 ? 'The management API or database is unavailable.'
      : `The request failed (${response.status}).`;
    throw new ApiError(response.status, requestId ? `${message} Request ID: ${requestId}.` : message, requestId);
  }
  return response;
}

export async function apiGet<T>(path: string, token: string, signal?: AbortSignal): Promise<T> {
  return (await apiResponse(path, token, signal)).json() as Promise<T>;
}

const WRITE_MESSAGES: Record<number, string> = {
  400: 'The request was rejected as invalid. Check every field.',
  401: 'Your session has expired. Sign in again.',
  403: 'Your role or CA grant does not allow this change.',
  404: 'That revision no longer exists for this authority.',
  409: 'This change conflicts with the recorded state: the revision may be stale, already submitted, or its digest changed. Reload and try again.',
  413: 'The request is too large.',
  422: 'The request was refused: a revision with syntax warnings cannot be submitted, a decision needs a signature by your registered key over the exact claim, and activation needs the CA policy version and suites the CA declares.',
  503: 'Profile changes are unavailable: the management API or its write database is not configured or not reachable.',
};

/**
 * POSTs JSON with an idempotency key. Retrying with the same key and body
 * returns the recorded result instead of writing twice.
 */
export async function apiPost<T>(path: string, token: string, body: unknown, idempotencyKey: string): Promise<{ status: number; replayed: boolean; value: T }> {
  const response = await fetch(path, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`, Accept: 'application/json',
      'Content-Type': 'application/json', 'Idempotency-Key': idempotencyKey,
    },
    body: JSON.stringify(body),
    credentials: 'omit',
    cache: 'no-store',
  });
  if (!response.ok) {
    const rawRequestId = response.headers.get('x-request-id');
    const requestId = rawRequestId && /^[0-9]{1,10}-[0-9]{1,20}$/.test(rawRequestId) ? rawRequestId : null;
    const message = WRITE_MESSAGES[response.status] ?? `The request failed (${response.status}).`;
    throw new ApiError(response.status, requestId ? `${message} Request ID: ${requestId}.` : message, requestId);
  }
  return { status: response.status, replayed: response.headers.get('idempotent-replayed') === 'true', value: await response.json() as T };
}

export async function apiGetPage<T>(path: string, token: string, signal?: AbortSignal): Promise<ApiPage<T>> {
  const response = await apiResponse(path, token, signal);
  return {
    items: await response.json() as T[],
    nextCursor: response.headers.get('x-next-cursor'),
  };
}
