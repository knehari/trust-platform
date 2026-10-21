#!/usr/bin/env bash
# Proves the management API's PostgreSQL TLS policy against a real server:
# verified TLS 1.3 to a trusted host succeeds (even with sslmode=disable in the
# URL), while an unrelated CA or a host name outside the certificate fails.
# CI-oriented: needs Docker, OpenSSL and sudo (the key must belong to uid 999).
set -euo pipefail

work="$(mktemp -d)"
name="trust-db-tls-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}"
cleanup() {
  docker rm -f "$name" >/dev/null 2>&1 || true
  sudo rm -rf "$work"
}
trap cleanup EXIT

ec_key=(-newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes)
openssl req -x509 "${ec_key[@]}" -days 1 -keyout "$work/ca.key" -out "$work/ca.pem" \
  -subj "/CN=Trust DB TLS Test CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" 2>/dev/null
openssl req -x509 "${ec_key[@]}" -days 1 -keyout "$work/other.key" -out "$work/untrusted-ca.pem" \
  -subj "/CN=Unrelated CA" -addext "basicConstraints=critical,CA:TRUE" 2>/dev/null
openssl req -new "${ec_key[@]}" -keyout "$work/server.key" -out "$work/server.csr" \
  -subj "/CN=localhost" 2>/dev/null
printf 'subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n' \
  > "$work/server.ext"
openssl x509 -req -in "$work/server.csr" -CA "$work/ca.pem" -CAkey "$work/ca.key" \
  -CAcreateserial -days 1 -extfile "$work/server.ext" -out "$work/server.pem" 2>/dev/null

mkdir "$work/certs"
cp "$work/server.pem" "$work/server.key" "$work/certs/"
chmod 600 "$work/certs/server.key"
sudo chown -R 999:999 "$work/certs"

docker run --detach --name "$name" \
  -e POSTGRES_USER=trust_tls_ci \
  -e POSTGRES_PASSWORD=test-only-not-secret \
  -e POSTGRES_DB=trust_tls \
  -v "$work/certs:/certs:ro" \
  -p 127.0.0.1:55434:5432 postgres:16 \
  -c ssl=on -c ssl_cert_file=/certs/server.pem -c ssl_key_file=/certs/server.key \
  -c ssl_min_protocol_version=TLSv1.3 >/dev/null

for _ in $(seq 1 30); do
  if docker exec "$name" pg_isready -h 127.0.0.1 -U trust_tls_ci -d trust_tls >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
docker exec "$name" pg_isready -h 127.0.0.1 -U trust_tls_ci -d trust_tls

TRUST_REQUIRE_DATABASE=1 \
TRUST_API_TLS_TEST_DATABASE_URL="postgresql://trust_tls_ci:test-only-not-secret@localhost:55434/trust_tls" \
TRUST_API_TLS_TEST_CA_FILE="$work/ca.pem" \
TRUST_API_TLS_TEST_UNTRUSTED_CA_FILE="$work/untrusted-ca.pem" \
  cargo test -p trust-management-api --locked \
    database::tests::verify_full_connects_only_to_a_trusted_matching_server -- --exact
echo 'PASS: management API requires verified TLS 1.3 to PostgreSQL'

# The lab services (CRL distribution, revocation API) apply the same policy:
# with the trusted CA the handshake succeeds and they reach their login
# check (which refuses this superuser); with an unrelated CA or another host
# name they never get a session.
cargo build -q --locked -p trust-management-api --bin crl_distribution --bin revocation_api \
  --bin crl_housekeeping --bin signed_evidence_audit --bin ca_admin_api
tls_url="postgresql://trust_tls_ci:test-only-not-secret@localhost:55434/trust_tls"
service_error() { # <binary> <ca-file> <url>
  local binary="$1" ca="$2" url="$3"
  TRUST_DATABASE_CA_FILE="$ca" TRUST_CRL_DATABASE_URL="$url" TRUST_CRL_BIND=127.0.0.1:18099 \
  TRUST_REVOCATION_DATABASE_URL="$url" TRUST_CA_ADMIN_DATABASE_URL="$url" \
  TRUST_OIDC_ISSUER=https://issuer.invalid \
  TRUST_OIDC_AUDIENCE=trust-api TRUST_WEBAUTHN_RP_ID=officer.lab.invalid \
  TRUST_WEBAUTHN_ORIGIN=https://officer.lab.invalid \
    timeout 30 "target/debug/$binary" 2>&1 | tail -1 || true
}
job_error() { # <binary> <ca-file> <url> <args...>: the lab jobs (TRUST_DATABASE_URL)
  local binary="$1" ca="$2" url="$3"; shift 3
  TRUST_DATABASE_CA_FILE="$ca" TRUST_DATABASE_URL="$url" \
  TRUST_WEBAUTHN_RP_ID=officer.lab.invalid TRUST_WEBAUTHN_ORIGIN=https://officer.lab.invalid \
    timeout 30 "target/debug/$binary" "$@" 2>&1 | tail -1 || true
}
expect_job_error() { # <what> <expected substring> <binary> <ca-file> <url> <args...>
  local what="$1" expected="$2"; shift 2
  local out; out="$(job_error "$@")"
  case "$out" in
    *"$expected"*) ;;
    *) echo "FAIL: $what: $out" >&2; exit 1 ;;
  esac
}
expect_error() { # <what> <expected substring> <binary> <ca-file> <url>
  local what="$1" expected="$2"; shift 2
  local out; out="$(service_error "$@")"
  case "$out" in
    *"$expected"*) ;;
    *) echo "FAIL: $what: $out" >&2; exit 1 ;;
  esac
}
expect_error "crl_distribution verified TLS" "must hold only trust_crl_publisher" \
  crl_distribution "$work/ca.pem" "$tls_url"
expect_error "crl_distribution untrusted CA" "connection or TLS failed" \
  crl_distribution "$work/untrusted-ca.pem" "$tls_url"
expect_error "crl_distribution wrong host" "connection or TLS failed" \
  crl_distribution "$work/ca.pem" "${tls_url/localhost/127.0.0.1}"
expect_error "revocation_api verified TLS" "login is privileged" \
  revocation_api "$work/ca.pem" "$tls_url"
expect_error "revocation_api untrusted CA" "connection or TLS failed" \
  revocation_api "$work/untrusted-ca.pem" "$tls_url"
expect_error "ca_admin_api verified TLS" "login is privileged" \
  ca_admin_api "$work/ca.pem" "$tls_url"
expect_error "ca_admin_api untrusted CA" "connection or TLS failed" \
  ca_admin_api "$work/untrusted-ca.pem" "$tls_url"
# The lab jobs apply the same policy: verified TLS reaches the login check
# (this superuser is refused), an unrelated CA gets no session.
for job in "crl_housekeeping --all" "signed_evidence_audit 00000000-0000-4000-8000-000000000000"; do
  set -- $job
  expect_job_error "$1 verified TLS" "PrivilegedSession" "$1" "$work/ca.pem" "$tls_url" "$2"
  expect_job_error "$1 untrusted CA" "connection or TLS failed" \
    "$1" "$work/untrusted-ca.pem" "$tls_url" "$2"
done
echo 'PASS: lab CRL distribution, revocation and CA-admin APIs, housekeeping and evidence audit require verified TLS 1.3 to PostgreSQL'
