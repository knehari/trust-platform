#!/usr/bin/env bash
# Lab only: TLS 1.3 HTTP transport of the token-carrying lab APIs
# (crates/management-api/src/http_tls.rs). Makes a throwaway CA and a
# "localhost" server certificate with OpenSSL, then runs the transport
# tests, the TLS one included (TRUST_REQUIRE_HTTP_TLS_TEST makes a skip
# fail): TLS 1.3 served, a TLS 1.2 client and a plaintext request refused,
# and handlers see the client address (ConnectInfo).
# Then a real API binary must refuse a certificate without its key.
#   bash tests/http_tls.sh
set -euo pipefail
temp="$(mktemp -d)"
trap 'rm -rf "$temp"; [ -n "${server_pid:-}" ] && kill "$server_pid" 2>/dev/null || true' EXIT
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
  -subj "/CN=Trust Lab HTTP Test CA" -keyout "$temp/ca.key" -out "$temp/ca.pem" 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -subj "/CN=localhost" -keyout "$temp/server.key" -out "$temp/server.csr" 2>/dev/null
printf 'subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n' >"$temp/ext"
openssl x509 -req -in "$temp/server.csr" -CA "$temp/ca.pem" -CAkey "$temp/ca.key" \
  -CAcreateserial -days 1 -extfile "$temp/ext" -out "$temp/server.pem" 2>/dev/null

TRUST_HTTP_TLS_TEST_DIR="$temp" TRUST_REQUIRE_HTTP_TLS_TEST=1 \
  cargo test -q --locked -p trust-management-api --bin trust-management-api http_tls:: 2>&1 \
  | tee "$temp/test.log" | grep -E "^test result|FAILED|panicked"
grep -q "test result: ok. 5 passed" "$temp/test.log" || { echo "FAIL: transport tests" >&2; exit 1; }

# A real API binary refuses plaintext off loopback before touching OIDC or
# the database (settings and bind are checked first).
cargo build -q --locked -p trust-management-api --bin revocation_api
set +e
TRUST_REVOCATION_BIND=0.0.0.0:0 TRUST_OIDC_ISSUER=http://127.0.0.1:9 TRUST_OIDC_AUDIENCE=x \
TRUST_REVOCATION_DATABASE_URL=postgresql://nobody@127.0.0.1:9/none TRUST_DATABASE_TLS=disable-lab \
TRUST_WEBAUTHN_RP_ID=officer.lab.invalid TRUST_WEBAUTHN_ORIGIN=https://officer.lab.invalid \
TRUST_HTTP_TLS_CERT_FILE="$temp/server.pem" \
  timeout 20 target/debug/revocation_api >"$temp/half.log" 2>&1
half=$?
set -e
[ "$half" != 0 ] && [ "$half" != 124 ] && grep -q "go together" "$temp/half.log" \
  || { cat "$temp/half.log" >&2; echo "FAIL: a certificate without its key was accepted" >&2; exit 1; }
# No TLS settings and a non-loopback bind: refused at startup, before the
# (unreachable) OIDC issuer or database is contacted.
for api in revocation_api:TRUST_REVOCATION_BIND ca_admin_api:TRUST_CA_ADMIN_BIND \
           trust-management-api:TRUST_API_BIND; do
  bin="${api%%:*}"
  cargo build -q --locked -p trust-management-api --bin "$bin"
  set +e
  env "${api#*:}=0.0.0.0:0" TRUST_OIDC_ISSUER=http://127.0.0.1:9 TRUST_OIDC_AUDIENCE=x \
    timeout 20 "target/debug/$bin" >"$temp/plain.log" 2>&1
  status=$?
  set -e
  [ "$status" != 0 ] && [ "$status" != 124 ] && grep -q "refusing plaintext HTTP" "$temp/plain.log" \
    || { cat "$temp/plain.log" >&2; echo "FAIL: $bin served plaintext off loopback" >&2; exit 1; }
done

# An invalid trusted-proxy setting refuses to start (never "trust nothing"
# silently, never "trust everything").
for api in revocation_api:TRUST_REVOCATION_BIND ca_admin_api:TRUST_CA_ADMIN_BIND \
           trust-management-api:TRUST_API_BIND; do
  bin="${api%%:*}"
  set +e
  env "${api#*:}=127.0.0.1:0" TRUST_HTTP_TRUSTED_PROXIES="10.0.0.0/8, proxy.lab" \
    TRUST_OIDC_ISSUER=http://127.0.0.1:9 TRUST_OIDC_AUDIENCE=x \
    timeout 20 "target/debug/$bin" >"$temp/proxy.log" 2>&1
  status=$?
  set -e
  [ "$status" != 0 ] && [ "$status" != 124 ] && grep -q "TRUST_HTTP_TRUSTED_PROXIES: invalid" "$temp/proxy.log" \
    || { cat "$temp/proxy.log" >&2; echo "FAIL: $bin started with an invalid trusted-proxy setting" >&2; exit 1; }
done

echo "PASS: lab APIs serve TLS 1.3 only with the configured certificate, refuse plaintext off loopback and refuse an invalid trusted-proxy setting"
