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
