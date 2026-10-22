#!/usr/bin/env bash
# Disposable PostgreSQL 16 (lab only): the crl_distribution binary serves a
# CA's latest stored CRL byte for byte, OpenSSL verifies it against the
# registered issuer, unknown CAs get 404, and a CRL altered in the database
# is refused (503) instead of published. Needs migrations 0001..0030, at least
# one STORED CRL (run after revocation_crl_postgres), a superuser URL, psql,
# curl, openssl and python3:
#   TRUST_CI_DATABASE_URL=postgresql://... bash tests/crl_distribution.sh
set -euo pipefail
: "${TRUST_CI_DATABASE_URL:?TRUST_CI_DATABASE_URL is required}"
db="$TRUST_CI_DATABASE_URL"
temp="$(mktemp -d)"
server=""
cleanup() {
  [ -n "$server" ] && kill "$server" 2>/dev/null || true
  rm -rf "$temp"
}
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; [ -f "$temp/server.log" ] && cat "$temp/server.log" >&2; exit 1; }
sql() { psql -X -q -A -t -v ON_ERROR_STOP=1 "$db" -c "$1"; }
unhex() { python3 -c 'import sys,binascii;sys.stdout.buffer.write(binascii.unhexlify(sys.stdin.read().strip()))'; }

ca="$(sql "SELECT p.ca_id FROM crl_publication p JOIN ca_issuer_certificate i USING (ca_id)
           WHERE p.status = 'STORED' ORDER BY p.ca_id LIMIT 1")"
[ -n "$ca" ] || fail "no stored CRL in the database"
number="$(sql "SELECT max(crl_number) FROM crl_publication WHERE ca_id = '$ca' AND status = 'STORED'")"
sql "SELECT encode(crl_der, 'hex') FROM crl_publication WHERE ca_id = '$ca' AND crl_number = $number" | unhex >"$temp/expected.der"
sql "SELECT encode(certificate_der, 'hex') FROM ca_issuer_certificate WHERE ca_id = '$ca'" | unhex >"$temp/issuer.der"
openssl x509 -inform DER -in "$temp/issuer.der" -out "$temp/issuer.pem"

# A login holding only trust_crl_publisher (test-only password, lab only).
sql "DO \$\$BEGIN
       IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trust_crl_publisher_ci') THEN
         CREATE ROLE trust_crl_publisher_ci LOGIN PASSWORD 'test-only-not-secret';
       END IF;
     END\$\$;
     GRANT trust_crl_publisher TO trust_crl_publisher_ci" >/dev/null
publisher_url="$(python3 - "$db" <<'PY'
import sys, urllib.parse
u = urllib.parse.urlsplit(sys.argv[1])
host = u.hostname + (f":{u.port}" if u.port else "")
print(urllib.parse.urlunsplit((u.scheme, f"trust_crl_publisher_ci:test-only-not-secret@{host}",
                               u.path, u.query, u.fragment)))
PY
)"

cargo build -q --locked -p trust-management-api --bin crl_distribution
port=18082
# Without the explicit lab opt-out, verified TLS is required: no CA bundle,
# no start (the database here has no TLS; tests/management_db_tls.sh covers
# verified TLS).
if TRUST_CRL_DATABASE_URL="$publisher_url" TRUST_CRL_BIND="127.0.0.1:$port" \
   timeout 10 target/debug/crl_distribution 2>"$temp/tls.log"; then
  fail "started without TLS or the lab opt-out"
fi
grep -q "TRUST_DATABASE_CA_FILE" "$temp/tls.log" || fail "missing CA bundle not reported"
# A superuser login is refused at start.
if TRUST_DATABASE_TLS=disable-lab TRUST_CRL_DATABASE_URL="$db" TRUST_CRL_BIND="127.0.0.1:$port" \
   timeout 10 target/debug/crl_distribution 2>"$temp/refused.log"; then
  fail "a superuser login was accepted"
fi
grep -q "trust_crl_publisher" "$temp/refused.log" || fail "superuser refusal not reported"

# An out-of-range reuse window is refused at start.
if TRUST_DATABASE_TLS=disable-lab TRUST_CRL_DATABASE_URL="$publisher_url" TRUST_CRL_BIND="127.0.0.1:$port" \
   TRUST_CRL_REUSE_SECONDS=301 timeout 10 target/debug/crl_distribution 2>"$temp/reuse.log"; then
  fail "an out-of-range reuse window was accepted"
fi
grep -q "TRUST_CRL_REUSE_SECONDS" "$temp/reuse.log" || fail "reuse window refusal not reported"
# Reuse disabled here: the database copy is re-read and re-verified on
# every request, so the alteration below is refused at once (the default
# 30-second reuse is covered by the binary's unit tests).
TRUST_DATABASE_TLS=disable-lab TRUST_CRL_DATABASE_URL="$publisher_url" TRUST_CRL_BIND="127.0.0.1:$port" \
  TRUST_CRL_REUSE_SECONDS=0 target/debug/crl_distribution 2>"$temp/server.log" &
server=$!
for _ in $(seq 1 100); do
  curl -s -o /dev/null "http://127.0.0.1:$port/crl/$ca.crl" && break
  sleep 0.1
done

curl -sf -D "$temp/headers" -o "$temp/served.der" "http://127.0.0.1:$port/crl/$ca.crl" \
  || fail "stored CRL not served"
cmp -s "$temp/served.der" "$temp/expected.der" || fail "served CRL differs from the stored one"
grep -qi '^content-type: application/pkix-crl' "$temp/headers" || fail "wrong content type"
grep -qi "^etag: \"$number\"" "$temp/headers" || fail "ETag is not the CRL number"
[ "$(curl -s -o /dev/null -w '%{http_code}' -H "If-None-Match: \"$number\"" "http://127.0.0.1:$port/crl/$ca.crl")" = 304 ] \
  || fail "current ETag not answered with 304"
last_modified="$(grep -i '^last-modified:' "$temp/headers" | cut -d' ' -f2- | tr -d '\r')"
[ "$(curl -s -o /dev/null -w '%{http_code}' -H "If-Modified-Since: $last_modified" "http://127.0.0.1:$port/crl/$ca.crl")" = 304 ] \
  || fail "If-Modified-Since thisUpdate not answered with 304"
[ "$(curl -s -o /dev/null -w '%{http_code}' -H 'If-None-Match: "0"' "http://127.0.0.1:$port/crl/$ca.crl")" = 200 ] \
  || fail "stale ETag not answered with the CRL"
openssl crl -inform DER -in "$temp/served.der" -CAfile "$temp/issuer.pem" -noout 2>&1 \
  | grep -q "verify OK" || fail "OpenSSL does not verify the served CRL"
[ "$(curl -s -o /dev/null -w '%{http_code}' -I "http://127.0.0.1:$port/crl/$ca.crl")" = 200 ] \
  || fail "HEAD not answered"
[ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/crl/00000000-0000-4000-8000-000000000000.crl")" = 404 ] \
  || fail "unknown CA not 404"
[ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/crl/$ca.der")" = 404 ] \
  || fail "non-canonical path not 404"

# A superuser alters the stored CRL: the distribution point refuses to serve
# it. The original bytes are restored afterwards (shared CI database).
sql "ALTER TABLE crl_publication DISABLE TRIGGER crl_publication_guard;
     UPDATE crl_publication SET crl_der = overlay(crl_der placing
         set_byte(substring(crl_der from octet_length(crl_der) for 1), 0,
                  get_byte(crl_der, octet_length(crl_der) - 1) # 1)
         from octet_length(crl_der))
     WHERE ca_id = '$ca' AND crl_number = $number;
     ALTER TABLE crl_publication ENABLE TRIGGER crl_publication_guard" >/dev/null
status="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/crl/$ca.crl")"
python3 - "$db" "$ca" "$number" "$temp/expected.der" <<'PY'
import subprocess, sys
db, ca, number, path = sys.argv[1:]
data = open(path, "rb").read().hex()
sql = (f"ALTER TABLE crl_publication DISABLE TRIGGER crl_publication_guard;"
       f"UPDATE crl_publication SET crl_der = decode('{data}', 'hex')"
       f" WHERE ca_id = '{ca}' AND crl_number = {number};"
       f"ALTER TABLE crl_publication ENABLE TRIGGER crl_publication_guard")
subprocess.run(["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", db, "-c", sql], check=True,
               stdout=subprocess.DEVNULL)
PY
[ "$status" = 503 ] || fail "altered CRL answered $status instead of 503"
grep -q crl_refused_verification_failed "$temp/server.log" || fail "refusal not logged"
curl -sf -o "$temp/again.der" "http://127.0.0.1:$port/crl/$ca.crl" || fail "restored CRL not served"
cmp -s "$temp/again.der" "$temp/expected.der" || fail "restored CRL differs"

echo "PASS: CRL distribution serves verified stored CRLs and refuses altered ones"
