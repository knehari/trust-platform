#!/usr/bin/env bash
# Lab-only: the crl_reconcile tool stores a quarantined CRL from its DER
# (migration 0021) under a login holding only trust_crl_signer. Needs the
# files written by verified_crl_whose_storage_failed_is_reconciled with
# TRUST_CRL_EXPORT_DIR (<dir>/reconcile: crl.der, issuer.der,
# other_issuer.der, ids), a superuser URL, psql and python3:
#   TRUST_CI_DATABASE_URL=postgresql://... bash tests/crl_reconcile.sh <dir>
set -euo pipefail
: "${TRUST_CI_DATABASE_URL:?TRUST_CI_DATABASE_URL is required}"
db="$TRUST_CI_DATABASE_URL"
dir="${1:?usage: $0 <export dir>}/reconcile"
temp="$(mktemp -d)"
trap 'rm -rf "$temp"' EXIT
fail() { echo "FAIL: $*" >&2; cat "$temp/out" >&2 2>/dev/null; exit 1; }
sql() { psql -X -q -A -t -v ON_ERROR_STOP=1 "$db" -c "$1"; }
read -r ca number <"$dir/ids"
status() { sql "SELECT status FROM crl_publication WHERE ca_id = '$ca' AND crl_number = $number"; }
[ "$(status)" = RECONCILIATION_REQUIRED ] || fail "CRL $number is not quarantined"

sql "SET client_min_messages = warning;
     DO \$\$BEGIN
       IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trust_crl_signer_reconcile_ci') THEN
         CREATE ROLE trust_crl_signer_reconcile_ci LOGIN PASSWORD 'test-only-not-secret';
       END IF;
     END\$\$;
     GRANT trust_crl_signer TO trust_crl_signer_reconcile_ci" >/dev/null
signer_url="$(python3 - "$db" <<'PY'
import sys, urllib.parse
u = urllib.parse.urlsplit(sys.argv[1])
host = u.hostname + (f":{u.port}" if u.port else "")
print(urllib.parse.urlunsplit((u.scheme, f"trust_crl_signer_reconcile_ci:test-only-not-secret@{host}",
                               u.path, u.query, u.fragment)))
PY
)"
cargo build -q --locked -p trust-pki-core --features postgres-store,lab-software --example crl_reconcile
bin=target/debug/examples/crl_reconcile
run() { # <url> <issuer> <crl> [actor]
  TRUST_DATABASE_TLS=disable-lab TRUST_DATABASE_URL="$1" "$bin" "$ca" "$2" "$3" --actor "${4:-crl-reviewer-ci}" \
    >"$temp/out" 2>&1
}
refused() { # <what> <expected message> <args...>
  local what="$1" message="$2"; shift 2
  if run "$@"; then fail "$what was stored"; fi
  grep -q "$message" "$temp/out" || fail "$what: wrong refusal"
  [ "$(status)" = RECONCILIATION_REQUIRED ] || fail "$what changed the row"
}
cp "$dir/crl.der" "$temp/altered.der"
python3 - "$temp/altered.der" <<'PY'
import sys
p = sys.argv[1]; b = bytearray(open(p, "rb").read()); b[-1] ^= 1; open(p, "wb").write(bytes(b))
PY
refused "a superuser session" "PrivilegedSession" "$db" "$dir/issuer.der" "$dir/crl.der"
refused "an altered CRL" "does not verify" "$signer_url" "$dir/issuer.der" "$temp/altered.der"
refused "another issuer" "does not verify" "$signer_url" "$dir/other_issuer.der" "$dir/crl.der"
run "$signer_url" "$dir/issuer.der" "$dir/crl.der" || fail "the quarantined CRL was not stored"
grep -q "CRL $number stored" "$temp/out" || fail "no confirmation"
[ "$(status)" = STORED ] || fail "row not STORED"
[ "$(sql "SELECT count(*) FROM audit_event WHERE ca_id = '$ca' AND event_type = 'crl.reconciled'
          AND actor_id = 'crl-reviewer-ci' AND decision = 'STORED:$number'")" = 1 ] || fail "not audited"
[ "$(sql "SELECT crl_der = decode('$(python3 -c 'import sys;print(open(sys.argv[1],"rb").read().hex())' "$dir/crl.der")', 'hex') FROM crl_publication
          WHERE ca_id = '$ca' AND crl_number = $number")" = t ] || fail "stored bytes differ"
if run "$signer_url" "$dir/issuer.der" "$dir/crl.der"; then fail "a stored CRL was reconciled twice"; fi
grep -q "is STORED, not quarantined" "$temp/out" || fail "second run: wrong refusal"
echo "PASS: crl_reconcile stores a quarantined CRL from its DER and refuses altered, foreign and privileged attempts"
