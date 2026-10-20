#!/usr/bin/env bash
# Disposable PostgreSQL 16 (lab only): end-to-end sealing and external
# anchoring with the audit_chain_anchor example (migration 0027). Needs an
# EMPTY database it may tamper with (committed superuser rewrites), a
# superuser URL and host psql:
#   TRUST_ANCHOR_DATABASE_URL=postgresql://... bash tests/audit_chain_anchor.sh
set -euo pipefail
: "${TRUST_ANCHOR_DATABASE_URL:?TRUST_ANCHOR_DATABASE_URL is required}"
db="$TRUST_ANCHOR_DATABASE_URL"
temp="$(mktemp -d)"
trap 'rm -rf "$temp"' EXIT
anchor="$temp/checkpoints"

psql_run() { psql -X -q -A -t -v ON_ERROR_STOP=1 "$db" "$@"; }
for migration in migrations/*.sql; do
  psql_run -f "$migration" >/dev/null
done
cargo build -q --locked -p trust-pki-core --features postgres-store,lab-software --example audit_chain_anchor
bin="target/debug/examples/audit_chain_anchor"
as_role() { # <role> <args...>
  local role="$1"; shift
  local sep='?'; [[ "$db" == *\?* ]] && sep='&'
  TRUST_DATABASE_URL="${db}${sep}options=-crole%3D${role}" "$bin" "$@"
}
expect_status() { # <expected> <what> <command...>
  local expected="$1" what="$2"; shift 2
  set +e; "$@" >"$temp/out" 2>&1; local status=$?; set -e
  if [ "$status" != "$expected" ]; then
    echo "FAIL: $what: exit $status, expected $expected" >&2
    cat "$temp/out" >&2
    exit 1
  fi
}
event() {
  psql_run -c "INSERT INTO audit_event(event_id,actor_id,event_type,decision)
               VALUES (gen_random_uuid(),'anchor-test','audit.anchor.probe','$1')" >/dev/null
}

event first
expect_status 0 "seal" as_role trust_audit_sealer seal
expect_status 0 "first verification" as_role trust_audit_verifier verify "$anchor"
[ "$(wc -l <"$anchor")" = 1 ] || { echo "FAIL: no checkpoint exported" >&2; exit 1; }
expect_status 0 "verification without new entries" as_role trust_audit_verifier verify "$anchor"
[ "$(wc -l <"$anchor")" = 1 ] || { echo "FAIL: checkpoint appended without new entries" >&2; exit 1; }

event second
expect_status 0 "seal" as_role trust_audit_sealer seal
expect_status 0 "second verification" as_role trust_audit_verifier verify "$anchor"
[ "$(wc -l <"$anchor")" = 2 ] || { echo "FAIL: second checkpoint missing" >&2; exit 1; }

# A record left unsealed is reported (2), the role split holds (1).
event third
expect_status 2 "unsealed record" as_role trust_audit_verifier verify "$anchor" --unsealed-older-than 0
expect_status 1 "verifier cannot seal" as_role trust_audit_verifier seal
expect_status 0 "seal" as_role trust_audit_sealer seal
expect_status 0 "third verification" as_role trust_audit_verifier verify "$anchor"
cp "$anchor" "$temp/anchor.before"

# Signed anchor (lab P-256 key generated here, PKCS#8 DER; an HSM in production).
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 2>/dev/null \
  | openssl pkcs8 -topk8 -nocrypt -outform DER -out "$temp/anchor.key"
openssl pkey -inform DER -in "$temp/anchor.key" -pubout -outform DER -out "$temp/anchor.pub"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 2>/dev/null \
  | openssl pkcs8 -topk8 -nocrypt -outform DER -out "$temp/other.key"
openssl pkey -inform DER -in "$temp/other.key" -pubout -outform DER -out "$temp/other.pub"
signed="$temp/signed-checkpoints"
expect_status 0 "signed anchor" as_role trust_audit_verifier verify "$signed" --anchor-key "$temp/anchor.key"
grep -q '^audit-chain-checkpoint v2 ' "$signed" || { echo "FAIL: no signed checkpoint" >&2; exit 1; }
expect_status 0 "public-key verifier" as_role trust_audit_verifier verify "$signed" --anchor-public-key "$temp/anchor.pub"
expect_status 3 "another anchor key" as_role trust_audit_verifier verify "$signed" --anchor-public-key "$temp/other.pub"
expect_status 1 "mismatched key pair" as_role trust_audit_verifier verify "$signed" \
  --anchor-key "$temp/anchor.key" --anchor-public-key "$temp/other.pub"
# Someone with file access but not the key edits the head: refused.
python3 - "$signed" <<'PY'
import sys
path = sys.argv[1]
parts = open(path).read().split(" ")
head = parts[3]
parts[3] = ("0" if head[0] != "0" else "1") + head[1:]
open(path, "w").write(" ".join(parts))
PY
expect_status 3 "edited signed checkpoint" as_role trust_audit_verifier verify "$signed" --anchor-public-key "$temp/anchor.pub"
grep -q "tampered_anchor" "$temp/out" || { cat "$temp/out" >&2; echo "FAIL: wrong finding" >&2; exit 1; }
# An unsigned line in a signed anchor is refused too.
expect_status 3 "unsigned line in a signed anchor" as_role trust_audit_verifier verify "$anchor" --anchor-public-key "$temp/anchor.pub"

# A superuser rewrites a sealed record and recomputes the chain: the
# database is internally consistent again, the exported checkpoints are not.
psql_run >/dev/null <<'SQL'
ALTER TABLE audit_event DISABLE TRIGGER prevent_audit_update;
UPDATE audit_event SET decision = 'forged' WHERE decision = 'first';
ALTER TABLE audit_event ENABLE TRIGGER prevent_audit_update;
ALTER TABLE audit_chain_entry DISABLE TRIGGER audit_chain_entry_append_only;
DELETE FROM audit_chain_entry;
ALTER TABLE audit_chain_entry ENABLE ALWAYS TRIGGER audit_chain_entry_append_only;
SELECT seal_audit_chain(100000);
SQL
expect_status 3 "rewritten history" as_role trust_audit_verifier verify "$anchor"
grep -q "CheckpointMismatch" "$temp/out" || { cat "$temp/out" >&2; echo "FAIL: wrong finding" >&2; exit 1; }
cmp -s "$anchor" "$temp/anchor.before" || { echo "FAIL: checkpoint appended after tampering" >&2; exit 1; }
# Without the external anchor the rewrite would pass: that is its purpose.
expect_status 0 "fresh anchor accepts the rewritten chain" \
  as_role trust_audit_verifier verify "$temp/fresh-anchor"

# A damaged anchor file fails closed.
echo "not a checkpoint" >>"$anchor"
expect_status 1 "damaged checkpoint file" as_role trust_audit_verifier verify "$anchor"

echo "PASS: sealed audit chain anchored outside the database (signed checkpoints) detects a superuser rewrite"
