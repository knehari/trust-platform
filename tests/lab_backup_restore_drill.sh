#!/usr/bin/env bash
# Laboratory recovery drill (ADR-0041, Proposed). Run from the repository
# root against a running laboratory stack whose lab issuing CA has published
# CRLs and whose audit key exists (scripts/lab/up.sh --reset --demo, or the
# CI compose job). It destroys and restores the stack several times.
#
# 1. Backup A, then restore it on a destroyed stack: the records match the
#    backup, the public CRL is republished and verifies under the issuing
#    CA, and the signer checkpoints new audit events: it accepts the
#    restored chain as the continuation of what it signed.
# 2. Backup B, then restore only A's database under B's signer state: the
#    signer refuses every checkpoint (AuditRollback); no checkpoint is
#    recorded. A rollback of the database is detected.
# 3. Restore B entirely: checkpoints resume.
#
# Each restore's duration is reported (a laboratory RTO, not a target).
set -euo pipefail
cd "$(dirname "$0")/.."
# Seal and checkpoint every 30 seconds (the shortest checkpoint interval)
# once the drill has restarted the worker.
export TRUST_LAB_AUDIT_INTERVAL_SECONDS=30
compose() {
  if [ -n "${TRUST_LAB_COMPOSE_OVERRIDE:-}" ]; then
    docker compose --env-file .env.lab -f compose.lab.yaml -f "$TRUST_LAB_COMPOSE_OVERRIDE" "$@"
  else
    docker compose --env-file .env.lab -f compose.lab.yaml "$@"
  fi
}
issuing_ca=dddddddd-dddd-4ddd-8ddd-dddddddddddd
issuing_root=.lab-keys/ca/ca-root-lab-issuing-ca.crt
[ -s "$issuing_root" ] || { echo "$issuing_root is missing: run the demo first" >&2; exit 1; }
work=.lab-backups/drill-$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p .lab-backups && chmod 700 .lab-backups
trap 'rm -rf "$work" "$work.crl"' EXIT

owner_sql() { docker exec -i "$(compose ps -q db)" psql -U trust_lab -d trust_lab -XAtq -v ON_ERROR_STOP=1 -c "$1"; }
counter() { # metric line name -> value, 0 when absent
  curl -fsS http://127.0.0.1:9464/metrics 2>/dev/null | awk -v name="$1" '$1 == name { value = $2 } END { print value + 0 }'
}
wait_until() { # seconds description command...
  local deadline=$(( $(date +%s) + $1 )) description=$2; shift 2
  until "$@"; do
    [ "$(date +%s)" -lt "$deadline" ] || { echo "FAIL: $description" >&2; return 1; }
    sleep 2
  done
}
signed() { [ "$(counter 'trust_audit_checkpoints_total{status="SIGNED"}')" -gt 0 ]; }
refused() { [ "$(counter 'trust_audit_checkpoints_total{status="REFUSED"}')" -gt 0 ]; }
drill_event() {
  owner_sql "INSERT INTO audit_event (event_id, ca_id, actor_id, event_type, decision, policy_version)
             VALUES (gen_random_uuid(), '$issuing_ca', 'recovery-drill', 'drill.recovery', 'allow', 'v1')" >/dev/null
}
checkpoint_seq() { owner_sql 'SELECT coalesce(max(seq), 0) FROM audit_chain_checkpoint'; }
fact() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["facts"][sys.argv[2]])' "$1/manifest.json" "$2"; }
public_crl_verifies() {
  curl -fsS -o "$work.crl" "http://127.0.0.1:8082/v1/public/crls/$issuing_ca/latest.crl" 2>/dev/null \
    && openssl crl -inform DER -in "$work.crl" -CAfile "$issuing_root" -noout 2>/dev/null
}

echo '== 1. Backup A, destroy the stack, restore A'
scripts/lab/backup.sh --out "$work/a"
start=$(date +%s)
scripts/lab/restore.sh --replace-stack "$work/a"
wait_until 60 'the restored worker reads the database' \
  sh -c 'curl -fsS http://127.0.0.1:9464/metrics | grep -qx "trust_metrics_database_up 1"'
wait_until 90 'the public CRL is republished and verifies under the issuing CA' public_crl_verifies
latest=$(owner_sql "SELECT max(crl_number) FROM crl_document WHERE ca_id = '$issuing_ca'")
served=$(openssl crl -inform DER -in "$work.crl" -noout -crlnumber | sed 's/^crlNumber=//')
[ "$((16#${served#0x}))" = "$latest" ] || { echo "FAIL: served CRL $served, latest $latest" >&2; exit 1; }
drill_event
wait_until 150 'the signer checkpoints the restored chain' signed
[ "$(checkpoint_seq)" -gt "$(fact "$work/a" checkpoint_seq)" ] \
  || { echo 'FAIL: no checkpoint beyond the backup' >&2; exit 1; }
echo "PASS: full restore, CRL republished, checkpoints resume ($(( $(date +%s) - start )) s to a new checkpoint)"

echo '== 2. Backup B, restore only A'"'"'s database under B'"'"'s signer state'
scripts/lab/backup.sh --out "$work/b"
before=$(checkpoint_seq)
scripts/lab/restore.sh --database-only "$work/a"
drill_event
wait_until 150 'the signer refuses to checkpoint a rolled-back database' refused
[ "$(counter 'trust_audit_checkpoints_total{status="SIGNED"}')" = 0 ] \
  || { echo 'FAIL: a rolled-back database was checkpointed' >&2; exit 1; }
[ "$(checkpoint_seq)" = "$(fact "$work/a" checkpoint_seq)" ] && [ "$(checkpoint_seq)" -lt "$before" ] \
  || { echo 'FAIL: unexpected checkpoints after the rollback' >&2; exit 1; }
compose logs worker 2>&1 | grep -q '"reason":"AuditRollback"' \
  || { echo 'FAIL: the worker did not log the signer'"'"'s AuditRollback' >&2; exit 1; }
echo 'PASS: database rollback detected (AuditRollback); no checkpoint recorded'

echo '== 3. Restore B entirely'
scripts/lab/restore.sh --replace-stack "$work/b"
drill_event
wait_until 150 'checkpoints resume after restoring the matching pair' signed
echo 'PASS: recovery drill'
