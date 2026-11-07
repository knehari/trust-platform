#!/bin/sh
# Lab-only scheduler for the database jobs (compose service "jobs").
# Every TRUST_LAB_JOBS_INTERVAL_SECONDS (default 300) it runs, each under
# its own login:
#   crl_housekeeping --all           trust_crl_operator
#   audit_chain_anchor seal          trust_audit_sealer
#   audit_chain_anchor verify FILE   trust_audit_verifier (checkpoint file
#                                    on the jobs volume, outside the database)
#   signed_evidence_audit --all      trust_audit_verifier
# and prints one "job=<name> exit=<status>" line per job. A job that fails
# or alerts does not stop the others or the next round; alerting on those
# lines is left to whoever reads the logs (no paging in the lab).
# "trust-lab-jobs health" succeeds while the last round finished within
# three intervals (compose healthcheck).
set -u

interval=${TRUST_LAB_JOBS_INTERVAL_SECONDS:-300}
case $interval in
  '' | *[!0-9]*) echo "jobs: TRUST_LAB_JOBS_INTERVAL_SECONDS must be a number of seconds" >&2; exit 1 ;;
esac
if [ "$interval" -lt 10 ] || [ "$interval" -gt 86400 ]; then
  echo "jobs: TRUST_LAB_JOBS_INTERVAL_SECONDS must be 10 to 86400" >&2
  exit 1
fi
marker=${TRUST_LAB_JOBS_MARKER:-/tmp/trust-lab-jobs.last}

if [ "${1:-}" = health ]; then
  [ -f "$marker" ] || exit 1
  age=$(( $(date +%s) - $(stat -c %Y "$marker") ))
  [ "$age" -le $(( interval * 3 )) ]
  exit
fi

for name in TRUST_LAB_HOUSEKEEPING_URL TRUST_LAB_AUDITOR_URL TRUST_LAB_SEALER_URL; do
  eval "value=\${$name:-}"
  if [ -z "$value" ]; then
    echo "jobs: $name is not set" >&2
    exit 1
  fi
done
checkpoints=${TRUST_LAB_CHECKPOINT_FILE:-/var/lib/trust-jobs/checkpoints}

run() { # <job name> <database url> <command...>
  name=$1
  url=$2
  shift 2
  TRUST_DATABASE_URL=$url "$@"
  echo "job=$name exit=$?"
}

while :; do
  echo "jobs: round at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  run crl_housekeeping "$TRUST_LAB_HOUSEKEEPING_URL" crl_housekeeping --all
  run audit_chain_seal "$TRUST_LAB_SEALER_URL" audit_chain_anchor seal
  run audit_chain_verify "$TRUST_LAB_AUDITOR_URL" audit_chain_anchor verify "$checkpoints"
  run signed_evidence_audit "$TRUST_LAB_AUDITOR_URL" signed_evidence_audit --all
  touch "$marker"
  sleep "$interval"
done
