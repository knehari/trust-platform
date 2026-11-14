#!/bin/sh
set -eu

# Laboratory only (ADR-0035, Proposed). Generates the signer's audit
# checkpoint key (ADR-0023) inside its own SoftHSM2 token, sensitive and never
# extractable, and writes only its public key to
# .lab-keys/audit/audit-checkpoint.pub.pem, the key lab_verify_audit_chain
# checks checkpoints against. Run once, with the stack up; until then the
# signer refuses checkpoints (AuditKeyFile) and the API logs the refusal.
#
# The ceremony runs in the running signer container, which holds the token.
# TRUST_LAB_CEREMONY replaces that command (e.g. a local build with
# SOFTHSM2_CONF and the TRUST_SIGNER_AUDIT_PKCS11_* variables set).
cd "$(dirname "$0")/../.."
umask 077
mkdir -p .lab-keys/audit
chmod 700 .lab-keys .lab-keys/audit
public=.lab-keys/audit/audit-checkpoint.pub.pem
trap 'rm -f "$public.tmp"' EXIT
ceremony=${TRUST_LAB_CEREMONY:-docker compose --env-file .env.lab -f compose.lab.yaml exec -T signer trust-lab-ca-ceremony}
# shellcheck disable=SC2086 # the command is a word list
$ceremony --audit-key > "$public.tmp"
chmod 644 "$public.tmp"
mv "$public.tmp" "$public"
cat "$public"
