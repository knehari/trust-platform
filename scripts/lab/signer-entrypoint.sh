#!/bin/sh
# Laboratory signer container entrypoint (ADR-0034, ADR-0035, Proposed).
# Initialises, once and in the token volume, the SoftHSM2 tokens of the CA key
# (`$TRUST_SIGNER_PKCS11_TOKEN_LABEL`) and of the audit key
# (`$TRUST_SIGNER_AUDIT_PKCS11_TOKEN_LABEL`, when set), each with its own user
# PIN and the lab SO PIN from .env.lab; then drops the SO PIN from the
# environment and starts the signer. The keys themselves are generated later,
# inside the tokens, by trust-lab-ca-ceremony (scripts/lab/create-lab-root-hsm.sh
# and scripts/lab/create-audit-key-hsm.sh); nothing here creates or reads a key.
set -eu
: "${TRUST_SIGNER_PKCS11_TOKEN_LABEL:?}" "${TRUST_SIGNER_PKCS11_PIN:?}"
init_token() { # label pin
  if ! softhsm2-util --show-slots | grep -q "^ *Label: *$1 *\$"; then
    : "${TRUST_LAB_HSM_SO_PIN:?the token $1 does not exist yet: TRUST_LAB_HSM_SO_PIN is required}"
    softhsm2-util --init-token --free --label "$1" --so-pin "$TRUST_LAB_HSM_SO_PIN" --pin "$2" >/dev/null
    echo "{\"event\":\"lab_hsm_token_initialised\",\"token\":\"$1\"}" >&2
  fi
}
init_token "$TRUST_SIGNER_PKCS11_TOKEN_LABEL" "$TRUST_SIGNER_PKCS11_PIN"
if [ -n "${TRUST_SIGNER_AUDIT_PKCS11_TOKEN_LABEL:-}" ]; then
  : "${TRUST_SIGNER_AUDIT_PKCS11_PIN:?}"
  init_token "$TRUST_SIGNER_AUDIT_PKCS11_TOKEN_LABEL" "$TRUST_SIGNER_AUDIT_PKCS11_PIN"
fi
unset TRUST_LAB_HSM_SO_PIN
exec trust-lab-signer
