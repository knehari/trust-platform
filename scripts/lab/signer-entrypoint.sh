#!/bin/sh
# Laboratory signer container entrypoint (ADR-0034, Proposed).
# Initialises the SoftHSM2 token `$TRUST_SIGNER_PKCS11_TOKEN_LABEL` once, in
# the token volume, with the lab SO and user PINs from .env.lab; then drops
# the SO PIN from the environment and starts the signer. The CA key itself is
# generated later, inside the token, by trust-lab-ca-ceremony
# (scripts/lab/create-lab-root-hsm.sh); nothing here creates or reads a key.
set -eu
: "${TRUST_SIGNER_PKCS11_TOKEN_LABEL:?}" "${TRUST_SIGNER_PKCS11_PIN:?}"
if ! softhsm2-util --show-slots | grep -q "^ *Label: *${TRUST_SIGNER_PKCS11_TOKEN_LABEL} *\$"; then
  : "${TRUST_LAB_HSM_SO_PIN:?the token does not exist yet: TRUST_LAB_HSM_SO_PIN is required}"
  softhsm2-util --init-token --free --label "$TRUST_SIGNER_PKCS11_TOKEN_LABEL" \
    --so-pin "$TRUST_LAB_HSM_SO_PIN" --pin "$TRUST_SIGNER_PKCS11_PIN" >/dev/null
  echo "{\"event\":\"lab_hsm_token_initialised\",\"token\":\"$TRUST_SIGNER_PKCS11_TOKEN_LABEL\"}" >&2
fi
unset TRUST_LAB_HSM_SO_PIN
exec trust-lab-signer
