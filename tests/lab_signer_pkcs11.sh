#!/usr/bin/env bash
# PKCS#11 CA key (ADR-0034): a throwaway SoftHSM2 token, the signer's token
# adapter tests, and the laboratory key ceremony, checked with OpenSSL and
# OpenSC's pkcs11-tool. Needs softhsm2, opensc and openssl. Nothing here is a
# secret: the token, its PINs and its keys are generated, used and deleted.
set -euo pipefail

module=${TRUST_TEST_PKCS11_MODULE:-$(ls /usr/lib/softhsm/libsofthsm2.so /usr/lib/*/softhsm/libsofthsm2.so 2>/dev/null | head -n 1)}
[[ -n $module && -f $module ]] || { echo 'FAIL: SoftHSM2 module not found (install softhsm2)' >&2; exit 1; }
ceremony=${TRUST_CEREMONY_BIN:-target/debug/trust-lab-ca-ceremony}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/tokens"
printf 'directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\n' "$work/tokens" > "$work/softhsm2.conf"
export SOFTHSM2_CONF=$work/softhsm2.conf
pin=test-only-user-pin
softhsm2-util --init-token --free --label trust-test --so-pin test-only-so-pin --pin "$pin" >/dev/null
softhsm2-util --init-token --free --label trust-other --so-pin test-only-so-pin --pin "$pin" >/dev/null

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "PASS: $*"; }

# 1. The adapter against the token: generation, protection attributes,
#    signatures, refusals. One thread: each test opens and finalizes the module.
TRUST_TEST_PKCS11_MODULE=$module TRUST_TEST_PKCS11_TOKEN=trust-test TRUST_TEST_PKCS11_PIN=$pin \
  cargo test -q -p trust-lab-signer --lib ca_key -- --ignored --test-threads=1
pass 'token adapter tests'

# 2. The ceremony: a key in the token and a root certificate it signed.
export TRUST_SIGNER_PKCS11_MODULE=$module TRUST_SIGNER_PKCS11_TOKEN_LABEL=trust-test \
  TRUST_SIGNER_PKCS11_KEY_LABEL=ca-root-test-ceremony-ca TRUST_SIGNER_PKCS11_PIN=$pin
"$ceremony" 'Test Ceremony CA' 30 > "$work/root.crt"
openssl verify -check_ss_sig -CAfile "$work/root.crt" "$work/root.crt" >/dev/null || fail 'root does not verify'
text=$(openssl x509 -in "$work/root.crt" -noout -text)
names=$(openssl x509 -in "$work/root.crt" -noout -subject -issuer -nameopt RFC2253)
[[ $names = $'subject=CN=Test Ceremony CA\nissuer=CN=Test Ceremony CA' ]] || fail "names: $names"
grep -q 'Signature Algorithm: ecdsa-with-SHA256' <<<"$text" || fail 'algorithm'
grep -q 'ASN1 OID: prime256v1' <<<"$text" || fail 'curve'
grep -A1 'Basic Constraints: critical' <<<"$text" | grep -q 'CA:TRUE' || fail 'basicConstraints'
grep -A1 'Key Usage: critical' <<<"$text" | grep -q 'Certificate Sign, CRL Sign' || fail 'keyUsage'
ski=$(grep -A1 'Subject Key Identifier' <<<"$text" | tail -n 1 | tr -d ' ')
aki=$(grep -A1 'Authority Key Identifier' <<<"$text" | tail -n 1 | tr -d ' ' | sed 's/^keyid://')
[[ -n $ski && $ski = "$aki" ]] || fail 'key identifiers'
[[ $(openssl x509 -in "$work/root.crt" -noout -serial | cut -d= -f2 | wc -c) -eq 33 ]] || fail '16-byte serial'
# The certificate's key is the token's public key.
pkcs11-tool --module "$module" --token-label trust-test --read-object --type pubkey \
  --label ca-root-test-ceremony-ca -o "$work/pub.der" >/dev/null 2>&1
[[ $(openssl pkey -pubin -inform DER -in "$work/pub.der" -outform DER | sha256sum) = \
   $(openssl x509 -in "$work/root.crt" -noout -pubkey | openssl pkey -pubin -outform DER | sha256sum) ]] \
  || fail 'certificate key is not the token key'
pass 'ceremony root: self-signed by the token key, CA extensions, 16-byte serial'

# 3. The private key never leaves the token.
attributes=$(pkcs11-tool --module "$module" --token-label trust-test --login --pin "$pin" \
  --list-objects --type privkey --label ca-root-test-ceremony-ca 2>/dev/null)
grep -q 'Access: *sensitive, always sensitive, never extractable, local$' <<<"$attributes" || fail "attributes: $attributes"
grep -q 'Usage: *sign$' <<<"$attributes" || fail "usage: $attributes"
# The adapter tests (1) also show that CKA_VALUE is unreadable and that
# wrapping the key out under a caller's key fails.
pass 'private key generated in the token: sensitive, never extractable, sign only'

# 4. Refusals: a second ceremony under the same label, a wrong PIN, another
#    token. None creates an object.
count() { pkcs11-tool --module "$module" --token-label "$1" --login --pin "$pin" --list-objects 2>/dev/null | grep -c '^\(Private\|Public\) Key Object' || true; }
before=$(count trust-test)
if "$ceremony" 'Test Ceremony CA' 30 > /dev/null 2> "$work/err"; then fail 'key replaced'; fi
grep -q 'KeyExists' "$work/err" || fail "second ceremony: $(cat "$work/err")"
if TRUST_SIGNER_PKCS11_PIN=not-the-pin "$ceremony" 'Other CA' 30 > /dev/null 2> "$work/err"; then fail 'wrong PIN accepted'; fi
grep -q 'Token' "$work/err" || fail "wrong PIN: $(cat "$work/err")"
if TRUST_SIGNER_PKCS11_TOKEN_LABEL=no-such-token "$ceremony" 'Other CA' 30 > /dev/null 2> "$work/err"; then fail 'unknown token accepted'; fi
if "$ceremony" 'Bad/Name' 30 > /dev/null 2>&1; then fail 'invalid display name accepted'; fi
[[ $(count trust-test) = "$before" && $(count trust-other) = 0 ]] || fail 'a refused ceremony created objects'
pass 'refusals: existing label, wrong PIN, unknown token, invalid name; nothing created'

# 5. The audit checkpoint key (ADR-0035): generated in its own token; only the
#    public key leaves, and it is the token's.
softhsm2-util --init-token --free --label trust-audit --so-pin test-only-so-pin --pin test-only-audit-pin >/dev/null
export TRUST_SIGNER_AUDIT_PKCS11_MODULE=$module TRUST_SIGNER_AUDIT_PKCS11_TOKEN_LABEL=trust-audit \
  TRUST_SIGNER_AUDIT_PKCS11_KEY_LABEL=audit-checkpoint TRUST_SIGNER_AUDIT_PKCS11_PIN=test-only-audit-pin
"$ceremony" --audit-key > "$work/audit.pub.pem"
[[ $(head -n 1 "$work/audit.pub.pem") = '-----BEGIN PUBLIC KEY-----' ]] || fail 'audit key: not a public key PEM'
openssl pkey -pubin -in "$work/audit.pub.pem" -noout -text | grep -q 'ASN1 OID: prime256v1' || fail 'audit key curve'
pkcs11-tool --module "$module" --token-label trust-audit --read-object --type pubkey \
  --label audit-checkpoint -o "$work/audit.der" >/dev/null 2>&1
[[ $(openssl pkey -pubin -inform DER -in "$work/audit.der" -outform DER | sha256sum) = \
   $(openssl pkey -pubin -in "$work/audit.pub.pem" -outform DER | sha256sum) ]] || fail 'audit public key is not the token key'
attributes=$(pkcs11-tool --module "$module" --token-label trust-audit --login --pin test-only-audit-pin \
  --list-objects --type privkey 2>/dev/null)
grep -q 'Access: *sensitive, always sensitive, never extractable, local$' <<<"$attributes" || fail "audit attributes: $attributes"
if "$ceremony" --audit-key > /dev/null 2> "$work/err"; then fail 'audit key replaced'; fi
grep -q 'KeyExists' "$work/err" || fail "second audit ceremony: $(cat "$work/err")"
# The CA token's PIN does not open the audit token.
if TRUST_SIGNER_AUDIT_PKCS11_PIN=$pin "$ceremony" --audit-key > /dev/null 2>&1; then fail 'CA PIN opened the audit token'; fi
pass 'audit key: generated in its own token, only the public key out, not replaced'

# 6. The signer refuses an audit key in the CA's token, and two audit keys.
signer=${TRUST_SIGNER_BIN:-target/debug/trust-lab-signer}
startup() { env TRUST_SIGNER_SOCKET="$work/s.sock" TRUST_SIGNER_DATABASE_URL=postgresql://none@127.0.0.1:1/none \
  TRUST_SIGNER_CA_ID=dddddddd-dddd-4ddd-8ddd-dddddddddddd TRUST_SIGNER_AUDIT_STATE_FILE="$work/state.json" "$@" "$signer" 2>&1 || true; }
startup TRUST_SIGNER_AUDIT_PKCS11_TOKEN_LABEL=trust-test | grep -q 'another token than the CA key' || fail 'audit key in the CA token accepted'
startup TRUST_SIGNER_AUDIT_KEY_FILE="$work/none.pem" | grep -q 'at most one of' || fail 'two audit keys accepted'
pass 'signer: audit key never in the CA token, never two sources'

echo 'PKCS#11 CA and audit key tests passed.'
