#!/bin/sh
set -eu

# Creates, or completes, the private .env.lab of the disposable laboratory
# stack. Existing values are never replaced: rotating a database password
# underneath a running volume would lock the stack out. Values missing from
# an older .env.lab (such as the Keycloak credentials) are appended.
cd "$(dirname "$0")/../.."
umask 077
[ -e .env.lab ] || : > .env.lab
added=0
for name in TRUST_LAB_DB_PASSWORD TRUST_LAB_API_PASSWORD TRUST_LAB_WRITER_PASSWORD \
    TRUST_LAB_HOUSEKEEPING_PASSWORD TRUST_LAB_AUDITOR_PASSWORD TRUST_LAB_SEALER_PASSWORD \
    TRUST_LAB_KC_ADMIN_PASSWORD \
    TRUST_LAB_WORKLOAD_SECRET \
    TRUST_LAB_PW_READER TRUST_LAB_PW_EDITOR TRUST_LAB_PW_APPROVER_1 TRUST_LAB_PW_APPROVER_2 \
    TRUST_LAB_PW_OPERATOR TRUST_LAB_PW_OUTSIDER TRUST_LAB_PW_DISABLED TRUST_LAB_PW_OTHER_CA \
    TRUST_LAB_PW_FOREIGN TRUST_LAB_PW_AUTHOR; do
  if ! grep -q "^${name}=" .env.lab; then
    printf '%s=%s\n' "$name" "$(openssl rand -hex 24)" >> .env.lab
    added=$((added + 1))
  fi
done

# Laboratory approver keys (ADR-0011): one P-256 key per approver, generated
# by OpenSSL into the ignored .lab-keys/ directory. Only the public point
# (uncompressed SEC1, hex) goes into .env.lab, for the database to register.
# These software keys are for the disposable laboratory only.
mkdir -p .lab-keys
chmod 700 .lab-keys
for approver in 1 2; do
  key=".lab-keys/lab-approver-$approver.pem"
  name="TRUST_LAB_APPROVER_${approver}_SEC1"
  if [ ! -s "$key" ]; then
    openssl ecparam -name prime256v1 -genkey -noout -out "$key"
    sed -i.bak "/^${name}=/d" .env.lab && rm -f .env.lab.bak
  fi
  chmod 600 "$key"
  if ! grep -q "^${name}=" .env.lab; then
    point=$(openssl ec -in "$key" -pubout -outform DER -conv_form uncompressed 2>/dev/null \
      | tail -c 65 | od -An -v -tx1 | tr -d ' \n')
    case "$point" in
      04????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????) ;;
      *) echo "Could not read the public key of $key" >&2; exit 1 ;;
    esac
    printf '%s=%s\n' "$name" "$point" >> .env.lab
    added=$((added + 1))
  fi
done
chmod 600 .env.lab
echo "Private .env.lab ready for the disposable laboratory stack ($added value(s) added)."
