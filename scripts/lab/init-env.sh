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
for name in TRUST_LAB_DB_PASSWORD TRUST_LAB_API_PASSWORD TRUST_LAB_KC_ADMIN_PASSWORD \
    TRUST_LAB_WORKLOAD_SECRET \
    TRUST_LAB_PW_READER TRUST_LAB_PW_EDITOR TRUST_LAB_PW_APPROVER_1 TRUST_LAB_PW_APPROVER_2 \
    TRUST_LAB_PW_OPERATOR TRUST_LAB_PW_OUTSIDER TRUST_LAB_PW_DISABLED TRUST_LAB_PW_OTHER_CA \
    TRUST_LAB_PW_FOREIGN; do
  if ! grep -q "^${name}=" .env.lab; then
    printf '%s=%s\n' "$name" "$(openssl rand -hex 24)" >> .env.lab
    added=$((added + 1))
  fi
done
chmod 600 .env.lab
echo "Private .env.lab ready for the disposable laboratory stack ($added value(s) added)."
