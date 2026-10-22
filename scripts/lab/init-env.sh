#!/bin/sh
set -eu

cd "$(dirname "$0")/../.."
umask 077
created=0
[ -e .env.lab ] || { : > .env.lab; created=1; }
chmod 600 .env.lab
# Adds only the missing variables: existing credentials stay as they are,
# since they match an existing database volume.
for name in TRUST_LAB_DB_PASSWORD TRUST_LAB_API_PASSWORD TRUST_LAB_HOUSEKEEPING_PASSWORD \
            TRUST_LAB_AUDITOR_PASSWORD TRUST_LAB_SEALER_PASSWORD; do
  if ! grep -q "^${name}=" .env.lab; then
    printf '%s=%s\n' "$name" "$(openssl rand -hex 24)" >> .env.lab
    [ "$created" = 1 ] || echo "Added $name to .env.lab (reset the lab volume to provision it)."
  fi
done
if [ "$created" = 1 ]; then
  echo 'Created private .env.lab for the disposable laboratory stack.'
else
  echo '.env.lab already exists; preserving its credentials.'
fi
