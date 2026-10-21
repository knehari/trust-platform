#!/usr/bin/env bash
set -euo pipefail

# The supplied URL must name a new, disposable PostgreSQL database. This is
# an upgrade regression, not an online migration runner for deployed data.
: "${TRUST_UPGRADE_DATABASE_URL:?set TRUST_UPGRADE_DATABASE_URL to an empty disposable database}"
psql_bin=${TRUST_PSQL_BIN:-psql}

for migration in migrations/000*.sql migrations/0010*.sql migrations/0011*.sql; do
  "$psql_bin" "$TRUST_UPGRADE_DATABASE_URL" -X -v ON_ERROR_STOP=1 -f "$migration" >/dev/null
done
"$psql_bin" "$TRUST_UPGRADE_DATABASE_URL" -X -v ON_ERROR_STOP=1 -f tests/management_populated_upgrade_seed.sql >/dev/null

for migration in migrations/0012*.sql migrations/0013*.sql migrations/0014*.sql migrations/0015*.sql; do
  "$psql_bin" "$TRUST_UPGRADE_DATABASE_URL" -X -v ON_ERROR_STOP=1 -f "$migration" >/dev/null
done
"$psql_bin" "$TRUST_UPGRADE_DATABASE_URL" -X -v ON_ERROR_STOP=1 -f tests/management_populated_upgrade_verify.sql >/dev/null
"$psql_bin" "$TRUST_UPGRADE_DATABASE_URL" -X -v ON_ERROR_STOP=1 -f tests/management_api_readonly.sql >/dev/null

echo 'PASS: populated 0011 -> 0015 management upgrade preserved rows and read-only grants'
