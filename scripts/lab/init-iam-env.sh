#!/bin/sh
set -eu

cd "$(dirname "$0")/../.."
if [ -e .env.iam.lab ]; then
  echo '.env.iam.lab already exists; preserving it.'
  exit 0
fi
umask 077
{
  printf 'TRUST_IAM_DB_PASSWORD=%s\n' "$(openssl rand -hex 24)"
  printf 'TRUST_IAM_API_PASSWORD=%s\n' "$(openssl rand -hex 24)"
  printf 'TRUST_IAM_ADMIN_PASSWORD=%s\n' "$(openssl rand -hex 24)"
  printf 'TRUST_IAM_MAKER_PASSWORD=%s\n' "$(openssl rand -hex 24)"
  printf 'TRUST_IAM_CHECKER_PASSWORD=%s\n' "$(openssl rand -hex 24)"
  printf 'TRUST_IAM_WORKLOAD_SECRET=%s\n' "$(openssl rand -hex 24)"
} > .env.iam.lab
echo 'Created ignored .env.iam.lab for the isolated IAM laboratory.'
