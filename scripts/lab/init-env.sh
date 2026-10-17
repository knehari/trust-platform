#!/bin/sh
set -eu

cd "$(dirname "$0")/../.."
if [ -e .env.lab ]; then
  echo '.env.lab already exists; preserving it.'
  exit 0
fi
umask 077
{
  printf 'TRUST_LAB_DB_PASSWORD=%s\n' "$(openssl rand -hex 24)"
  printf 'TRUST_LAB_API_PASSWORD=%s\n' "$(openssl rand -hex 24)"
} > .env.lab
echo 'Created private .env.lab for the disposable laboratory stack.'

