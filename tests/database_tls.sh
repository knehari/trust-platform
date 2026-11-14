#!/usr/bin/env bash
# Database TLS (ADR-0031): a throwaway PostgreSQL cluster that accepts only
# TLS connections, with a throwaway CA, and trust-db-check under the
# platform's policy (TRUST_DATABASE_CA_FILE). Needs initdb/pg_ctl and openssl.
# Nothing here is a secret: every key is generated, used and deleted.
set -euo pipefail

bindir=${TRUST_PG_BINDIR:-$(ls -d /usr/lib/postgresql/*/bin 2>/dev/null | sort -V | tail -n 1)}
check=${TRUST_DB_CHECK_BIN:-target/debug/trust-db-check}
port=${TRUST_TLS_TEST_PORT:-55471}
work=$(mktemp -d)
chmod 755 "$work"
run_pg() { if [[ $(id -u) = 0 ]]; then su postgres -s /bin/bash -c "$*"; else bash -c "$*"; fi; }
# pg_ctl refuses to run as root: stop the cluster as its owner.
trap 'run_pg "\"$bindir/pg_ctl\" -D \"$work/data\" -m immediate stop" >/dev/null 2>&1 || true; rm -rf "$work"' EXIT

# A CA, a server certificate for 127.0.0.1 and localhost, one for another
# name, and an unrelated CA.
cd "$work"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj '/CN=TLS Test CA' \
  -keyout ca.key -out ca.crt -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign 2>/dev/null
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj '/CN=Other CA' \
  -keyout other.key -out other.crt -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign 2>/dev/null
issue() { # name san
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=$1" -keyout "$1.key" -out "$1.csr" 2>/dev/null
  printf 'subjectAltName=%s\nextendedKeyUsage=serverAuth\n' "$2" > "$1.ext"
  openssl x509 -req -in "$1.csr" -CA ca.crt -CAkey ca.key -CAcreateserial -days 2 -extfile "$1.ext" -out "$1.crt" 2>/dev/null
}
issue server 'DNS:localhost,IP:127.0.0.1'
issue wrong 'DNS:wrong.invalid'
# Client certificates (ADR-0036): one per login, CN = login name; one for
# another login; one for the right login from another CA.
client() { # cn ca-prefix out
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=$1" -keyout "$3.key" -out "$3.csr" 2>/dev/null
  printf 'extendedKeyUsage=clientAuth\n' > "$3.ext"
  openssl x509 -req -in "$3.csr" -CA "$2.crt" -CAkey "$2.key" -CAcreateserial -days 2 -extfile "$3.ext" -out "$3.crt" 2>/dev/null
}
mkdir -p clients/good clients/swapped clients/foreign clients/mismatched clients/empty
client trust_mtls ca clients/good/trust_mtls
client trust_other ca clients/swapped/trust_mtls
client trust_mtls other clients/foreign/trust_mtls
cp clients/good/trust_mtls.crt clients/mismatched/trust_mtls.crt
cp clients/swapped/trust_mtls.key clients/mismatched/trust_mtls.key
cd - >/dev/null

mkdir "$work/data"
[[ $(id -u) = 0 ]] && chown -R postgres "$work"
run_pg "'$bindir/initdb' -D '$work/data' -U trust_tls --auth=trust >/dev/null"
cat >> "$work/data/postgresql.conf" <<CONF
ssl_ca_file = '$work/ca.crt'
listen_addresses = '127.0.0.1'
port = $port
unix_socket_directories = '$work'
ssl = on
ssl_cert_file = '$work/server.crt'
ssl_key_file = '$work/server.key'
ssl_min_protocol_version = 'TLSv1.2'
CONF
cat > "$work/data/pg_hba.conf" <<HBA
local     all all                trust
hostnossl all all 0.0.0.0/0      reject
hostssl   all trust_mtls 127.0.0.1/32 scram-sha-256 clientcert=verify-full
hostssl   all all 127.0.0.1/32   trust
HBA
[[ $(id -u) = 0 ]] && chown postgres "$work"/*.key "$work"/*.crt && chmod 600 "$work"/*.key
run_pg "'$bindir/pg_ctl' -D '$work/data' -l '$work/pg.log' -w start >/dev/null"

url="postgresql://trust_tls@127.0.0.1:$port/postgres"
fail() { echo "FAIL: $*" >&2; exit 1; }

# Verified TLS with the right CA.
out=$(TRUST_DATABASE_CA_FILE="$work/ca.crt" "$check" "$url" --require-tls) || fail "TLS with the CA: $out"
[[ $out == *'"tls":true'* ]] || fail "not encrypted: $out"
# The same with localhost: the name is checked, and it is in the certificate.
TRUST_DATABASE_CA_FILE="$work/ca.crt" "$check" "postgresql://trust_tls@localhost:$port/postgres" --require-tls >/dev/null \
  || fail 'localhost refused'
# Another CA: the server is not trusted.
if TRUST_DATABASE_CA_FILE="$work/other.crt" "$check" "$url" >/dev/null; then fail 'an untrusted server was accepted'; fi
# A URL that asks for plaintext while TLS is required: refused by the client.
out=$(TRUST_DATABASE_CA_FILE="$work/ca.crt" "$check" "$url?sslmode=disable" || true)
[[ $out == *'sslmode=disable'* ]] || fail "plaintext request not refused: $out"
# Without the policy, plaintext: refused by the server.
if "$check" "$url" >/dev/null; then fail 'the server accepted plaintext'; fi
# Mutual TLS (ADR-0036): a login whose server rule requires its certificate
# and its password.
run_pg "psql -h '$work' -p $port -U trust_tls -d postgres -qc \"CREATE ROLE trust_mtls LOGIN PASSWORD 'test-only-mtls'\""
murl="postgresql://trust_mtls:test-only-mtls@127.0.0.1:$port/postgres"
mtls() { TRUST_DATABASE_CA_FILE="$work/ca.crt" TRUST_DATABASE_CLIENT_CERT_DIR="$work/clients/$1" "$check" "${2:-$murl}" --require-tls; }
out=$(mtls good) || fail "mTLS with the login's certificate: $out"
[[ $out == *'"tls":true'* && $out == *'"client_dn":"/CN=trust_mtls"'* ]] || fail "mTLS not encrypted with the login certificate: $out"
out=$(TRUST_DATABASE_CA_FILE="$work/ca.crt" "$check" "$murl" || true)
[[ $out == *'certificate'* ]] || fail "no client certificate was accepted: $out"
out=$(mtls empty || true)
[[ $out == *'TRUST_DATABASE_CLIENT_CERT_DIR'* ]] || fail "a missing client certificate was not refused by the client: $out"
if mtls swapped >/dev/null; then fail "another login's certificate was accepted"; fi
if mtls foreign >/dev/null; then fail 'a certificate from another CA was accepted'; fi
out=$(mtls mismatched || true)
[[ $out == *'TRUST_DATABASE_CLIENT_CERT_DIR'* ]] || fail "a key that does not match the certificate was used: $out"
if mtls good "postgresql://trust_mtls:wrong-password@127.0.0.1:$port/postgres" >/dev/null; then fail 'the certificate replaced the password'; fi
out=$(TRUST_DATABASE_CLIENT_CERT_DIR="$work/clients/good" "$check" "$murl" || true)
[[ $out == *'TRUST_DATABASE_CLIENT_CERT_DIR'* ]] || fail "client certificates without a CA file were accepted: $out"
echo 'PASS: mutual TLS: the login certificate and the password are both required; other logins, other CAs, mismatched keys refused'

# A certificate for another name: refused even under the right CA.
cp "$work/wrong.crt" "$work/server.crt"; cp "$work/wrong.key" "$work/server.key"
[[ $(id -u) = 0 ]] && chown postgres "$work/server.crt" "$work/server.key"
run_pg "'$bindir/pg_ctl' -D '$work/data' reload >/dev/null"; sleep 1
if TRUST_DATABASE_CA_FILE="$work/ca.crt" "$check" "$url" >/dev/null; then fail 'a certificate for another name was accepted'; fi
# An unreadable CA file is an error, never a plaintext fallback.
if TRUST_DATABASE_CA_FILE="$work/missing.crt" "$check" "$url" >/dev/null; then fail 'a missing CA file was ignored'; fi

echo 'PASS: database TLS is required and verified (name and CA), with no plaintext fallback'
