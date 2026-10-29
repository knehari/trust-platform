# Laboratory CRL distribution point

Lab only (migration 0030). It is not a production publication service: no
TLS termination, no CDN, no availability or ETSI EN 319 411-1 publication
commitments.

`crates/management-api/src/bin/crl_distribution.rs` answers
`GET /crl/<ca-uuid>.crl` (and `HEAD`) with the CA's latest `STORED` CRL as
`application/pkix-crl` (RFC 5280 4.2.1.13, RFC 2585 4.2). Relying parties
fetch CRLs anonymously, so the endpoint has no authentication. It has no
write path either:

- The database login must hold only `trust_crl_publisher`, which may call
  `published_crl` and nothing else. The binary refuses to start with a
  superuser, an owner-role member, or a login holding any table privilege.
- Before serving, it re-checks the CRL (`crl::verify_published_crl`):
  - the DER is canonical;
  - the signature is ECDSA P-256/SHA-256, issued and signed by the CA's
    registered issuer certificate;
  - the CRL number, thisUpdate and nextUpdate equal what the database
    reports.

  A CRL altered in the database is refused with 503 and logged
  (`crl_refused_verification_failed`); it is never served.
- Only `<canonical lowercase uuid>.crl` paths are answered. Anything else,
  an unknown CA or a CA without a stored CRL gets 404.
- Response headers:
  - `ETag` is the CRL number;
  - `Last-Modified` is thisUpdate and `Expires` is nextUpdate;
  - `Cache-Control: public, max-age` runs until nextUpdate, capped at one
    hour;
  - a CRL past its nextUpdate is still served, with `no-cache`, so that
    relying parties see it is stale;
  - conditional requests (RFC 9110 §13): `If-None-Match` (weak comparison, `*`
    accepted) and otherwise `If-Modified-Since` against thisUpdate get
    `304 Not Modified` with the same validators and cache headers. The
    answer is given only after re-verification, so a client holding a CRL
    whose stored copy was altered gets 503, not 304.
- Delta CRLs (migration 0059, RFC 5280 5.2.4) are served at
  `GET /delta/<ca-uuid>.crl`: the CA's latest stored delta CRL, re-checked
  with `crl::verify_published_delta_crl`. It requires exactly one critical
  delta CRL indicator naming a base below the CRL number; the other checks
  are as above.
  - The two endpoints never mix. `published_crl` returns complete CRLs only,
    and `verify_published_crl` refuses a delta. A database answer of the
    wrong kind gets 503 at either endpoint.
  - A CA without a stored delta gets 404 at `/delta`.
  - Point the CA's `ca_revocation_policy.delta_crl_url` (the freshestCRL
    its complete CRLs carry) at this path.
- At most 16 requests run concurrently; the others get 503.
- Each client address (an IPv4 address, or an IPv6 /64) may make 600
  requests per minute; beyond that it gets 429, so one client cannot keep
  the 16 slots from the others. Per process. Behind a reverse proxy, list
  it in `TRUST_HTTP_TRUSTED_PROXIES` (addresses or CIDR prefixes) so that
  each client is counted by its X-Forwarded-For address; from any other
  peer the header is ignored. When 10,000 addresses are already in their window (a flood from many addresses, such as the /64s of one IPv6 /48), a new address is counted under its /48 (IPv4: /24) instead, so a flood spends its own prefix's budget; only if 10,000 prefixes are live as well is the request refused. Connections are bounded too (`http_serve`): at most 1,024 at once per process (a new one beyond that is closed at once), and each request header must arrive within 10 seconds or the connection is closed, and a request, its body included, must be answered within 30 seconds or it gets 408 and the connection is closed, so slow or idle clients cannot hold sockets. HTTP/1.1 only, as the TLS listener advertises.
- A CRL that re-verified is reused for 30 seconds (never past its
  nextUpdate) without querying the database or re-verifying, so a flood of
  requests costs neither. A newly stored CRL is served at most that much
  later, and a CRL altered in the database is refused (and logged) at most
  that much later, the verified copy being served meanwhile.
  `TRUST_CRL_REUSE_SECONDS` sets the window (0 disables it, at most 300;
  anything else refuses to start).

```
TRUST_CRL_DATABASE_URL=postgresql://publisher@db.lab.invalid/trust \
TRUST_DATABASE_CA_FILE=/etc/trust/db-ca.pem \
TRUST_CRL_BIND=127.0.0.1:8082 \
  cargo run -p trust-management-api --bin crl_distribution
```

The database connection follows the management API's policy (SEC-03/D-03):
- TLS 1.3, with the server certificate checked against
  `TRUST_DATABASE_CA_FILE` and the host name checked, by default;
- any `sslmode` in the URL is overridden;
- plaintext only with the explicit lab opt-out `TRUST_DATABASE_TLS=disable-lab`,
  which is logged (`crl_database_tls_disabled_lab`).

`tests/management_db_tls.sh` shows, against a TLS-only PostgreSQL, that the
binary reaches its login check with the trusted CA and gets no session with
an unrelated CA or another host name.

Issued certificates name it in a cRLDistributionPoints extension (RFC 5280
4.2.1.13) when the lab CA is configured with
`EphemeralLabCa::set_crl_distribution_point(&x509_extensions::crl_distribution_url(base, ca_id))`.
The extension is non-critical and holds one distribution point whose fullName
is one plain `http://` URI. HTTPS is refused: it would make revocation
checking depend on another certificate's revocation status. The independent
`LabX509Verifier` requires exactly the approved URL
(`with_crl_distribution_point`) and refuses a certificate carrying a
distribution point it was not told to expect. The configuration is
per-process (lab CA); persisting it per CA is open.

`tests/crl_distribution_point_e2e.sh` lets OpenSSL (`verify -crl_check
-crl_download`) follow the URL in issued certificates to this binary: the
revoked leaf is refused and the valid one accepted. OpenSSL 3.0 can spin when
a distribution point refuses connections, so the script runs it under a
timeout.
Covered by the unit tests in the binary and by `tests/crl_distribution.sh`,
which checks the served bytes against the database, verifies them with
OpenSSL and tampers with the stored CRL.

## Delta CRLs and relying parties

`tests/crl_delta_openssl.sh` checks a delta CRL stored through PostgreSQL
against its base with OpenSSL 3.0, which needs both `-use_deltas` and
`-extended_crl`. With only `-use_deltas`, or with neither, OpenSSL picks the
newest of the CRLs it is given as the complete CRL, even if it is a delta.
A certificate revoked only in the base then verifies as valid. This was
observed when the delta's thisUpdate was later than the base's. That is why
the CDP never serves a delta: a client that fetches only the CDP gets the
complete CRL. A client given both files must enable extended CRL support.

The HTTP contract is `openapi/crl-distribution-v1.yaml`; CI checks it against
the served routes (`scripts/ci/openapi_routes.py`).
