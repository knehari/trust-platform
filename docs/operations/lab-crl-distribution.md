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
    relying parties see it is stale.
- At most 16 requests run concurrently; the others get 503.

```
TRUST_CRL_DATABASE_URL=postgresql://publisher@127.0.0.1/trust \
TRUST_CRL_BIND=127.0.0.1:8082 \
  cargo run -p trust-management-api --bin crl_distribution
```

The database connection uses the lab `NoTls` adapter; run it only against a
loopback or private lab database.

Issued certificates do not carry a CRL distribution points extension yet.
Covered by the unit tests in the binary and by `tests/crl_distribution.sh`,
which checks the served bytes against the database, verifies them with
OpenSSL and tampers with the stored CRL.
