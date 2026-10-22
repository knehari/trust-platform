# RFC 5280 path-validation suite (lab)

Lab only. This suite checks that the certificates and CRLs the platform
produces are accepted or refused by two independent RFC 5280 validators,
each for the expected reason. The platform's own checks are not the judge.

- `crates/pki-core/tests/rfc5280_path_validation.rs` (feature
  `lab-software`) builds the artifacts and checks every case with
  [rustls-webpki](https://github.com/rustls/webpki). The artifacts come from
  the lab issuer (`EphemeralLabCa::issue_leaf` from verified PKCS#10
  requests) and the CRL pipeline (`crl_once`: intent, one signature,
  independent verification).
- `tests/rfc5280_path_validation.sh` exports the same artifacts and a
  manifest, then replays every case with `openssl verify` (`-attime`,
  `-purpose`, `-crl_check`, `-verify_hostname`).

Both run in the `rust` CI job. A case passes only if the outcome
matches and, for an invalid case, the error is the expected one.

## Cases

| Case | RFC 5280 | Expected | webpki | OpenSSL |
| --- | --- | --- | --- | --- |
| valid_leaf | 6.1 | valid | — | — |
| before_not_before | 6.1.3 (a)(2) | invalid | CertNotValidYet | certificate is not yet valid |
| after_not_after | 6.1.3 (a)(2) | invalid | CertExpired | certificate has expired |
| same_name_other_key_anchor | 6.1.3 (a)(1), (a)(4) | invalid | InvalidSignatureForPublicKey | unable to get local issuer certificate |
| altered_signature | 6.1.3 (a)(1) | invalid | InvalidSignatureForPublicKey | certificate signature failure |
| altered_signed_content | 6.1.3 (a)(1) | invalid | InvalidSignatureForPublicKey | certificate signature failure |
| wrong_host_name | 4.2.1.6 | invalid | CertNotValidForName | hostname mismatch |
| wrong_extended_key_usage | 4.2.1.12 | invalid | RequiredEkuNotFound | unsuitable certificate purpose |
| revoked_key_compromise | 6.1.3 (a)(3) | invalid | CertRevoked | certificate revoked |
| on_hold | 6.1.3 (a)(3) | invalid | CertRevoked | certificate revoked |
| not_listed | 6.3 | valid | — | — |
| hold_released (next CRL) | 6.3 | valid | — | — |
| still_revoked_on_next_crl | 6.3 | invalid | CertRevoked | certificate revoked |
| crl_within_next_update | 6.3.3 | valid | — | — |
| crl_past_next_update | 6.3.3 (a) | invalid | CrlExpired | CRL has expired |
| crl_signed_by_other_key | 6.3.3 (f) | invalid | InvalidCrlSignatureForPublicKey | unable to get certificate CRL |
| end_entity_used_as_ca | 6.1.4 (k) | invalid | EndEntityUsedAsCa | invalid CA certificate |

Where the two validators report different errors, both still refuse:

- The look-alike root has the same name as the real root but a different
  key. OpenSSL selects the issuer by the leaf's authority key identifier,
  so it finds none. webpki selects by name, then the signature fails.
- For a CRL signed by the look-alike key, OpenSSL ignores it (its AKI does
  not match), so the status is unknown and refused. webpki rejects the
  signature.

Revocation is checked with an unknown status refused and nextUpdate
enforced. The suite uses CRLs only: there is no OCSP.

The negative certificates are made by the test itself, never by the
platform:
- the two altered copies of a leaf;
- the certificate signed with a leaf's key, which needs a leaf issued from
  a request whose key the test holds.

## Evidence that it detects a platform defect

As a mutation, the lab issuer was changed to issue leaves with cA true.
The suite then fails: webpki reports `CaUsedAsEndEntity` for 15 of the 17
cases, starting with `valid_leaf`. The source was restored afterwards.

## Not covered

- Intermediate CAs, name constraints, policy mapping and inhibitAnyPolicy:
  the lab issuer has a single level and no policy constraints.
- Delta CRLs: the platform does not issue them yet, and webpki does not
  process them.
- OCSP, and algorithms other than ECDSA P-256 with SHA-256 on this path.
  The RSA and other classical lab chains have their own OpenSSL tests.
- The NIST PKITS or a full conformance corpus.
