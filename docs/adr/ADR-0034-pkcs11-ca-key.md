# ADR-0034 — The CA key in a PKCS#11 token (SoftHSM2 in the laboratory)

**Status:** Proposed · 2026-11-11. It is not accepted; acceptance needs the
owner's decision and an independent security review (AGENTS.md). It
addresses the review's P0 item "PKCS#11/HSM" for the laboratory only.

**Scope:**
- the lab signer (`trust-lab-signer`): a PKCS#11 key source beside the
  software key file;
- a new laboratory ceremony tool, `trust-lab-ca-ceremony`;
- the compose signer service and image, `init-env.sh`, a ceremony script;
- the certificate-application end-to-end suite;
- CI.

**Out of scope:**
- a real HSM, a vendor module, FIPS-validated hardware, key backup and
  restore, cloning, and multi-person (M of N) ceremony controls;
- the audit checkpoint key (ADR-0023), which stays a software file;
- proposed CA roots other than the lab issuing CA, which stay software keys
  (`create-lab-root.sh`).

**Supersedes in part:** ADR-0017 and ADR-0013, which kept the lab issuing
CA's key in a software file on the host, read by the signer for each
request.

## Context

The lab issuing CA's private key was a PEM file in `.lab-keys/ca/`. Anyone
who could read that host directory, or the signer container's mount, held
the CA. The review ranks hardware or token custody of CA keys as P0. This
container now provides SoftHSM2 2.6, a software PKCS#11 token, which lets
the platform build and test the PKCS#11 boundary itself: the code that a
real HSM would use, without claiming the protection a real HSM gives.

## Decision

1. **One signing contract, two key sources.** The signer signs through a
   `CaKey` trait: the public key, and a DER ECDSA P-256 / SHA-256 signature
   over a message. The software key file and the PKCS#11 key implement it.
   The policy checks before signing are unchanged and identical for both.
   The source is chosen at startup: exactly one of `TRUST_SIGNER_KEY_FILE`
   or `TRUST_SIGNER_PKCS11_MODULE` (with `_TOKEN_LABEL`, `_KEY_LABEL` and
   `_PIN`). Both, or neither, is a startup error; there is no fallback. The
   startup log names the source (`"ca_key": "pkcs11"`).
2. **The PKCS#11 signature contract.**
   - The message is the exact DER of the TBSCertificate or TBSCertList.
   - The signer computes SHA-256 itself and signs the 32-byte digest with
     `CKM_ECDSA`. It never uses a combined hash-and-sign mechanism, so the
     hash is always the one `ecdsa-with-SHA256` names.
   - The token returns `r || s` (64 bytes); the signer re-encodes it as the
     DER `ECDSA-Sig-Value`.
   - The signer verifies each signature under the token's public key before
     returning it.
   - The signer still checks the token's public key against the CA's
     attested issuer key for each request (ADR-0017).
3. **Only protected keys are used.** For each operation, the signer opens a
   session, logs in as user and finds exactly one private and one public key
   with the configured label. It uses the private key only when the token
   reports all of the following:
   - an EC key on P-256 (`CKA_EC_PARAMS` = prime256v1);
   - `CKA_SIGN`;
   - `CKA_SENSITIVE` and `CKA_ALWAYS_SENSITIVE`;
   - not `CKA_EXTRACTABLE`, and `CKA_NEVER_EXTRACTABLE`.

   An imported or once-extractable key is refused (`KeyNotProtected`). A
   missing key is `KeyFile`. A module, token, PIN or signature failure is
   `Token`.
4. **The ceremony generates the key in the token.**
   `trust-lab-ca-ceremony "<name>" [days]`:
   - generates the key pair inside the token, under a label no object uses
     yet. The private key is sensitive, not extractable, sign-only; the
     public key is verify-only;
   - builds the same root certificate as `create-lab-root.sh`:
     - `CN=<name>`;
     - basicConstraints critical CA;
     - keyUsage critical keyCertSign and cRLSign;
     - subject and authority key identifiers (RFC 7093 method 1);
     - a 16-byte positive serial from the token's generator;
   - has the token sign the certificate, verifies the signature
     independently, and prints only the certificate.

   It refuses an existing label (`KeyExists`) and never replaces a key.
5. **The laboratory stack uses the token for the lab issuing CA.**
   - The signer image installs SoftHSM2 and keeps its tokens in the
     `trust_signer_hsm` volume.
   - The entrypoint initialises the `trust-lab-ca` token once, with the SO
     and user PINs that `init-env.sh` generates into `.env.lab`. It then
     removes the SO PIN from the environment and starts the signer.
   - `scripts/lab/create-lab-root-hsm.sh "Lab Issuing CA"` runs the
     ceremony in the signer container. Only the certificate reaches
     `.lab-keys/ca/`.
   - The signer no longer mounts `.lab-keys/ca/`.
   - `docker compose down -v` destroys the token with the stack.

## Alternatives considered

- **OpenSSL with a PKCS#11 provider or engine for the ceremony.** That adds
  a provider package and configuration to the image. The ceremony in Rust
  reuses the adapter, so the root is signed by exactly the code path that
  later signs certificates.
- **`CKM_ECDSA_SHA256`.** It is simpler, but whether the hash is applied
  depends on the module. Pre-hashing with `CKM_ECDSA` makes the signed
  bytes explicit and is the mechanism most HSMs support for P-256.
- **Keep the key file and encrypt it.** The key would still be decrypted in
  the signer's memory. A token key never is.
- **`cryptoki` 0.10.0** (Apache-2.0, Parsec project) is the maintained Rust
  PKCS#11 wrapper. It adds `cryptoki-sys`, `libloading`, `secrecy`,
  `paste` and `bitflags` 1 to the lockfile. Its `unsafe` FFI is confined to
  that crate; the signer adds no `unsafe` code.

## Consequences and open risks

- **SoftHSM2 is not an HSM.** Its token files are encrypted under the user
  PIN, but anyone who holds both the volume and the PIN holds the key. Its
  RNG and implementation are not certified. This slice proves the PKCS#11
  boundary and the ceremony flow, not hardware custody. A real HSM still
  needs vendor testing, timeouts, session pooling and an approved custody
  design (ROADMAP v2.7).
- **PINs in the environment.** The user PIN is in the signer's
  environment. The SO PIN is in the container's configuration until the
  token exists; the entrypoint drops it before the signer starts. Both are
  lab secrets in `.env.lab`. A deployment should use a secret store, or the
  HSM's own authentication.
- **No backup.** Destroying the volume destroys the CA key. That suits the
  disposable lab; a real CA needs an HSM backup or cloning procedure, and a
  recovery test.
- **One-person ceremony.** No witness, quorum, recorded minutes or split
  PINs. ROADMAP v3.6 covers ceremony as code.
- **Per-operation sessions.** Each signature opens a session and logs in.
  That is enough for the lab's one request at a time. A deployment would
  pool sessions and bound each token call with a timeout. A signature that
  fails after the database claim is the ambiguous outcome that ADR-0017
  already reconciles; it is never retried silently.
- **Ceremony through the running signer.** The ceremony runs as a second
  process in the signer container. A deployment would separate ceremony
  and signing roles in the token: different users or key-usage policies.

## Tests

- `crates/lab-signer` unit tests: `CKA_EC_POINT` forms, re-encoding of
  `r || s`, and refusal of malformed points and signatures.
- `tests/lab_signer_pkcs11.sh`, run in the Rust CI job against a throwaway
  SoftHSM2 token:
  - the adapter tests:
    - generation, signatures that verify;
    - `KeyExists` on the same label;
    - `CKA_VALUE` unreadable;
    - wrapping the key out under a caller's key fails;
    - an extractable key is refused;
    - a wrong PIN or an unknown token is refused;
  - the ceremony root, checked with OpenSSL:
    - self-signed by the token's key;
    - subject and issuer;
    - `ecdsa-with-SHA256` on P-256;
    - CA basic constraints and key usage;
    - matching key identifiers;
    - a 16-byte serial;
  - the token's attributes, checked with OpenSC's `pkcs11-tool`: sensitive,
    always sensitive, never extractable, local, sign-only;
  - refused ceremonies (existing label, wrong PIN, unknown token, invalid
    name) create no object.
- The certificate-application suite, locally against a signer on a
  SoftHSM2 token, and in CI's compose job:
  - the ceremony leaves only the certificate on the host, and the API
    accepts that root;
  - certificates and CRLs signed through the token verify with OpenSSL;
  - the revocation and CRL steps pass as before.
