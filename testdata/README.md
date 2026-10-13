# Test vectors

Public, non-secret test material only: certificates, CSRs, CRLs and malformed
DER samples used by unit, interoperability and fuzz tests.

- **Never** place private keys here, not even test keys. Tests that need a
  private key generate it at runtime.
- Record the origin of every external vector (tool, version, source URL) in a
  `SOURCES.md` next to it.
