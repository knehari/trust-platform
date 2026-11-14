# ADR-0035 — The audit checkpoint key in its own PKCS#11 token

**Status:** Proposed · 2026-11-11. It is not accepted; acceptance needs the
owner's decision and an independent security review (AGENTS.md). It extends
ADR-0034 (the CA key in a PKCS#11 token) to the signer's other private key.

**Scope:**
- the lab signer's audit key configuration and checkpoint signing;
- the laboratory ceremony tool (`--audit-key`);
- the compose signer service, `init-env.sh` and a new script;
- the certificate-application suite, the compose CI job and
  `tests/lab_signer_pkcs11.sh`.

**Supersedes in part:** ADR-0023, whose audit key was a PEM file that
`init-env.sh` generated into `.lab-keys/audit/` and the signer read from a
mount.

## Context

Signed audit checkpoints (ADR-0023) let a verifier holding the audit public
key detect a rewritten or rolled-back audit chain, even when the whole
database is compromised. That guarantee rests on the audit key: whoever
reads it can sign checkpoints over a forged chain. After ADR-0034 the CA key
is in a token, but the audit key was still a host file.

## Decision

1. **The audit key may be a token key.**
   - `TRUST_SIGNER_AUDIT_PKCS11_MODULE`, `_TOKEN_LABEL`, `_KEY_LABEL` and
     `_PIN` name it. They are exclusive with `TRUST_SIGNER_AUDIT_KEY_FILE`:
     at most one is set.
   - It goes through the same adapter as the CA key: a P-256 key, sensitive
     and never extractable, `CKM_ECDSA` over a SHA-256 digest computed by the
     signer, and each signature verified before use (ADR-0034).
   - The checkpoint logic, its message and its key identifier (SHA-256 of
     the SPKI) are unchanged.
2. **Separate tokens.** The signer refuses to start when the audit key's
   token is the CA key's token. Each token has its own user PIN
   (`TRUST_LAB_HSM_AUDIT_PIN`, `TRUST_LAB_HSM_PIN`), so neither PIN opens the
   other key. The existing check that the audit key is not the CA key also
   still applies.
3. **One module load.** When both keys use the same PKCS#11 module, the
   signer loads it once and opens both tokens from it, because dropping a
   module's last handle finalizes it for the whole process.
4. **Ceremony.** `trust-lab-ca-ceremony --audit-key`:
   - generates the key in the audit token, under a label no object uses
     yet;
   - prints only its SubjectPublicKeyInfo PEM.

   `scripts/lab/create-audit-key-hsm.sh` runs it in the signer container
   and writes `.lab-keys/audit/audit-checkpoint.pub.pem`. That public key
   comes from the token, never from the database. `lab_verify_audit_chain`
   checks checkpoints against it, as before.
5. **Compose.**
   - The entrypoint initialises the `trust-lab-audit` token beside
     `trust-lab-ca`.
   - The signer no longer mounts `.lab-keys/audit/`.
   - `init-env.sh` no longer generates an audit key file.
   - Until the ceremony runs, the signer refuses checkpoints with
     `AuditKeyFile`, and the API logs the refusal as an alert.

## Alternatives considered

- **Generate the audit key automatically at the first start.** Simpler,
  but a key would appear without an explicit act, and the public key would
  have to be fetched afterwards anyway. One explicit script, run once,
  keeps generation an operator act, as for the CA key.
- **One token for both keys.** Rejected: one PIN would unlock both, and a
  compromise of the CA role would also give the means to forge audit
  checkpoints.

## Consequences and open risks

- **SoftHSM2 is not an HSM** (ADR-0034). Both tokens sit in the same
  volume, in the same container, and their PINs are in the same `.env.lab`.
  The separation is logical; it is not a separation of custody.
- **A checkpoint gap before the ceremony.** On a fresh stack, checkpoints
  are refused until `create-audit-key-hsm.sh` runs. CI runs it right after
  the stack starts.
- **No backup.** Losing the volume loses the audit key. Verifiers keep the
  old public key and can still check old checkpoints, but new checkpoints
  need a new key. The signer's state file then names the old key and
  refuses (`AuditKeyChanged`) until it is reset on purpose.

## Tests

- `tests/lab_signer_pkcs11.sh` (Rust CI job), on throwaway SoftHSM2
  tokens:
  - the audit ceremony prints a P-256 public key PEM, which is the token's
    key;
  - the private key is sensitive, always sensitive, never extractable and
    local;
  - a second ceremony is refused (`KeyExists`);
  - the CA token's PIN does not open the audit token;
  - the signer refuses an audit key in the CA's token, and two audit key
    sources.
- The `crates/lab-signer` checkpoint unit tests run unchanged, generic over
  the key source.
- The certificate-application suite, locally against a signer on two
  SoftHSM2 tokens and in CI's compose job:
  - the latest checkpoint names the token key (its SPKI SHA-256);
  - its signature verifies in Node over the version-1 checkpoint message,
    with the public key the ceremony wrote.
- Locally, `lab_verify_audit_chain` with that public key and
  `TRUST_AUDIT_REQUIRE_CHECKPOINT=1` verified the chain and every
  checkpoint signature. The signer's log showed one `AuditKeyFile` refusal
  before the ceremony.
