# CA and certificate-profile lifecycle boundary

**Status:** laboratory design contract, 22 October 2026. No CA or profile
write route is authorized by this document. The current Rust management API,
database login and React console remain read-only. This contract refines
[ADR-0003](../adr/ADR-0003-authenticated-identity-and-csr-trust.md) and
[ADR-0005](../adr/ADR-0005-rust-management-control-plane.md); independent PKI
and security review, G0 and real identity provisioning remain open.

## Identities and immutable binding

Each CA has a UUID independent of its display name and policy text. A profile
is identified by `(ca_id, profile_id, revision)`: `profile_id` is a stable,
issuer-local ASCII identifier, and each positive revision is an immutable
snapshot. A later revision never rewrites the old one. The snapshot must
eventually capture the policy-enforced X.509 profile, allowed DNS zones,
algorithms, EKU/key usage, maximum lifetime, CP/CPS version and a digest of
the canonical policy data. An unreviewed JSON blob or CSR field cannot become
the effective policy. The existing `pki-policy` engine remains authoritative
for actor, name, algorithm and validity checks; a catalogue record is not an
`Authorization`.

An issuance request must bind its CA ID, exact profile revision and digest,
effective policy version, verified requester identity and CSR digest before
serial reservation or signing. The current `certificate_request` table lacks
the profile revision/digest fields, so the present laboratory issuance paths
must not be described as using this catalogue. A signer capability catalogue
entry does not establish that the selected provider can issue that profile.

## Profile states and actors

The intended state sequence is `DRAFT → SUBMITTED → APPROVED → ACTIVE →
RETIRED`; `REJECTED` is terminal for a submitted revision. A new draft
revision is created for any change after submission. At most one active
revision of a profile may be effective for a CA at a time. Retirement stops
new issuance but never changes the policy evidence on existing certificates.

- A **profile editor** may propose a draft within an authorized CA scope.
- A **policy approver** independently reviews the exact revision/digest.
  Approval requires a separately authenticated actor and a cryptographically
  distinct approval key, not merely a different string key ID.
- A **CA operator** may request activation only after approval and provider,
  issuer-certificate and CP/CPS compatibility checks. The policy engine and
  transactional store enforce the final active pointer, never the browser.
- A **reader** may see only profiles for a CA in both its signed token scope
  and the server-owned issuer/subject/CA grant. Reader credentials cannot
  insert, alter or activate profiles.

The first implementation may persist **draft snapshots only**, without any
activation or issuance authority. It must name them as drafts in SQL, API and
UI. A synthetic lab fixture may be inserted by the migration owner solely to
exercise the read path; it is not a human approval.

## CA states and key custody

The intended CA sequence is `PROPOSED → KEY_ATTESTED → APPROVED → ACTIVE →
SUSPENDED → RETIRED`. A CA cannot become active merely because a row exists in
`ca`: the row currently contains no validated issuer certificate, protected
key reference, possession proof or lifecycle state. Key generation/import,
custody evidence, algorithm capability, certificate self/chain verification,
two-person approval and publication endpoints are prerequisites. Suspending
or retiring a CA must deny new issuance through the Rust Core and preserve
historical evidence. Deleting a CA with issued certificates is not a normal
workflow.

## Trust and failure boundaries

The browser may submit a proposal but cannot choose an effective role, CA
scope, signer, serial or policy digest. The Rust service must verify identity,
role, issuer scope and server-owned grant before a write; a real IdP/workload
identity and write-specific database role are required before introducing a
mutating route. CSR subject and SAN are untrusted and never establish actor
identity. Profile/CA approval and activation must produce durable audit
events with actor, decision, revision/digest, policy version and operation ID.
Ambiguous signing remains quarantined; lifecycle retries must be idempotent
and must not silently re-sign or activate a partially provisioned CA.

The following negative evidence is required before activation or HTTP
issuance: wrong CA grant, wrong actor role, same actor/key in two approvals,
stale profile revision, altered digest, unsupported suite/provider, missing
protected key, policy version mismatch, invalid CSR proof of possession,
concurrent activation, interrupted transaction and replayed request. The
current auto-approved OIDC fixture is inadequate for human separation of
duties. No production mutation or issuance claim follows from a schema,
read-only API or green CI alone.
