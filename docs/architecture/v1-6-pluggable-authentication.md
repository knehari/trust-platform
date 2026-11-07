# V1.6 — Pluggable authentication architecture (draft)

## Requirement
Trust Platform MUST support more than one enterprise authentication standard without binding its PKI, CLM, ceremony, audit or governance domain code to one IdP vendor or protocol.

## Protocol adapter categories
- **OIDC**: interactive SSO with strict JWKS/signature, issuer, audience, nonce, expiry, authorized algorithms, PKCE and session validation.
- **SAML 2.0**: enterprise federation with signed assertion and response handling, recipient, destination, InResponseTo, audience, time and replay controls; XML signature wrapping defenses.
- **Kerberos/SPNEGO**: domain-integrated authentication with SPN, ticket/channel binding and replay constraints.
- **X.509/mTLS**: certificate authentication with complete path, EKU, revocation policy, trust store, hostname/service binding where applicable, and private-key proof.
- **WebAuthn/FIDO2**: phishing-resistant credential ceremonies with RP ID, origin, challenge, user verification, credential ownership and counter handling, typically as an IdP factor or targeted privileged step-up.
- **LDAP/Active Directory**: directory and authorization lookup; explicit authenticated bind workflows only where required. LDAP queries alone do not constitute authentication; use TLS and protective policies.
- **Workloads**: dedicated token/certificate trust and authorization model, separated from human reviewer identities.

OAuth 2.0 by itself is an authorization framework; do not accept an arbitrary bearer access token as proof of human authentication. API clients may be authorized with OAuth profiles or other independently verified workload credentials.

## Contract
- Protocol adapters validate untrusted protocol inputs and produce a normalized `AuthenticationContext`.
- Independent authorization resolves privileges and scope for a stable, issuer-qualified human identity.
- A per-operation policy gates acceptable authentication methods, assurance level, trusted issuers and maximum session age.
- CP/CPS approval additionally requires two independent identity subjects, two separately authorized roles and independently pinned signing keys.
- High-risk ceremonies require explicit step-up policies, protected session and replay-resistant challenge binding.
- Security events and audit must preserve verified method, issuer, subject, session reference, authorization source and evidence hash, under a retention/privacy policy.

## Delivery boundaries
The Rust `authentication.rs` module is **only a protocol-neutral context and policy model**. It has no OIDC/SAML/Kerberos/mTLS/WebAuthn verification implementation and its public context structs can still be caller-created. Its checks cannot safely be used as a real authentication boundary.

Production implementation must hide constructors behind authenticated adapter outputs and trusted entitlement/time sources, create tamper-resistant persistence, and undergo protocol-by-protocol independent security review. No compliance or identity assurance claim is established by this draft.

## Acceptance gates
1. Reject unknown issuer, unapproved authentication method, low assurance, malformed identity and stale/future sessions.
2. Unit tests for every supported policy rule and negative path.
3. Independent integration suites using actual protocol messages and intentionally hostile tokens/assertions/tickets/certificates.
4. Persistent reviewer-to-signature evidence, revocation handling and key rotation.
5. G0 legal/employer-IP separation and independent security review before merge or commercial use.
