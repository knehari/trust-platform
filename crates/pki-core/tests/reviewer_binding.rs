//! In-memory security tests only; does not establish production IdP trust.
#![cfg(feature = "lab-software")]

use trust_pki_core::authentication::*;
use trust_pki_core::policy_decisions::*;
use trust_pki_core::reviewer_binding::*;
use trust_pki_crypto::{lab::EphemeralP256Signer, SignatureAlgorithm, SigningProvider};
use x509_cert::{der::Decode, spki::SubjectPublicKeyInfoOwned};

fn public(s: &EphemeralP256Signer) -> Vec<u8> {
    let der = s.public_key_spki_der(s.key_ref()).unwrap();
    SubjectPublicKeyInfoOwned::from_der(&der)
        .unwrap()
        .subject_public_key
        .as_bytes()
        .unwrap()
        .to_vec()
}

#[test]
fn policy_decision_requires_distinct_scoped_fresh_reviewers() {
    let maker = EphemeralP256Signer::generate("maker-key").unwrap();
    let checker = EphemeralP256Signer::generate("checker-key").unwrap();
    let claim = ApprovalClaim {
        ca_id: "ca-lab".into(),
        draft_id: "draft-lab".into(),
        policy_oid: "1.3.6.1.4.1.55555.1".into(),
        policy_revision: "v1".into(),
        cp_sha256: [3; 32],
        cps_sha256: [4; 32],
        effective_from_unix: 1_780_000_000,
        effective_until_unix: 1_790_000_000,
        decision_nonce: [7; 32],
    };
    let bytes = claim.canonical_bytes().unwrap();
    let proposer = SignerStatement {
        key_id: "maker-key".into(),
        signature_der: maker
            .sign(maker.key_ref(), SignatureAlgorithm::EcdsaP256Sha256, &bytes)
            .unwrap(),
    };
    let approver = SignerStatement {
        key_id: "checker-key".into(),
        signature_der: checker
            .sign(
                checker.key_ref(),
                SignatureAlgorithm::EcdsaP256Sha256,
                &bytes,
            )
            .unwrap(),
    };
    let maker_pub = public(&maker);
    let checker_pub = public(&checker);
    let verified = verify_dual_approval(
        &DualApproval {
            claim: &claim,
            proposer: &proposer,
            approver: &approver,
        },
        &PinnedPolicyKey {
            key_id: "maker-key",
            sec1_p256_public: &maker_pub,
        },
        &PinnedPolicyKey {
            key_id: "checker-key",
            sec1_p256_public: &checker_pub,
        },
        &claim,
    )
    .unwrap();
    let preparer = TrustedReviewer {
        subject_id: "subject-A",
        identity_issuer: "https://idp.example.invalid",
        pinned_key_id: "maker-key",
        role: PolicyRole::Preparer,
        ca_id: "ca-lab",
        authenticated_at_unix: 1_780_000_000,
    };
    let mut checker = TrustedReviewer {
        subject_id: "subject-B",
        identity_issuer: "https://idp.example.invalid",
        pinned_key_id: "checker-key",
        role: PolicyRole::Approver,
        ca_id: "ca-lab",
        authenticated_at_unix: 1_780_000_000,
    };
    let now = 1_780_000_100;
    assert!(bind_verified_policy_decision(&verified, &preparer, &checker, now, 300).is_ok());
    checker.subject_id = "subject-A";
    assert_eq!(
        bind_verified_policy_decision(&verified, &preparer, &checker, now, 300),
        Err(ReviewerBindingError::SameHuman)
    );
    checker.subject_id = "subject-B";
    checker.pinned_key_id = "maker-key";
    assert_eq!(
        bind_verified_policy_decision(&verified, &preparer, &checker, now, 300),
        Err(ReviewerBindingError::KeyMismatch)
    );
    checker.pinned_key_id = "checker-key";
    checker.role = PolicyRole::Preparer;
    assert_eq!(
        bind_verified_policy_decision(&verified, &preparer, &checker, now, 300),
        Err(ReviewerBindingError::RoleMismatch)
    );
    checker.role = PolicyRole::Approver;
    checker.ca_id = "other-ca";
    assert_eq!(
        bind_verified_policy_decision(&verified, &preparer, &checker, now, 300),
        Err(ReviewerBindingError::WrongIssuerScope)
    );
    checker.ca_id = "ca-lab";
    let accepted = TrustedReviewer {
        subject_id: "subject-B",
        identity_issuer: "https://idp.example.invalid",
        pinned_key_id: "checker-key",
        role: PolicyRole::Approver,
        ca_id: "ca-lab",
        authenticated_at_unix: 1_780_000_000,
    };
    let preparer_auth = AuthenticationContext {
        issuer: "https://idp.example.invalid",
        subject: "subject-A",
        method: AuthenticationMethod::OpenIdConnect,
        assurance: AssuranceLevel::High,
        authenticated_at_unix: 1_780_000_000,
        session_id: "preparer-session",
    };
    let mut approver_auth = AuthenticationContext {
        issuer: "https://idp.example.invalid",
        subject: "subject-B",
        method: AuthenticationMethod::Saml2,
        assurance: AssuranceLevel::High,
        authenticated_at_unix: 1_780_000_000,
        session_id: "approver-session",
    };
    let allowed_preparer = [AuthenticationMethod::OpenIdConnect];
    let allowed_approver = [AuthenticationMethod::Saml2];
    let trusted_issuers = ["https://idp.example.invalid"];
    let preparer_policy = AuthenticationPolicy {
        allowed_methods: &allowed_preparer,
        trusted_issuers: &trusted_issuers,
        minimum_assurance: AssuranceLevel::High,
        maximum_session_age_seconds: 300,
    };
    let approver_policy = AuthenticationPolicy {
        allowed_methods: &allowed_approver,
        trusted_issuers: &trusted_issuers,
        minimum_assurance: AssuranceLevel::High,
        maximum_session_age_seconds: 300,
    };
    assert!(bind_authenticated_policy_decision(
        &verified,
        &ReviewerAuthentication {
            reviewer: &preparer,
            context: &preparer_auth,
            policy: &preparer_policy,
        },
        &ReviewerAuthentication {
            reviewer: &accepted,
            context: &approver_auth,
            policy: &approver_policy,
        },
        now,
        )
    .is_ok());
    approver_auth.subject = "subject-A";
    assert_eq!(
        bind_authenticated_policy_decision(
            &verified,
            &ReviewerAuthentication {
                reviewer: &preparer,
                context: &preparer_auth,
                policy: &preparer_policy,
            },
            &ReviewerAuthentication {
                reviewer: &accepted,
                context: &approver_auth,
                policy: &approver_policy,
            },
            now,
            ),
        Err(AuthenticatedApprovalError::IdentityMismatch)
    );
    approver_auth.subject = "subject-B";
    approver_auth.method = AuthenticationMethod::DirectoryPassword;
    assert_eq!(
        bind_authenticated_policy_decision(
            &verified,
            &ReviewerAuthentication {
                reviewer: &preparer,
                context: &preparer_auth,
                policy: &preparer_policy,
            },
            &ReviewerAuthentication {
                reviewer: &accepted,
                context: &approver_auth,
                policy: &approver_policy,
            },
            now,
            ),
        Err(AuthenticatedApprovalError::ApproverAuthentication(
            AuthenticationPolicyError::UnsupportedMethod
        ))
    );
    checker.authenticated_at_unix = now - 301;
    assert_eq!(
        bind_verified_policy_decision(&verified, &preparer, &checker, now, 300),
        Err(ReviewerBindingError::ExpiredSession)
    );
}
