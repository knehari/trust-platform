//! Additional negative cases for v1.5 signed policy decisions.
//! Ephemeral software keys are test-only and do not establish human identity.
#![cfg(feature = "lab-software")]

use trust_pki_core::policy_decisions::*;
use trust_pki_crypto::{lab::EphemeralP256Signer, SignatureAlgorithm, SigningProvider};
use x509_cert::{der::Decode, spki::SubjectPublicKeyInfoOwned};

fn claim() -> ApprovalClaim {
    ApprovalClaim {
        ca_id: "11111111-1111-4111-8111-111111111111".into(),
        draft_id: "22222222-2222-4222-8222-222222222222".into(),
        policy_oid: "1.3.6.1.4.1.55555.1.1".into(),
        policy_revision: "v1".into(),
        cp_sha256: [3; 32],
        cps_sha256: [4; 32],
        effective_from_unix: 1_780_000_000,
        effective_until_unix: 1_790_000_000,
        decision_nonce: [7; 32],
    }
}
fn public(s: &EphemeralP256Signer) -> Vec<u8> {
    let der = s.public_key_spki_der(s.key_ref()).unwrap();
    SubjectPublicKeyInfoOwned::from_der(&der)
        .unwrap()
        .subject_public_key
        .as_bytes()
        .unwrap()
        .to_vec()
}
fn signature(s: &EphemeralP256Signer, c: &ApprovalClaim) -> SignerStatement {
    SignerStatement {
        key_id: s.key_ref().0.clone(),
        signature_der: s
            .sign(
                s.key_ref(),
                SignatureAlgorithm::EcdsaP256Sha256,
                &c.canonical_bytes().unwrap(),
            )
            .unwrap(),
    }
}

#[test]
fn claim_fields_are_all_cryptographically_bound() {
    let maker = EphemeralP256Signer::generate("maker-key").unwrap();
    let checker = EphemeralP256Signer::generate("checker-key").unwrap();
    let baseline = claim();
    let maker_sig = signature(&maker, &baseline);
    let checker_sig = signature(&checker, &baseline);
    let maker_pub = public(&maker);
    let checker_pub = public(&checker);
    let pm = PinnedPolicyKey {
        key_id: "maker-key",
        sec1_p256_public: &maker_pub,
    };
    let pa = PinnedPolicyKey {
        key_id: "checker-key",
        sec1_p256_public: &checker_pub,
    };
    let mut variants = Vec::new();
    let mut changed = baseline.clone();
    changed.ca_id = "33333333-3333-4333-8333-333333333333".into();
    variants.push(changed);
    let mut changed = baseline.clone();
    changed.draft_id = "44444444-4444-4444-8444-444444444444".into();
    variants.push(changed);
    let mut changed = baseline.clone();
    changed.policy_revision = "v2".into();
    variants.push(changed);
    let mut changed = baseline.clone();
    changed.cps_sha256 = [8; 32];
    variants.push(changed);
    let mut changed = baseline.clone();
    changed.effective_from_unix += 1;
    variants.push(changed);

    for changed in variants {
        let signed = DualApproval {
            claim: &changed,
            proposer: &maker_sig,
            approver: &checker_sig,
        };
        assert_eq!(
            verify_dual_approval(&signed, &pm, &pa, &changed),
            Err(ApprovalError::InvalidSignature)
        );
        let original = DualApproval {
            claim: &baseline,
            proposer: &maker_sig,
            approver: &checker_sig,
        };
        assert_eq!(
            verify_dual_approval(&original, &pm, &pa, &changed),
            Err(ApprovalError::PolicyMismatch)
        );
    }
}

#[test]
fn substituted_pinned_key_and_empty_signatures_are_rejected() {
    let maker = EphemeralP256Signer::generate("maker-key").unwrap();
    let checker = EphemeralP256Signer::generate("checker-key").unwrap();
    let impostor = EphemeralP256Signer::generate("impostor-key").unwrap();
    let baseline = claim();
    let maker_sig = signature(&maker, &baseline);
    let checker_sig = signature(&checker, &baseline);
    let maker_pub = public(&maker);
    let checker_pub = public(&checker);
    let impostor_pub = public(&impostor);
    let pm = PinnedPolicyKey {
        key_id: "maker-key",
        sec1_p256_public: &maker_pub,
    };
    let pa = PinnedPolicyKey {
        key_id: "checker-key",
        sec1_p256_public: &checker_pub,
    };
    let substituted = PinnedPolicyKey {
        key_id: "checker-key",
        sec1_p256_public: &impostor_pub,
    };
    let normal = DualApproval {
            claim: &baseline,
            proposer: &maker_sig,
            approver: &checker_sig,
        };
    assert_eq!(
        verify_dual_approval(&normal, &pm, &substituted, &baseline),
        Err(ApprovalError::InvalidSignature)
    );

    let blank = SignerStatement {
        key_id: "checker-key".into(),
        signature_der: Vec::new(),
    };
    let missing = DualApproval {
            claim: &baseline,
            proposer: &maker_sig,
            approver: &blank,
        };
    assert_eq!(
        verify_dual_approval(&missing, &pm, &pa, &baseline),
        Err(ApprovalError::InvalidSignature)
    );
}

#[test]
fn canonicalization_rejects_unbounded_or_control_character_fields() {
    for field in ["", "a\nrole=admin", "a\trole=admin"] {
        let mut changed = claim();
        changed.policy_revision = field.into();
        assert_eq!(changed.canonical_bytes(), Err(ApprovalError::InvalidClaim));
    }
    let mut long = claim();
    long.draft_id = "x".repeat(129);
    assert_eq!(long.canonical_bytes(), Err(ApprovalError::InvalidClaim));
    let mut zero_hash = claim();
    zero_hash.cps_sha256 = [0; 32];
    assert_eq!(
        zero_hash.canonical_bytes(),
        Err(ApprovalError::InvalidClaim)
    );
}
