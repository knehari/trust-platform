//! Ephemeral software signers are used ONLY to exercise signature verification.
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
fn separate_signatures_are_pinned_and_bound_to_same_edition() {
    let maker = EphemeralP256Signer::generate("maker-key").unwrap();
    let checker = EphemeralP256Signer::generate("checker-key").unwrap();
    let c = claim();
    let m = signature(&maker, &c);
    let a = signature(&checker, &c);
    let mk = public(&maker);
    let ak = public(&checker);
    let pm = PinnedPolicyKey {
        key_id: "maker-key",
        sec1_p256_public: &mk,
    };
    let pa = PinnedPolicyKey {
        key_id: "checker-key",
        sec1_p256_public: &ak,
    };
    let signed = DualApproval {
        claim: &c,
        proposer: &m,
        approver: &a,
    };
    let ok = verify_dual_approval(&signed, &pm, &pa, &c).unwrap();
    assert_eq!(ok.claim(), &c);
    assert!(!ok.claim_canonical().is_empty());
    assert_ne!(ok.evidence_sha256(), &[0; 32]);

    let mut changed = c.clone();
    changed.policy_oid = "1.3.6.1.4.1.55555.1.99".into();
    assert_eq!(
        verify_dual_approval(&signed, &pm, &pa, &changed),
        Err(ApprovalError::PolicyMismatch)
    );
    changed = c.clone();
    changed.cp_sha256 = [5; 32];
    assert_eq!(
        verify_dual_approval(&signed, &pm, &pa, &changed),
        Err(ApprovalError::PolicyMismatch)
    );
    changed = c.clone();
    changed.effective_until_unix += 60;
    assert_eq!(
        verify_dual_approval(&signed, &pm, &pa, &changed),
        Err(ApprovalError::PolicyMismatch)
    );
    changed = c.clone();
    changed.decision_nonce = [9; 32];
    assert_eq!(
        verify_dual_approval(&signed, &pm, &pa, &changed),
        Err(ApprovalError::PolicyMismatch)
    );
}
#[test]
fn forged_approver_and_shared_key_are_rejected() {
    let maker = EphemeralP256Signer::generate("maker-key").unwrap();
    let checker = EphemeralP256Signer::generate("checker-key").unwrap();
    let c = claim();
    let m = signature(&maker, &c);
    let a = signature(&checker, &c);
    let mk = public(&maker);
    let ak = public(&checker);
    let pm = PinnedPolicyKey {
        key_id: "maker-key",
        sec1_p256_public: &mk,
    };
    let pa = PinnedPolicyKey {
        key_id: "checker-key",
        sec1_p256_public: &ak,
    };
    let forged = DualApproval {
        claim: &c,
        proposer: &m,
        approver: &m,
    };
    assert_eq!(
        verify_dual_approval(&forged, &pm, &pa, &c),
        Err(ApprovalError::IdenticalApprover)
    );
    let shared = PinnedPolicyKey {
        key_id: "another-name",
        sec1_p256_public: &mk,
    };
    assert_eq!(
        verify_dual_approval(
            &DualApproval {
                claim: &c,
                proposer: &m,
                approver: &a
            },
            &pm,
            &shared,
            &c
        ),
        Err(ApprovalError::IdenticalApprover)
    );
    let mut altered = a.clone();
    altered.signature_der[0] ^= 1;
    let bad = DualApproval {
        claim: &c,
        proposer: &m,
        approver: &altered,
    };
    assert_eq!(
        verify_dual_approval(&bad, &pm, &pa, &c),
        Err(ApprovalError::InvalidSignature)
    );
}
#[test]
fn key_role_swaps_and_self_asserted_approval_are_rejected() {
    let maker = EphemeralP256Signer::generate("maker-key").unwrap();
    let checker = EphemeralP256Signer::generate("checker-key").unwrap();
    let c = claim();
    let m = signature(&maker, &c);
    let a = signature(&checker, &c);
    let mk = public(&maker);
    let ak = public(&checker);
    let pm = PinnedPolicyKey {
        key_id: "maker-key",
        sec1_p256_public: &mk,
    };
    let pa = PinnedPolicyKey {
        key_id: "checker-key",
        sec1_p256_public: &ak,
    };
    assert_eq!(
        verify_dual_approval(
            &DualApproval {
                claim: &c,
                proposer: &a,
                approver: &m
            },
            &pm,
            &pa,
            &c
        ),
        Err(ApprovalError::UntrustedKey)
    );
    let forged_approver = SignerStatement {
        key_id: "checker-key".into(),
        signature_der: m.signature_der.clone(),
    };
    assert_eq!(
        verify_dual_approval(
            &DualApproval {
                claim: &c,
                proposer: &m,
                approver: &forged_approver
            },
            &pm,
            &pa,
            &c
        ),
        Err(ApprovalError::InvalidSignature)
    );
}
#[test]
fn malformed_claim_fails_closed() {
    let mut c = claim();
    c.effective_until_unix = c.effective_from_unix;
    assert_eq!(c.canonical_bytes(), Err(ApprovalError::InvalidClaim));
    c = claim();
    c.decision_nonce = [0; 32];
    assert_eq!(c.canonical_bytes(), Err(ApprovalError::InvalidClaim));
    c = claim();
    c.policy_oid = "1.3.6.1.4.1.55555.1.1\nspoof".into();
    assert_eq!(c.canonical_bytes(), Err(ApprovalError::InvalidClaim));
}

#[test]
#[cfg(feature = "postgres-store")]
fn verified_dual_signature_receipt_roundtrips_and_replay_fails_in_postgres() {
    use sha2::{Digest, Sha256};
    use std::env;
    use trust_pki_core::{
        ca_observation::observe_pinned_lab_ca,
        cp_cps::{generate, Input as CpCpsInput},
        lab_ca::EphemeralLabCa,
        postgres_store::{LabDraftApproval, PgIssuanceStore},
    };
    use trust_pki_policy::StaticPolicy;
    use x509_cert::der::Encode;
    let Ok(url) = env::var("TRUST_CI_DATABASE_URL") else {
        assert_ne!(
            env::var("TRUST_REQUIRE_DATABASE").as_deref(),
            Ok("1"),
            "TRUST_CI_DATABASE_URL is required for PostgreSQL integration tests"
        );
        return;
    };
    let ca_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    let mut raw = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    raw.execute(
        "INSERT INTO ca(ca_id,display_name,policy_version)
         VALUES($1::text::uuid,'Dual Policy Signature Test CA','v1')",
        &[&ca_id],
    )
    .unwrap();
    drop(raw);
    let mut db = PgIssuanceStore::connect_lab(&url).unwrap();
    let root = EphemeralLabCa::new("Sovereign Trust Lab Root").unwrap();
    let root_der = root.root_certificate().to_der().unwrap();
    let pin: [u8; 32] = Sha256::digest(&root_der).into();
    let observed = observe_pinned_lab_ca(&root_der, &pin).unwrap();
    let observation_id = db
        .register_ca_public_observation(ca_id, "lab-observer", &observed)
        .unwrap();
    let policy = StaticPolicy {
        profile_id: "lab-server".into(),
        policy_version: "v1".into(),
        allowed_actors: vec!["lab-actor".into()],
        allowed_dns_zones: vec!["lab.invalid".into()],
        allowed_ca_signature_algorithms: vec![SignatureAlgorithm::EcdsaP256Sha256],
        max_validity_days: 3,
        max_dns_sans: 2,
    };
    let input = CpCpsInput {
        policy: &policy,
        policy_oid: "1.3.6.1.4.1.55555.1.1",
        edition: "v1",
        issuer: "Sovereign Trust Lab Root",
        authority: "Unverified Lab Policy Board",
        repository: "lab.invalid/draft",
    };
    let docs = generate(&input).unwrap();
    let draft_id = db
        .register_cp_cps_draft(ca_id, &observation_id, "lab-author", &input)
        .unwrap();
    let approval_id = db
        .approve_draft_policy_lab(&LabDraftApproval {
            ca_id,
            draft_id: &draft_id,
            proposer: "maker-key",
            approver: "checker-key",
            cp_sha256: &docs.cp.sha256,
            cps_sha256: &docs.cps.sha256,
            effective_from: "2025-01-01T00:00:00Z",
            effective_until: "2030-01-01T00:00:00Z",
        })
        .unwrap();
    let maker = EphemeralP256Signer::generate("maker-key").unwrap();
    let checker = EphemeralP256Signer::generate("checker-key").unwrap();
    let c = ApprovalClaim {
        ca_id: ca_id.into(),
        draft_id: draft_id.clone(),
        policy_oid: input.policy_oid.into(),
        policy_revision: "v1".into(),
        cp_sha256: docs.cp.sha256,
        cps_sha256: docs.cps.sha256,
        effective_from_unix: 1_735_689_600,
        effective_until_unix: 1_893_456_000,
        decision_nonce: [0x39; 32],
    };
    let m = signature(&maker, &c);
    let a = signature(&checker, &c);
    let mk = public(&maker);
    let ak = public(&checker);
    let pm = PinnedPolicyKey {
        key_id: "maker-key",
        sec1_p256_public: &mk,
    };
    let pa = PinnedPolicyKey {
        key_id: "checker-key",
        sec1_p256_public: &ak,
    };
    let signed = DualApproval {
        claim: &c,
        proposer: &m,
        approver: &a,
    };
    let verified = verify_dual_approval(&signed, &pm, &pa, &c).unwrap();
    let receipt = db
        .persist_dual_signature_policy_lab(&approval_id, &verified)
        .unwrap();
    assert!(!receipt.is_empty());
    assert!(db
        .persist_dual_signature_policy_lab(&approval_id, &verified)
        .is_err());
    let mut another = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    let row = another
        .query_one(
            "SELECT canonical_claim,proposer_signature_der,approver_signature_der,
                evidence_sha256
         FROM policy_dual_signature_receipt
         WHERE ca_id=$1::text::uuid AND approval_id=$2::text::uuid",
            &[&ca_id, &approval_id],
        )
        .unwrap();
    assert_eq!(row.get::<usize, Vec<u8>>(0), verified.claim_canonical());
    assert_eq!(row.get::<usize, Vec<u8>>(1), verified.proposer_signature());
    assert_eq!(row.get::<usize, Vec<u8>>(2), verified.approver_signature());
    assert_eq!(row.get::<usize, Vec<u8>>(3), verified.evidence_sha256());
}
