//! Ephemeral software signers are used ONLY to exercise signature verification.
#![cfg(feature="lab-software")]
use trust_pki_core::policy_decisions::*;
use trust_pki_crypto::{lab::EphemeralP256Signer,SignatureAlgorithm,SigningProvider};
use x509_cert::{der::Decode,spki::SubjectPublicKeyInfoOwned};

fn claim()->ApprovalClaim {
    ApprovalClaim {
        ca_id:"11111111-1111-4111-8111-111111111111".into(),
        draft_id:"22222222-2222-4222-8222-222222222222".into(),
        policy_oid:"1.3.6.1.4.1.55555.1.1".into(),
        policy_revision:"v1".into(),
        cp_sha256:[3;32],cps_sha256:[4;32],
        effective_from_unix:1_780_000_000,
        effective_until_unix:1_790_000_000,
        decision_nonce:[7;32],
    }
}
fn public(s:&EphemeralP256Signer)->Vec<u8>{
    let der=s.public_key_spki_der(s.key_ref()).unwrap();
    SubjectPublicKeyInfoOwned::from_der(&der).unwrap()
        .subject_public_key.as_bytes().unwrap().to_vec()
}
fn signature(s:&EphemeralP256Signer, c:&ApprovalClaim)->SignerStatement {
    SignerStatement {
        key_id:s.key_ref().0.clone(),
        signature_der:s.sign(s.key_ref(),SignatureAlgorithm::EcdsaP256Sha256,&c.canonical_bytes().unwrap()).unwrap()
    }
}
#[test]
fn separate_signatures_are_pinned_and_bound_to_same_edition(){
    let maker=EphemeralP256Signer::generate("maker-key").unwrap();
    let checker=EphemeralP256Signer::generate("checker-key").unwrap();
    let c=claim();let m=signature(&maker,&c);let a=signature(&checker,&c);
    let mk=public(&maker);let ak=public(&checker);
    let pm= PinnedPolicyKey{key_id:"maker-key",sec1_p256_public:&mk};
    let pa= PinnedPolicyKey{key_id:"checker-key",sec1_p256_public:&ak};
    let signed=DualApproval{claim:&c,proposer:&m,approver:&a};
    let ok=verify_dual_approval(&signed,&pm,&pa,&c).unwrap();
    assert_eq!(ok.claim(),&c);
    assert!(!ok.claim_canonical().is_empty());
    assert_ne!(ok.evidence_sha256(),&[0;32]);

    let mut changed=c.clone();changed.policy_oid="1.3.6.1.4.1.55555.1.99".into();
    assert_eq!(verify_dual_approval(&signed,&pm,&pa,&changed),Err(ApprovalError::PolicyMismatch));
    changed=c.clone();changed.cp_sha256=[5;32];
    assert_eq!(verify_dual_approval(&signed,&pm,&pa,&changed),Err(ApprovalError::PolicyMismatch));
    changed=c.clone();changed.effective_until_unix+=60;
    assert_eq!(verify_dual_approval(&signed,&pm,&pa,&changed),Err(ApprovalError::PolicyMismatch));
    changed=c.clone();changed.decision_nonce=[9;32];
    assert_eq!(verify_dual_approval(&signed,&pm,&pa,&changed),Err(ApprovalError::PolicyMismatch));
}
#[test]
fn forged_approver_and_shared_key_are_rejected(){
    let maker=EphemeralP256Signer::generate("maker-key").unwrap();
    let checker=EphemeralP256Signer::generate("checker-key").unwrap();
    let c=claim();let m=signature(&maker,&c);let a=signature(&checker,&c);
    let mk=public(&maker);let ak=public(&checker);
    let pm= PinnedPolicyKey{key_id:"maker-key",sec1_p256_public:&mk};
    let pa= PinnedPolicyKey{key_id:"checker-key",sec1_p256_public:&ak};
    let forged=DualApproval{claim:&c,proposer:&m,approver:&m};
    assert_eq!(verify_dual_approval(&forged,&pm,&pa,&c),Err(ApprovalError::IdenticalApprover));
    let shared= PinnedPolicyKey{key_id:"another-name",sec1_p256_public:&mk};
    assert_eq!(verify_dual_approval(&DualApproval{claim:&c,proposer:&m,approver:&a},&pm,&shared,&c),Err(ApprovalError::IdenticalApprover));
    let mut altered=a.clone();altered.signature_der[0]^=1;
    let bad=DualApproval{claim:&c,proposer:&m,approver:&altered};
    assert_eq!(verify_dual_approval(&bad,&pm,&pa,&c),Err(ApprovalError::InvalidSignature));
}
#[test]
fn key_role_swaps_and_self_asserted_approval_are_rejected(){
    let maker=EphemeralP256Signer::generate("maker-key").unwrap();
    let checker=EphemeralP256Signer::generate("checker-key").unwrap();
    let c=claim();let m=signature(&maker,&c);let a=signature(&checker,&c);
    let mk=public(&maker);let ak=public(&checker);
    let pm= PinnedPolicyKey{key_id:"maker-key",sec1_p256_public:&mk};
    let pa= PinnedPolicyKey{key_id:"checker-key",sec1_p256_public:&ak};
    assert_eq!(verify_dual_approval(&DualApproval{claim:&c,proposer:&a,approver:&m},&pm,&pa,&c),Err(ApprovalError::UntrustedKey));
    let forged_approver=SignerStatement{key_id:"checker-key".into(),signature_der:m.signature_der.clone()};
    assert_eq!(verify_dual_approval(&DualApproval{claim:&c,proposer:&m,approver:&forged_approver},&pm,&pa,&c),Err(ApprovalError::InvalidSignature));
}
#[test]
fn malformed_claim_fails_closed(){
    let mut c=claim();c.effective_until_unix=c.effective_from_unix;
    assert_eq!(c.canonical_bytes(),Err(ApprovalError::InvalidClaim));
    c=claim();c.decision_nonce=[0;32];
    assert_eq!(c.canonical_bytes(),Err(ApprovalError::InvalidClaim));
    c=claim();c.policy_oid="1.3.6.1.4.1.55555.1.1\nspoof".into();
    assert_eq!(c.canonical_bytes(),Err(ApprovalError::InvalidClaim));
}
