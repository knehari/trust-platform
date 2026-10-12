//! Laboratory validation of challenge-to-signed-claim binding.
//! Validation is not consumption: atomic single-use enforcement belongs to
//! a privileged PostgreSQL transaction coupled to receipt persistence.
use crate::policy_decisions::VerifiedDualApproval;
use crate::reviewer_binding::BoundPolicyDecision;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingChallenge<'a> {
    pub ca_id: &'a str,
    pub draft_id: &'a str,
    pub nonce_sha256: [u8; 32],
    pub proposer_subject: &'a str,
    pub approver_subject: &'a str,
    pub issued_at_unix: i64,
    pub expires_at_unix: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeBindingError {
    WrongDecision,
    WrongNonce,
    InvalidWindow,
}

/// Requires a previously verified dual signature AND bound reviewer identities.
/// The challenge and timestamp must come from a trusted database/clock.
pub fn validate_pending_challenge(
    verified: &VerifiedDualApproval,
    decision: &BoundPolicyDecision,
    challenge: &PendingChallenge<'_>,
    trusted_now_unix: i64,
) -> Result<(), ChallengeBindingError> {
    let claim = verified.claim();
    if decision.evidence_sha256 != *verified.evidence_sha256()
        || decision.ca_id != claim.ca_id
        || challenge.ca_id != claim.ca_id
        || challenge.draft_id != claim.draft_id
        || challenge.proposer_subject != decision.proposer_subject
        || challenge.approver_subject != decision.approver_subject
    {
        return Err(ChallengeBindingError::WrongDecision);
    }
    let digest: [u8; 32] = Sha256::digest(claim.decision_nonce).into();
    if digest != challenge.nonce_sha256 {
        return Err(ChallengeBindingError::WrongNonce);
    }
    if challenge.issued_at_unix <= 0
        || challenge.expires_at_unix <= challenge.issued_at_unix
        || trusted_now_unix < challenge.issued_at_unix
        || trusted_now_unix >= challenge.expires_at_unix
    {
        return Err(ChallengeBindingError::InvalidWindow);
    }
    Ok(())
}

#[cfg(all(test, feature = "lab-software"))]
mod tests {
    use super::*;
    use crate::policy_decisions::*;
    use crate::reviewer_binding::*;
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
    fn challenge_is_bound_to_signed_decision_and_reviewer_subjects() {
        let maker = EphemeralP256Signer::generate("maker-key").unwrap();
        let checker = EphemeralP256Signer::generate("checker-key").unwrap();
        let claim = ApprovalClaim {
            ca_id: "ca-lab".into(),
            draft_id: "draft-lab".into(),
            policy_oid: "1.3.6.1.4.1.55555.1".into(),
            policy_revision: "v1".into(),
            cp_sha256: [3; 32],
            cps_sha256: [4; 32],
            effective_from_unix: 100,
            effective_until_unix: 10000,
            decision_nonce: [7; 32],
        };
        let bytes = claim.canonical_bytes().unwrap();
        let proposer = SignerStatement {
            key_id: "maker-key".into(),
            signature_der: maker.sign(maker.key_ref(), SignatureAlgorithm::EcdsaP256Sha256, &bytes).unwrap(),
        };
        let approver = SignerStatement {
            key_id: "checker-key".into(),
            signature_der: checker.sign(checker.key_ref(), SignatureAlgorithm::EcdsaP256Sha256, &bytes).unwrap(),
        };
        let maker_pub = public(&maker);
        let checker_pub = public(&checker);
        let verified = verify_dual_approval(
            &DualApproval { claim: &claim, proposer: &proposer, approver: &approver },
            &PinnedPolicyKey { key_id: "maker-key", sec1_p256_public: &maker_pub },
            &PinnedPolicyKey { key_id: "checker-key", sec1_p256_public: &checker_pub },
            &claim,
        ).unwrap();
        let decision = BoundPolicyDecision {
            ca_id: claim.ca_id.clone(),
            proposer_subject: "subject-A".into(),
            approver_subject: "subject-B".into(),
            identity_issuer: "issuer-lab".into(),
            evidence_sha256: *verified.evidence_sha256(),
        };
        let digest: [u8; 32] = Sha256::digest(claim.decision_nonce).into();
        let mut challenge = PendingChallenge {
            ca_id: "ca-lab",
            draft_id: "draft-lab",
            nonce_sha256: digest,
            proposer_subject: "subject-A",
            approver_subject: "subject-B",
            issued_at_unix: 100,
            expires_at_unix: 200,
        };
        assert_eq!(validate_pending_challenge(&verified, &decision, &challenge, 150), Ok(()));
        challenge.nonce_sha256 = [8; 32];
        assert_eq!(validate_pending_challenge(&verified, &decision, &challenge, 150), Err(ChallengeBindingError::WrongNonce));
        challenge.nonce_sha256 = digest;
        challenge.approver_subject = "other";
        assert_eq!(validate_pending_challenge(&verified, &decision, &challenge, 150), Err(ChallengeBindingError::WrongDecision));
        challenge.approver_subject = "subject-B";
        assert_eq!(validate_pending_challenge(&verified, &decision, &challenge, 200), Err(ChallengeBindingError::InvalidWindow));
    }
}
