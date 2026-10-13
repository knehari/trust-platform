//! Coherent laboratory contract composition, not production issuance.
use trust_pki_core::{
    audit_chain::AuditChain,
    audit_manifest::manifest_digest,
    capacity_policy::{admit, CapacityLimits, CapacitySnapshot},
    issuance_evidence::{issuance_evidence_sha256, IssuanceEvidence},
    release_gate::{evaluate_release, GateError, ReleaseEvidence},
    signer_capabilities::{authorize_signer, Algorithm, SignerCapabilities},
};

#[test]
fn issuance_commitment_flows_to_audit_manifest_without_bypassing_release_gates() {
    let evidence = IssuanceEvidence {
        ca_id: "ca-1",
        request_id: "request-1",
        actor_id: "authenticated-actor",
        operation_ref: "operation-1",
        signer_key_ref: "issuer-key-1",
        policy_revision: "v1",
        tbs_sha256: &[0x12; 32],
        certificate_sha256: &[0x34; 32],
    };
    let evidence_hash = issuance_evidence_sha256(&evidence).unwrap();
    let mut chain = AuditChain::default();
    let first = chain.append(1, &chain.head(), &evidence_hash).unwrap();
    let manifest = manifest_digest(&[first]).unwrap();
    assert_ne!(manifest, evidence_hash);

    admit(
        CapacityLimits {
            max_in_flight: 2,
            max_pending: 10,
        },
        CapacitySnapshot {
            in_flight: 1,
            pending: 3,
        },
    )
    .unwrap();
    let signer = [SignerCapabilities {
        key_ref: "issuer-key-1",
        enabled: true,
        attested: false,
        algorithms: &[Algorithm::RsaPssSha256],
    }];
    assert!(authorize_signer(
        &signer,
        "issuer-key-1",
        Algorithm::RsaPssSha256,
        true
    )
    .is_err());

    assert_eq!(
        evaluate_release(ReleaseEvidence::default()),
        Err(GateError::LegalClearance)
    );
}
