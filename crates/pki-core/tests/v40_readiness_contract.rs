//! Cross-module laboratory preflight composition; not a production controller.
use trust_pki_core::{
    audit_integrity, audit_retention, certificate_profile, identity_boundary,
    key_attestation, platform_readiness, pqc_rollout, recovery_budget,
    request_rate, tenant_isolation,
};

#[test]
fn independent_preflight_contracts_accept_a_consistent_fixture() {
    identity_boundary::check("actor", "trusted-issuer", 200, 100).unwrap();
    tenant_isolation::check("tenant-a", "tenant-a", true).unwrap();
    key_attestation::check("key-a", &[1; 32], true).unwrap();
    certificate_profile::check(90, 1, false).unwrap();
    audit_retention::permit_deletion(365, false, true).unwrap();
    recovery_budget::check(3, 0, true).unwrap();
    request_rate::check(60, 0, 10).unwrap();
    pqc_rollout::check(true, true, true).unwrap();
    audit_integrity::check(&[1; 32], true, true).unwrap();
    platform_readiness::check(true, true, true, true).unwrap();
}

#[test]
fn missing_external_assurance_is_never_silently_accepted() {
    assert!(key_attestation::check("key-a", &[0; 32], true).is_err());
    assert!(tenant_isolation::check("tenant-a", "tenant-b", true).is_err());
    assert!(pqc_rollout::check(true, true, false).is_err());
    assert!(audit_integrity::check(&[1; 32], true, false).is_err());
    assert!(platform_readiness::check(true, true, false, true).is_err());
}
