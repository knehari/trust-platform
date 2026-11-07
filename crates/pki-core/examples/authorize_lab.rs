//! Lab-only demo: authorization without issuing, signing or storing certificates.

use trust_pki_core::authorize_request;
use trust_pki_crypto::SignatureAlgorithm;
use trust_pki_policy::{AuthenticatedPrincipal, IssuanceRequest, StaticPolicy};

fn main() {
    let policy = StaticPolicy {
        profile_id: "lab-server".into(),
        policy_version: "lab-v1".into(),
        allowed_actors: vec!["dev-operator".into()],
        allowed_dns_zones: vec!["lab.invalid".into()],
        allowed_ca_signature_algorithms: vec![SignatureAlgorithm::EcdsaP256Sha256],
        max_validity_days: 30,
        max_dns_sans: 3,
    };
    let principal = AuthenticatedPrincipal {
        subject_id: "dev-operator",
    };
    let names = ["api.lab.invalid"];
    let request = IssuanceRequest {
        profile_id: "lab-server",
        subject_common_name: "api.lab.invalid",
        dns_sans: &names,
        validity_days: 7,
        ca_signature_algorithm: SignatureAlgorithm::EcdsaP256Sha256,
    };

    let authorization = authorize_request(&policy, &principal, &request)
        .expect("the explicitly allowed laboratory policy should authorize");
    println!(
        "AUTHORIZED: actor={}, subject={}, policy={} (NO certificate issued)",
        authorization.actor_id(),
        authorization.common_name(),
        authorization.policy_version()
    );

    let forbidden_names = ["api.lab.invalid", "api.attacker.invalid"];
    let forbidden_request = IssuanceRequest {
        dns_sans: &forbidden_names,
        ..request
    };
    let result = authorize_request(&policy, &principal, &forbidden_request);
    assert!(result.is_err(), "out-of-scope SAN must never be authorized");
    println!("DENIED: request with an unauthorized SAN");
}
