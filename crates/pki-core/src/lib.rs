#![forbid(unsafe_code)]
//! Native CA orchestration contracts.
//! Sprint 0 deliberately does not parse CSRs, issue certificates or sign data.

pub mod cp_cps;
pub mod csr;
#[cfg(feature = "lab-software")]
pub mod lab_ca;
#[cfg(feature = "lab-software")]
pub mod lab_x509_verifier;
pub mod orchestrator;
#[cfg(feature = "postgres-store")]
pub mod postgres_store;
pub mod provider_evidence;
pub mod reconciliation;
pub mod serial;
pub mod x509_extensions;

use trust_pki_policy::{
    AuthenticatedPrincipal, Authorization, Denial, IssuanceRequest, PolicyEngine,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssuanceState {
    Received,
    CsrValidated,
    Authorized,
    SerialReserved,
    Signing,
    Signed,
    Published,
    Rejected,
    ReconciliationRequired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssuanceError {
    Unauthorized(Denial),
    InvalidTransition,
}

/// Policy decisions must be made using a principal returned by a trusted auth layer.
/// This function alone does not validate the CSR or generate a certificate.
pub fn authorize_request(
    policy: &impl PolicyEngine,
    principal: &AuthenticatedPrincipal<'_>,
    request: &IssuanceRequest<'_>,
) -> Result<Authorization, IssuanceError> {
    policy
        .authorize(principal, request)
        .map_err(IssuanceError::Unauthorized)
}

/// Defines legal lifecycle edges; actual durable enforcement requires the persistence layer.
/// It is NOT a substitute for CSR verification or signing-intent authorization.
pub fn can_transition(from: IssuanceState, to: IssuanceState) -> bool {
    use IssuanceState::*;
    matches!(
        (from, to),
        (Received, CsrValidated)
            | (Received, Rejected)
            | (CsrValidated, Authorized)
            | (CsrValidated, Rejected)
            | (Authorized, SerialReserved)
            | (SerialReserved, Signing)
            | (Signing, Signed)
            | (Signing, ReconciliationRequired)
            | (Signed, Published)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use trust_pki_crypto::SignatureAlgorithm;
    use trust_pki_policy::{DenyAll, StaticPolicy};

    #[test]
    fn deny_all_blocks_authorization() {
        let names = ["api.lab.invalid"];
        let principal = AuthenticatedPrincipal {
            subject_id: "operator",
        };
        let request = IssuanceRequest {
            profile_id: "lab-server",
            subject_common_name: "api.lab.invalid",
            dns_sans: &names,
            validity_days: 7,
            ca_signature_algorithm: SignatureAlgorithm::EcdsaP256Sha256,
        };
        assert_eq!(
            authorize_request(&DenyAll, &principal, &request),
            Err(IssuanceError::Unauthorized(Denial::DeniedByDefault))
        );
    }

    #[test]
    fn explicitly_allowed_policy_binds_actor() {
        let names = ["api.lab.invalid"];
        let principal = AuthenticatedPrincipal {
            subject_id: "operator",
        };
        let request = IssuanceRequest {
            profile_id: "lab-server",
            subject_common_name: "api.lab.invalid",
            dns_sans: &names,
            validity_days: 7,
            ca_signature_algorithm: SignatureAlgorithm::EcdsaP256Sha256,
        };
        let policy = StaticPolicy {
            profile_id: "lab-server".into(),
            policy_version: "2026-10".into(),
            allowed_actors: vec!["operator".into()],
            allowed_dns_zones: vec!["lab.invalid".into()],
            allowed_ca_signature_algorithms: vec![SignatureAlgorithm::EcdsaP256Sha256],
            max_validity_days: 30,
            max_dns_sans: 5,
        };
        let authorization = authorize_request(&policy, &principal, &request).unwrap();
        assert_eq!(authorization.actor_id(), "operator");
        assert_eq!(authorization.policy_version(), "2026-10");
    }

    #[test]
    fn no_transition_can_skip_authorization() {
        assert!(!can_transition(
            IssuanceState::Received,
            IssuanceState::Signing
        ));
        assert!(!can_transition(
            IssuanceState::CsrValidated,
            IssuanceState::SerialReserved
        ));
        assert!(!can_transition(
            IssuanceState::ReconciliationRequired,
            IssuanceState::Signing
        ));
    }

    #[test]
    fn allowed_transitions_match_design() {
        assert!(can_transition(
            IssuanceState::Signing,
            IssuanceState::ReconciliationRequired
        ));
        assert!(can_transition(
            IssuanceState::Signed,
            IssuanceState::Published
        ));
        assert!(!can_transition(
            IssuanceState::Rejected,
            IssuanceState::Authorized
        ));
    }
}
