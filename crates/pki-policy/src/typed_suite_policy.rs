//! Separate explicit typed-suite approval for the legacy RSA-PSS lab policy.
//! A legacy RsaPssSha256 authorization alone never grants SHA-384/512.
//! Trust in the policy configuration and principal is an external obligation.
use crate::{AuthenticatedPrincipal, Authorization, Denial, IssuanceRequest, PolicyEngine};
use trust_pki_crypto::{
    crypto_agility::{validate_suite, AlgorithmSuite, SignatureScheme},
    SignatureAlgorithm,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedSuiteGrant {
    suite: AlgorithmSuite,
    actor_id: String,
    profile_id: String,
    policy_version: String,
    common_name: String,
    dns_sans: Vec<String>,
    validity_days: u16,
}

impl TypedSuiteGrant {
    pub fn suite(&self) -> AlgorithmSuite {
        self.suite
    }

    /// Reject a grant being replayed against a different legacy authorization.
    pub fn matches(&self, authorization: &Authorization) -> bool {
        self.actor_id == authorization.actor_id()
            && self.profile_id == authorization.profile_id()
            && self.policy_version == authorization.policy_version()
            && self.common_name == authorization.common_name()
            && self.dns_sans == authorization.dns_sans()
            && self.validity_days == authorization.validity_days()
            && authorization.ca_signature_algorithm() == SignatureAlgorithm::RsaPssSha256
    }
}

/// Lab-only bridge: the legacy policy checks identity/DNS/validity; this second
/// explicit policy approves the precise RSA-PSS digest and key-size suite.
/// A returned grant binds the suite to the authorization attributes.
pub struct TypedSuitePolicy<'a, P: PolicyEngine> {
    pub legacy: &'a P,
    pub allowed_suites: &'a [AlgorithmSuite],
    pub x509_profile_approved: bool,
}

impl<P: PolicyEngine> TypedSuitePolicy<'_, P> {
    pub fn authorize(
        &self,
        principal: &AuthenticatedPrincipal<'_>,
        request: &IssuanceRequest<'_>,
        suite: AlgorithmSuite,
    ) -> Result<(Authorization, TypedSuiteGrant), Denial> {
        if self.allowed_suites.is_empty() || !self.x509_profile_approved {
            return Err(Denial::InvalidConfiguration);
        }
        if request.ca_signature_algorithm != SignatureAlgorithm::RsaPssSha256
            || suite.scheme != SignatureScheme::RsaPss
            || validate_suite(suite).is_err()
            || !self.allowed_suites.contains(&suite)
        {
            return Err(Denial::AlgorithmNotAllowed);
        }
        let legacy = self.legacy.authorize(principal, request)?;
        let grant = TypedSuiteGrant {
            suite,
            actor_id: legacy.actor_id().to_owned(),
            profile_id: legacy.profile_id().to_owned(),
            policy_version: legacy.policy_version().to_owned(),
            common_name: legacy.common_name().to_owned(),
            dns_sans: legacy.dns_sans().to_vec(),
            validity_days: legacy.validity_days(),
        };
        Ok((legacy, grant))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StaticPolicy;
    use trust_pki_crypto::crypto_agility::{Digest, KeyParameter};

    const PSS384: AlgorithmSuite = AlgorithmSuite {
        scheme: SignatureScheme::RsaPss,
        key: KeyParameter::Rsa3072,
        digest: Digest::Sha384,
    };

    fn legacy_policy() -> StaticPolicy {
        StaticPolicy {
            profile_id: "tls-lab".into(),
            policy_version: "p1".into(),
            allowed_actors: vec!["operator".into()],
            allowed_dns_zones: vec!["lab.invalid".into()],
            allowed_ca_signature_algorithms: vec![SignatureAlgorithm::RsaPssSha256],
            max_validity_days: 3,
            max_dns_sans: 3,
        }
    }

    #[test]
    fn digest_requires_separate_explicit_policy_grant() {
        let legacy = legacy_policy();
        let names = ["api.lab.invalid"];
        let principal = AuthenticatedPrincipal {
            subject_id: "operator",
        };
        let request = IssuanceRequest {
            profile_id: "tls-lab",
            subject_common_name: "api.lab.invalid",
            dns_sans: &names,
            validity_days: 1,
            ca_signature_algorithm: SignatureAlgorithm::RsaPssSha256,
        };
        let denied = TypedSuitePolicy {
            legacy: &legacy,
            allowed_suites: &[],
            x509_profile_approved: true,
        };
        assert!(matches!(
            denied.authorize(&principal, &request, PSS384),
            Err(Denial::InvalidConfiguration)
        ));
        let pss512 = AlgorithmSuite {
            digest: Digest::Sha512,
            ..PSS384
        };
        let policy = TypedSuitePolicy {
            legacy: &legacy,
            allowed_suites: &[PSS384],
            x509_profile_approved: true,
        };
        assert!(matches!(
            policy.authorize(&principal, &request, pss512),
            Err(Denial::AlgorithmNotAllowed)
        ));
        let (authorization, grant) =
            policy.authorize(&principal, &request, PSS384).unwrap();
        assert_eq!(grant.suite(), PSS384);
        assert!(grant.matches(&authorization));
        assert!(!grant.matches(&legacy.authorize(
            &principal,
            &IssuanceRequest {
                validity_days: 2,
                ..request
            }
        ).unwrap()));
    }
}
