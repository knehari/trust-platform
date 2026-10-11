#![forbid(unsafe_code)]
//! Fail-closed authorization for a private PKI.
//! The caller MUST obtain AuthenticatedPrincipal from a trusted authentication boundary.
//! CSR attributes are untrusted input and do not create permissions.

use trust_pki_crypto::SignatureAlgorithm;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatedPrincipal<'a> {
    pub subject_id: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuanceRequest<'a> {
    pub profile_id: &'a str,
    pub subject_common_name: &'a str,
    pub dns_sans: &'a [&'a str],
    pub validity_days: u16,
    pub ca_signature_algorithm: SignatureAlgorithm,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Denial {
    DeniedByDefault,
    InvalidConfiguration,
    MissingIdentity,
    MissingProfile,
    InvalidDnsName,
    SubjectNotAuthorized,
    TooManySans,
    InvalidValidity,
    AlgorithmNotAllowed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authorization {
    actor_id: String,
    profile_id: String,
    policy_version: String,
    common_name: String,
    dns_sans: Vec<String>,
    validity_days: u16,
    algorithm: SignatureAlgorithm,
}

impl Authorization {
    pub fn actor_id(&self) -> &str {
        &self.actor_id
    }

    pub fn policy_version(&self) -> &str {
        &self.policy_version
    }

    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    pub fn common_name(&self) -> &str {
        &self.common_name
    }

    pub fn dns_sans(&self) -> &[String] {
        &self.dns_sans
    }

    pub fn validity_days(&self) -> u16 {
        self.validity_days
    }

    pub fn ca_signature_algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }
}

pub trait PolicyEngine {
    fn authorize(
        &self,
        principal: &AuthenticatedPrincipal<'_>,
        request: &IssuanceRequest<'_>,
    ) -> Result<Authorization, Denial>;
}

#[derive(Debug, Default)]
pub struct DenyAll;

impl PolicyEngine for DenyAll {
    fn authorize(
        &self,
        _principal: &AuthenticatedPrincipal<'_>,
        _request: &IssuanceRequest<'_>,
    ) -> Result<Authorization, Denial> {
        Err(Denial::DeniedByDefault)
    }
}

/// Explicit lab policy only. Never use this as an identity verifier.
#[derive(Debug, Clone)]
pub struct StaticPolicy {
    pub profile_id: String,
    pub policy_version: String,
    pub allowed_actors: Vec<String>,
    pub allowed_dns_zones: Vec<String>,
    pub allowed_ca_ca_signature_algorithms: Vec<SignatureAlgorithm>,
    pub max_validity_days: u16,
    pub max_dns_sans: usize,
}

impl PolicyEngine for StaticPolicy {
    fn authorize(
        &self,
        principal: &AuthenticatedPrincipal<'_>,
        request: &IssuanceRequest<'_>,
    ) -> Result<Authorization, Denial> {
        if self.profile_id.trim().is_empty()
            || self.policy_version.trim().is_empty()
            || self.allowed_actors.is_empty()
            || self.allowed_dns_zones.is_empty()
            || self.allowed_ca_ca_signature_algorithms.is_empty()
            || self.max_validity_days == 0
            || self.max_dns_sans == 0
            || self
                .allowed_dns_zones
                .iter()
                .any(|name| !valid_dns_name(name))
        {
            return Err(Denial::InvalidConfiguration);
        }

        if principal.subject_id.trim().is_empty()
            || !self
                .allowed_actors
                .iter()
                .any(|actor| actor == principal.subject_id)
        {
            return Err(Denial::MissingIdentity);
        }

        if request.profile_id != self.profile_id {
            return Err(Denial::MissingProfile);
        }

        if request.validity_days == 0 || request.validity_days > self.max_validity_days {
            return Err(Denial::InvalidValidity);
        }

        if !self
            .allowed_ca_ca_signature_algorithms
            .contains(&request.ca_signature_algorithm)
        {
            return Err(Denial::AlgorithmNotAllowed);
        }

        if request.dns_sans.is_empty() || request.dns_sans.len() > self.max_dns_sans {
            return Err(Denial::TooManySans);
        }

        if !valid_dns_name(request.subject_common_name)
            || request.dns_sans.iter().any(|name| !valid_dns_name(name))
        {
            return Err(Denial::InvalidDnsName);
        }

        // The CN is not a TLS hostname authorization substitute: demand matching SAN.
        if !request.dns_sans.contains(&request.subject_common_name) {
            return Err(Denial::SubjectNotAuthorized);
        }

        if request.dns_sans.iter().any(|name| {
            !self
                .allowed_dns_zones
                .iter()
                .any(|zone| inside_zone(name, zone))
        }) {
            return Err(Denial::SubjectNotAuthorized);
        }

        Ok(Authorization {
            actor_id: principal.subject_id.to_owned(),
            profile_id: self.profile_id.clone(),
            policy_version: self.policy_version.clone(),
            common_name: request.subject_common_name.to_owned(),
            dns_sans: request
                .dns_sans
                .iter()
                .map(|name| (*name).to_owned())
                .collect(),
            validity_days: request.validity_days,
            algorithm: request.ca_signature_algorithm,
        })
    }
}

/// Intentional narrow ASCII DNS profile: FQDNs only, no wildcards, no Unicode.
/// Internationalized names must arrive in validated lower-case A-label form.
pub fn valid_dns_name(name: &str) -> bool {
    if name.len() > 253 || !name.is_ascii() || name.bytes().any(|b| b.is_ascii_uppercase()) {
        return false;
    }

    let labels: Vec<&str> = name.split('.').collect();
    if labels.len() < 2 {
        return false;
    }

    labels.iter().all(|label| {
        !label.starts_with("xn--")
            && !label.is_empty()
            && label.len() <= 63
            && label.as_bytes()[0].is_ascii_alphanumeric()
            && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
            && label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    })
}

fn inside_zone(name: &str, zone: &str) -> bool {
    if name == zone {
        return true;
    }

    name.strip_suffix(zone)
        .is_some_and(|prefix| prefix.ends_with('.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> StaticPolicy {
        StaticPolicy {
            profile_id: "lab-server".to_owned(),
            policy_version: "v1".to_owned(),
            allowed_actors: vec!["build-agent".to_owned()],
            allowed_dns_zones: vec!["lab.invalid".to_owned()],
            allowed_ca_ca_signature_algorithms: vec![SignatureAlgorithm::EcdsaP256Sha256],
            max_validity_days: 30,
            max_dns_sans: 4,
        }
    }

    fn request<'a>(sans: &'a [&'a str]) -> IssuanceRequest<'a> {
        IssuanceRequest {
            profile_id: "lab-server",
            subject_common_name: "api.lab.invalid",
            dns_sans: sans,
            validity_days: 15,
            ca_signature_algorithm: SignatureAlgorithm::EcdsaP256Sha256,
        }
    }

    #[test]
    fn deny_all_is_fail_closed() {
        let sans = ["api.lab.invalid"];
        let actor = AuthenticatedPrincipal {
            subject_id: "build-agent",
        };
        assert_eq!(
            DenyAll.authorize(&actor, &request(&sans)),
            Err(Denial::DeniedByDefault)
        );
    }

    #[test]
    fn explicitly_allowed_request_binds_identity_and_policy() {
        let sans = ["api.lab.invalid"];
        let actor = AuthenticatedPrincipal {
            subject_id: "build-agent",
        };
        let decision = policy().authorize(&actor, &request(&sans)).unwrap();
        assert_eq!(decision.actor_id(), "build-agent");
        assert_eq!(decision.policy_version(), "v1");
        assert_eq!(decision.profile_id(), "lab-server");
        assert_eq!(decision.dns_sans(), &["api.lab.invalid".to_owned()]);
    }

    #[test]
    fn zone_boundary_prevents_suffix_attack() {
        let sans = ["api.lab.invalid", "evil-lab.invalid"];
        let actor = AuthenticatedPrincipal {
            subject_id: "build-agent",
        };
        assert_eq!(
            policy().authorize(&actor, &request(&sans)),
            Err(Denial::SubjectNotAuthorized)
        );
    }

    #[test]
    fn untrusted_actor_is_denied() {
        let sans = ["api.lab.invalid"];
        let actor = AuthenticatedPrincipal {
            subject_id: "unauthorized",
        };
        assert_eq!(
            policy().authorize(&actor, &request(&sans)),
            Err(Denial::MissingIdentity)
        );
    }

    #[test]
    fn no_wildcards_or_mixed_case() {
        assert!(!valid_dns_name("*.lab.invalid"));
        assert!(!valid_dns_name("api.LAB.invalid"));
        assert!(!valid_dns_name("lab.invalid."));
        assert!(!valid_dns_name("bad..lab.invalid"));
        assert!(!valid_dns_name("xn--demo.lab.invalid"));
        assert!(valid_dns_name("node-1.lab.invalid"));
    }

    #[test]
    fn unsupported_algorithm_is_denied() {
        let sans = ["api.lab.invalid"];
        let actor = AuthenticatedPrincipal {
            subject_id: "build-agent",
        };
        let mut input = request(&sans);
        input.ca_signature_algorithm = SignatureAlgorithm::MlDsa65;
        assert_eq!(
            policy().authorize(&actor, &input),
            Err(Denial::AlgorithmNotAllowed)
        );
    }

    #[test]
    fn invalid_validity_or_excessive_sans_are_denied() {
        let sans = ["api.lab.invalid"];
        let actor = AuthenticatedPrincipal {
            subject_id: "build-agent",
        };
        let mut input = request(&sans);
        input.validity_days = 31;
        assert_eq!(
            policy().authorize(&actor, &input),
            Err(Denial::InvalidValidity)
        );

        let names = [
            "api.lab.invalid",
            "a.lab.invalid",
            "b.lab.invalid",
            "c.lab.invalid",
            "d.lab.invalid",
        ];
        assert_eq!(
            policy().authorize(&actor, &request(&names)),
            Err(Denial::TooManySans)
        );
    }

    #[test]
    fn missing_san_match_is_denied() {
        let sans = ["other.lab.invalid"];
        let actor = AuthenticatedPrincipal {
            subject_id: "build-agent",
        };
        assert_eq!(
            policy().authorize(&actor, &request(&sans)),
            Err(Denial::SubjectNotAuthorized)
        );
    }

    #[test]
    fn empty_config_never_allows_requests() {
        let sans = ["api.lab.invalid"];
        let actor = AuthenticatedPrincipal {
            subject_id: "build-agent",
        };
        let mut config = policy();
        config.allowed_dns_zones.clear();
        assert_eq!(
            config.authorize(&actor, &request(&sans)),
            Err(Denial::InvalidConfiguration)
        );
    }
}
