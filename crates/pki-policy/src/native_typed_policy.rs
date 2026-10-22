//! Algorithm-native issuance authorization, independent of the legacy enum.
//! Authorization is an in-memory laboratory contract, not a signed policy
//! receipt, authentication provider, or durable approval record.
use crate::{inside_zone, valid_dns_name, AuthenticatedPrincipal, Denial};
use trust_pki_crypto::{
    certificate_algorithm_binding::{authorize_certificate_binding, CertificateAlgorithmBinding},
    crypto_agility::{AlgorithmSuite, KeyParameter},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeTypedIssuanceRequest<'a> {
    pub profile_id: &'a str,
    pub subject_common_name: &'a str,
    pub dns_sans: &'a [&'a str],
    pub validity_days: u16,
    pub issuer_suite: AlgorithmSuite,
    pub subject_key: KeyParameter,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeTypedAuthorization {
    actor_id: String,
    profile_id: String,
    policy_version: String,
    common_name: String,
    dns_sans: Vec<String>,
    validity_days: u16,
    issuer_suite: AlgorithmSuite,
    subject_key: KeyParameter,
}

impl NativeTypedAuthorization {
    pub fn actor_id(&self) -> &str {
        &self.actor_id
    }

    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    pub fn policy_version(&self) -> &str {
        &self.policy_version
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

    pub fn issuer_suite(&self) -> AlgorithmSuite {
        self.issuer_suite
    }

    pub fn subject_key(&self) -> KeyParameter {
        self.subject_key
    }
}

/// The trusted configuration controls issuer signing and CSR key algorithms
/// independently. No combination is implicitly authorized from another.
pub struct NativeTypedPolicy {
    pub profile_id: String,
    pub policy_version: String,
    pub allowed_actors: Vec<String>,
    pub allowed_dns_zones: Vec<String>,
    pub allowed_issuer_suites: Vec<AlgorithmSuite>,
    pub allowed_subject_keys: Vec<KeyParameter>,
    pub max_validity_days: u16,
    pub max_dns_sans: usize,
}

impl NativeTypedPolicy {
    pub fn authorize(
        &self,
        principal: &AuthenticatedPrincipal<'_>,
        request: &NativeTypedIssuanceRequest<'_>,
    ) -> Result<NativeTypedAuthorization, Denial> {
        if self.profile_id.trim().is_empty()
            || self.policy_version.trim().is_empty()
            || self.allowed_actors.is_empty()
            || self.allowed_dns_zones.is_empty()
            || self.allowed_issuer_suites.is_empty()
            || self.allowed_subject_keys.is_empty()
            || self.max_validity_days == 0
            || self.max_dns_sans == 0
            || self
                .allowed_dns_zones
                .iter()
                .any(|zone| !valid_dns_name(zone))
        {
            return Err(Denial::InvalidConfiguration);
        }
        if principal.subject_id.trim().is_empty()
            || !self
                .allowed_actors
                .iter()
                .any(|a| a == principal.subject_id)
        {
            return Err(Denial::MissingIdentity);
        }
        if request.profile_id != self.profile_id {
            return Err(Denial::MissingProfile);
        }
        if request.validity_days == 0 || request.validity_days > self.max_validity_days {
            return Err(Denial::InvalidValidity);
        }
        if authorize_certificate_binding(
            CertificateAlgorithmBinding {
                issuer_signature: request.issuer_suite,
                subject_key: request.subject_key,
            },
            &self.allowed_issuer_suites,
            &self.allowed_subject_keys,
        )
        .is_err()
        {
            return Err(Denial::AlgorithmNotAllowed);
        }
        if request.dns_sans.is_empty() || request.dns_sans.len() > self.max_dns_sans {
            return Err(Denial::TooManySans);
        }
        if !valid_dns_name(request.subject_common_name)
            || request.dns_sans.iter().any(|dns| !valid_dns_name(dns))
        {
            return Err(Denial::InvalidDnsName);
        }
        // A deterministic subject identity prevents duplicate SANs and
        // inconsistent inventory, renewal or policy-evidence records.
        if request
            .dns_sans
            .iter()
            .enumerate()
            .any(|(i, name)| request.dns_sans[..i].contains(name))
        {
            return Err(Denial::InvalidDnsName);
        }
        if !request.dns_sans.contains(&request.subject_common_name)
            || request.dns_sans.iter().any(|name| {
                !self
                    .allowed_dns_zones
                    .iter()
                    .any(|zone| inside_zone(name, zone))
            })
        {
            return Err(Denial::SubjectNotAuthorized);
        }
        Ok(NativeTypedAuthorization {
            actor_id: principal.subject_id.to_owned(),
            profile_id: self.profile_id.clone(),
            policy_version: self.policy_version.clone(),
            common_name: request.subject_common_name.to_owned(),
            dns_sans: request.dns_sans.iter().map(|s| (*s).to_owned()).collect(),
            validity_days: request.validity_days,
            issuer_suite: request.issuer_suite,
            subject_key: request.subject_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trust_pki_crypto::crypto_agility::{Digest, SignatureScheme};

    const RSA: AlgorithmSuite = AlgorithmSuite {
        scheme: SignatureScheme::RsaPkcs1V15,
        key: KeyParameter::Rsa3072,
        digest: Digest::Sha384,
    };

    fn policy() -> NativeTypedPolicy {
        NativeTypedPolicy {
            profile_id: "server".into(),
            policy_version: "v2".into(),
            allowed_actors: vec!["lab-operator".into()],
            allowed_dns_zones: vec!["lab.invalid".into()],
            allowed_issuer_suites: vec![RSA],
            allowed_subject_keys: vec![KeyParameter::P256],
            max_validity_days: 3,
            max_dns_sans: 4,
        }
    }

    #[test]
    fn authorizes_distinct_issuer_signature_and_subject_key() {
        let p = policy();
        let names = ["api.lab.invalid"];
        let input = NativeTypedIssuanceRequest {
            profile_id: "server",
            subject_common_name: "api.lab.invalid",
            dns_sans: &names,
            validity_days: 2,
            issuer_suite: RSA,
            subject_key: KeyParameter::P256,
        };
        let actor = AuthenticatedPrincipal {
            subject_id: "lab-operator",
        };
        let approved = p.authorize(&actor, &input).unwrap();
        assert_eq!(approved.issuer_suite(), RSA);
        assert_eq!(approved.subject_key(), KeyParameter::P256);
        assert_eq!(approved.dns_sans(), &["api.lab.invalid".to_owned()]);
        assert_eq!(approved.policy_version(), "v2");
    }

    #[test]
    fn rejects_suite_subject_policy_and_identity_substitution() {
        let p = policy();
        let names = ["api.lab.invalid"];
        let mut input = NativeTypedIssuanceRequest {
            profile_id: "server",
            subject_common_name: "api.lab.invalid",
            dns_sans: &names,
            validity_days: 2,
            issuer_suite: RSA,
            subject_key: KeyParameter::P256,
        };
        let actor = AuthenticatedPrincipal {
            subject_id: "lab-operator",
        };
        input.issuer_suite.scheme = SignatureScheme::RsaPss;
        assert_eq!(
            p.authorize(&actor, &input),
            Err(Denial::AlgorithmNotAllowed)
        );
        input.issuer_suite = RSA;
        input.subject_key = KeyParameter::Rsa3072;
        assert_eq!(
            p.authorize(&actor, &input),
            Err(Denial::AlgorithmNotAllowed)
        );
        input.subject_key = KeyParameter::P256;
        assert_eq!(
            p.authorize(
                &AuthenticatedPrincipal {
                    subject_id: "unknown"
                },
                &input,
            ),
            Err(Denial::MissingIdentity)
        );
        let duplicate = ["api.lab.invalid", "api.lab.invalid"];
        let duplicate_request = NativeTypedIssuanceRequest {
            profile_id: "server",
            subject_common_name: "api.lab.invalid",
            dns_sans: &duplicate,
            validity_days: 2,
            issuer_suite: RSA,
            subject_key: KeyParameter::P256,
        };
        assert_eq!(
            p.authorize(&actor, &duplicate_request),
            Err(Denial::InvalidDnsName)
        );
        input.validity_days = 4;
        assert_eq!(p.authorize(&actor, &input), Err(Denial::InvalidValidity));
    }
}
