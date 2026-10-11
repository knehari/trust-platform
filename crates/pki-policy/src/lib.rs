#![forbid(unsafe_code)]
//! Policy contract. No CSR-provided extension can authorize itself.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuanceRequest<'a> {
    pub requester_id: &'a str,
    pub profile_id: &'a str,
    pub subject_common_name: &'a str,
    pub dns_sans: &'a [&'a str],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Denial {
    MissingIdentity,
    MissingProfile,
    SubjectNotAuthorized,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authorization {
    pub policy_version: String,
}

pub trait PolicyEngine {
    fn authorize(&self, request: &IssuanceRequest<'_>) -> Result<Authorization, Denial>;
}

#[derive(Debug, Default)]
pub struct DenyAll;

impl PolicyEngine for DenyAll {
    fn authorize(&self, _request: &IssuanceRequest<'_>) -> Result<Authorization, Denial> {
        Err(Denial::SubjectNotAuthorized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn default_policy_denies_everything() {
        let req = IssuanceRequest {
            requester_id: "actor", profile_id: "server",
            subject_common_name: "example.invalid", dns_sans: &[],
        };
        assert_eq!(DenyAll.authorize(&req), Err(Denial::SubjectNotAuthorized));
    }
}
