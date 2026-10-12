//! Protocol-neutral authentication evidence and policy contracts (v1.6 laboratory).
//! These values are NOT proof of authentication: a hardened, protocol-specific
//! adapter must validate messages, signatures, trust anchors and session binding
//! before any caller may rely on the normalized context.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticationMethod {
    OpenIdConnect,
    Saml2,
    Kerberos,
    MutualTls,
    WebAuthn,
    DirectoryPassword,
    ServiceWorkloadIdentity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AssuranceLevel {
    Low,
    Substantial,
    High,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticationContext<'a> {
    /// Issuer-qualified, non-reassignable identity, never a display name.
    pub issuer: &'a str,
    pub subject: &'a str,
    pub method: AuthenticationMethod,
    /// Assurance is independently assessed from verified authentication evidence;
    /// it must NOT be accepted merely because a token includes an ACR string.
    pub assurance: AssuranceLevel,
    pub authenticated_at_unix: i64,
    /// Unique protocol session reference, derived by a trusted adapter.
    pub session_id: &'a str,
}

#[derive(Debug, Clone)]
pub struct AuthenticationPolicy<'a> {
    pub allowed_methods: &'a [AuthenticationMethod],
    pub trusted_issuers: &'a [&'a str],
    pub minimum_assurance: AssuranceLevel,
    pub maximum_session_age_seconds: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticationPolicyError {
    InvalidContext,
    UnsupportedMethod,
    UntrustedIssuer,
    InsufficientAssurance,
    ExpiredSession,
}

fn bounded(s: &str) -> bool {
    !s.is_empty() && s.len() <= 256 && s.bytes().all(|b| b.is_ascii_graphic())
}

/// Fail-closed constraints on pre-validated authentication context.
/// This function does not verify OIDC, SAML, Kerberos, TLS or WebAuthn itself.
pub fn evaluate_authentication_context(
    context: &AuthenticationContext<'_>,
    policy: &AuthenticationPolicy<'_>,
    trusted_now_unix: i64,
) -> Result<(), AuthenticationPolicyError> {
    if !bounded(context.issuer)
        || !bounded(context.subject)
        || !bounded(context.session_id)
        || policy.allowed_methods.is_empty()
        || policy.trusted_issuers.is_empty()
        || policy.maximum_session_age_seconds <= 0
        || trusted_now_unix <= 0
    {
        return Err(AuthenticationPolicyError::InvalidContext);
    }
    if !policy.allowed_methods.contains(&context.method) {
        return Err(AuthenticationPolicyError::UnsupportedMethod);
    }
    if !policy.trusted_issuers.contains(&context.issuer) {
        return Err(AuthenticationPolicyError::UntrustedIssuer);
    }
    if context.assurance < policy.minimum_assurance {
        return Err(AuthenticationPolicyError::InsufficientAssurance);
    }
    if context.authenticated_at_unix <= 0
        || context.authenticated_at_unix > trusted_now_unix
        || trusted_now_unix
            .checked_sub(context.authenticated_at_unix)
            .is_none_or(|age| age > policy.maximum_session_age_seconds)
    {
        return Err(AuthenticationPolicyError::ExpiredSession);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multiple_methods_with_shared_policy_contract() {
        let methods = [
            AuthenticationMethod::OpenIdConnect,
            AuthenticationMethod::Saml2,
            AuthenticationMethod::MutualTls,
        ];
        let issuers = ["idp.example.invalid", "pki.example.invalid"];
        let policy = AuthenticationPolicy {
            allowed_methods: &methods,
            trusted_issuers: &issuers,
            minimum_assurance: AssuranceLevel::Substantial,
            maximum_session_age_seconds: 300,
        };
        for method in methods {
            let context = AuthenticationContext {
                issuer: "idp.example.invalid",
                subject: "stable-subject",
                method,
                assurance: AssuranceLevel::High,
                authenticated_at_unix: 1000,
                session_id: "session-123",
            };
            assert_eq!(
                evaluate_authentication_context(&context, &policy, 1100),
                Ok(())
            );
        }
    }

    #[test]
    fn unsupported_method_issuer_low_assurance_and_stale_session_fail_closed() {
        let methods = [AuthenticationMethod::OpenIdConnect];
        let issuers = ["trusted.example.invalid"];
        let policy = AuthenticationPolicy {
            allowed_methods: &methods,
            trusted_issuers: &issuers,
            minimum_assurance: AssuranceLevel::High,
            maximum_session_age_seconds: 60,
        };
        let mut context = AuthenticationContext {
            issuer: "trusted.example.invalid",
            subject: "subject",
            method: AuthenticationMethod::Kerberos,
            assurance: AssuranceLevel::High,
            authenticated_at_unix: 100,
            session_id: "session",
        };
        assert_eq!(
            evaluate_authentication_context(&context, &policy, 110),
                Err(AuthenticationPolicyError::UnsupportedMethod)
            );
        context.method = AuthenticationMethod::OpenIdConnect;
        context.issuer = "untrusted.example.invalid";
        assert_eq!(
            evaluate_authentication_context(&context, &policy, 110),
                Err(AuthenticationPolicyError::UntrustedIssuer)
            );
        context.issuer = "trusted.example.invalid";
        context.assurance = AssuranceLevel::Low;
        assert_eq!(
            evaluate_authentication_context(&context, &policy, 110),
                Err(AuthenticationPolicyError::InsufficientAssurance)
            );
        context.assurance = AssuranceLevel::High;
        assert_eq!(
            evaluate_authentication_context(&context, &policy, 200),
                Err(AuthenticationPolicyError::ExpiredSession)
            );
        context.authenticated_at_unix = i64::MAX;
        assert_eq!(
            evaluate_authentication_context(&context, &policy, 200),
                Err(AuthenticationPolicyError::ExpiredSession)
            );
    }
}
