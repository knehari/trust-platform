//! Structural X.509 binding for an immutable signing plan.
//! Does not verify issuer keys, trust chains, crypto signatures or profiles.
use crate::orchestrator::{CertificateVerifier, IssuancePlan, IssueError};
use crate::serial::SerialNumber as ReservedSerial;
use crate::serial_binding::verify_certificate_reserved_serial;
use x509_cert::{
    der::{Decode, Encode},
    serial_number::SerialNumber,
    Certificate, TbsCertificate,
};

/// Apply before invoking an external signer, so malformed or mismatched TBS
/// never leads to a signing intent or cryptographic operation.
pub fn preflight_issuance_plan(plan: &IssuancePlan<'_>) -> Result<(), IssueError> {
    if plan.tbs_der.is_empty() || plan.tbs_der.len() > 64 * 1024 {
        return Err(IssueError::VerificationFailure);
    }
    let reserved = ReservedSerial::from_positive_der_content(plan.serial_der)
        .map_err(|_| IssueError::VerificationFailure)?;
    let tbs = TbsCertificate::from_der(plan.tbs_der)
        .map_err(|_| IssueError::VerificationFailure)?;
    if tbs.to_der().map_err(|_| IssueError::VerificationFailure)? != plan.tbs_der {
        return Err(IssueError::VerificationFailure);
    }
    let expected = SerialNumber::new(reserved.as_der_content())
        .map_err(|_| IssueError::VerificationFailure)?;
    if tbs.serial_number != expected {
        return Err(IssueError::VerificationFailure);
    }
    Ok(())
}

/// Composes X.509 structural binding with a separate cryptographic verifier.
/// This wrapper MUST NOT be used with a permissive test double in production.
pub struct BoundX509Verifier<V>(pub V);

impl<V: CertificateVerifier> CertificateVerifier for BoundX509Verifier<V> {
    fn verify(&self, plan: &IssuancePlan<'_>, certificate_der: &[u8]) -> Result<(), IssueError> {
        preflight_issuance_plan(plan)?;
        let cert = Certificate::from_der(certificate_der)
            .map_err(|_| IssueError::VerificationFailure)?;
        if cert
            .tbs_certificate
            .to_der()
            .map_err(|_| IssueError::VerificationFailure)?
            != plan.tbs_der
        {
            return Err(IssueError::VerificationFailure);
        }
        let reserved = ReservedSerial::from_positive_der_content(plan.serial_der)
            .map_err(|_| IssueError::VerificationFailure)?;
        verify_certificate_reserved_serial(certificate_der, &reserved)
            .map_err(|_| IssueError::VerificationFailure)?;
        self.0.verify(plan, certificate_der)
    }
}
