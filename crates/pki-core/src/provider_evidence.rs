//! Provider-independent **collector** attestations for ambiguous signatures.
//!
//! The signature verified here belongs to a pinned, independently operated
//! audit COLLECTOR. It is NOT a cryptographic signature produced by an HSM,
//! and does NOT by itself prove an operation occurred inside the HSM.
//! The collector must authenticate the source and retain the raw provider log.
//! Nothing in this module invokes a signer, restores a cert or publishes it.

use crate::{
    orchestrator::{CertificateVerifier, IssuancePlan},
    reconciliation::{ProviderResponse, ReadOnlySigningProvider, ReconciliationError},
};
use sha2::{Digest, Sha256};
use trust_pki_crypto::verify_p256_ecdsa_sha256;

const DOMAIN: &[u8] = b"STP-AUDIT-COLLECTOR-ATTESTATION-V1\0";
const MAX_ID_LENGTH: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceKind {
    /// An audited signing event was observed, but no signed result is available.
    SigningEventObserved,
    /// A signed DER certificate was retrieved and fingerprinted by collector.
    RetrievedSignedCertificate,
    /// No matching log was observed. This NEVER proves no signature happened.
    NoMatchingEvent,
}

impl EvidenceKind {
    fn tag(self) -> u8 {
        match self {
            Self::SigningEventObserved => 1,
            Self::RetrievedSignedCertificate => 2,
            Self::NoMatchingEvent => 3,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceClaim {
    pub issuer_id: String,
    pub operation_ref: String,
    pub signer_key_ref: String,
    pub collector_key_id: String,
    pub audit_event_id: String,
    pub observed_at_unix_seconds: u64,
    pub tbs_sha256: [u8; 32],
    pub raw_provider_log_sha256: [u8; 32],
    pub certificate_sha256: Option<[u8; 32]>,
    pub kind: EvidenceKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectorAttestation {
    pub claim: EvidenceClaim,
    pub signature_der: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvidenceError {
    InvalidClaim,
    UntrustedCollector,
    InvalidSignature,
    IntentMismatch,
    ProviderUnavailable,
    ProviderMismatch,
    CertificateInvalid,
}

/// Wire format is deliberately tiny and canonical: fixed domain separator,
/// outcome tag, u64 BE time, length-prefixed ASCII identifiers (u16 BE),
/// TBS hash, raw log hash, one-byte optional flag + optional certificate hash.
/// JSON serialization/field ordering is NOT part of signature computation.
impl EvidenceClaim {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EvidenceError> {
        let result_present = self.certificate_sha256.is_some();
        if result_present != (self.kind == EvidenceKind::RetrievedSignedCertificate)
            || self.tbs_sha256 == [0; 32]
            || self.raw_provider_log_sha256 == [0; 32]
            || self.certificate_sha256 == Some([0; 32])
            || self.observed_at_unix_seconds == 0
        {
            return Err(EvidenceError::InvalidClaim);
        }

        let mut message = Vec::with_capacity(600);
        message.extend_from_slice(DOMAIN);
        message.push(self.kind.tag());
        message.extend_from_slice(&self.observed_at_unix_seconds.to_be_bytes());
        for field in [
            &self.issuer_id,
            &self.operation_ref,
            &self.signer_key_ref,
            &self.collector_key_id,
            &self.audit_event_id,
        ] {
            let data = field.as_bytes();
            if data.is_empty() || data.len() > MAX_ID_LENGTH
                || !data.iter().all(|b| b.is_ascii_graphic())
            {
                return Err(EvidenceError::InvalidClaim);
            }
            message.extend_from_slice(&(data.len() as u16).to_be_bytes());
            message.extend_from_slice(data);
        }
        message.extend_from_slice(&self.tbs_sha256);
        message.extend_from_slice(&self.raw_provider_log_sha256);
        if let Some(fingerprint) = self.certificate_sha256 {
            message.push(1);
            message.extend_from_slice(&fingerprint);
        } else {
            message.push(0);
        }
        Ok(message)
    }
}

pub struct PinnedCollectorKey<'a> {
    /// Must be loaded from protected, independently reviewed configuration.
    pub key_id: &'a str,
    /// P-256 SEC1 public key, not a self-asserted key returned by the provider.
    pub public_key_sec1: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestedFinding {
    /// Verified retrieved certificate, but it is NOT approved for publication.
    VerifiedRecoveredCandidate {
        certificate_sha256: [u8; 32],
        attestation_sha256: [u8; 32],
    },
    /// An event was observed, but the signature/certificate cannot be rebuilt.
    EventOnly {
        attestation_sha256: [u8; 32],
    },
    /// Absence of a matching event is inconclusive: NO automatic retry.
    NoMatchingEventObserved {
        attestation_sha256: [u8; 32],
    },
}

/// Read-only evaluation. A successful result is ONLY an audit finding.
/// It is never an authorization to re-sign, publish or transition a DB request.
///
/// The claimed event time is signed but not compared with trusted clock or
/// provider timestamp; external anti-replay, collection integrity and
/// identity-controlled operator review are required before deployment.
pub fn inspect_attested_provider<P: ReadOnlySigningProvider, V: CertificateVerifier>(
    provider: &P,
    verifier: &V,
    plan: &IssuancePlan<'_>,
    expected_tbs_sha256: &[u8; 32],
    attestation: &CollectorAttestation,
    pinned_key: &PinnedCollectorKey<'_>,
) -> Result<AttestedFinding, EvidenceError> {
    let claim = &attestation.claim;
    let message = claim.canonical_bytes()?;
    if pinned_key.key_id.is_empty() || claim.collector_key_id != pinned_key.key_id
        || pinned_key.public_key_sec1.is_empty()
    {
        return Err(EvidenceError::UntrustedCollector);
    }
    verify_p256_ecdsa_sha256(
        pinned_key.public_key_sec1,
        &message,
        &attestation.signature_der,
    )
    .map_err(|_| EvidenceError::InvalidSignature)?;

    let actual_tbs: [u8; 32] = Sha256::digest(plan.tbs_der).into();
    if plan.ca_id != claim.issuer_id
        || plan.operation_ref != claim.operation_ref
        || plan.signer_key_ref != claim.signer_key_ref
        || claim.tbs_sha256 != actual_tbs
        || claim.tbs_sha256 != *expected_tbs_sha256
        || plan.tbs_der.is_empty()
        || plan.serial_der.is_empty()
    {
        return Err(EvidenceError::IntentMismatch);
    }
    let attestation_sha256: [u8; 32] = Sha256::digest(&message).into();
    match claim.kind {
        EvidenceKind::SigningEventObserved => Ok(AttestedFinding::EventOnly {
            attestation_sha256,
        }),
        EvidenceKind::NoMatchingEvent => Ok(AttestedFinding::NoMatchingEventObserved {
            attestation_sha256,
        }),
        EvidenceKind::RetrievedSignedCertificate => {
            let reply = provider.lookup(plan.operation_ref, plan.signer_key_ref)
                .map_err(|e| match e {
                    ReconciliationError::ProviderUnavailable => EvidenceError::ProviderUnavailable,
                    _ => EvidenceError::ProviderMismatch,
                })?;
            match reply {
                ProviderResponse::SignedCertificate {
                    operation_ref,
                    signer_key_ref,
                    certificate_der,
                    evidence_sha256,
                } => {
                    if operation_ref != plan.operation_ref
                        || signer_key_ref != plan.signer_key_ref
                        || evidence_sha256 != claim.raw_provider_log_sha256
                        || certificate_der.len() > 65_536
                        || certificate_der.is_empty()
                        || Some(Sha256::digest(&certificate_der).into())
                            != claim.certificate_sha256
                    {
                        return Err(EvidenceError::ProviderMismatch);
                    }
                    verifier.verify(plan, &certificate_der)
                        .map_err(|_| EvidenceError::CertificateInvalid)?;
                    Ok(AttestedFinding::VerifiedRecoveredCandidate {
                        certificate_sha256: claim.certificate_sha256
                            .ok_or(EvidenceError::InvalidClaim)?,
                        attestation_sha256,
                    })
                }
                _ => Err(EvidenceError::ProviderMismatch),
            }
        }
    }
}
