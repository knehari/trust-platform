//! Strict PKCS#10 parsing and proof-of-possession check (RFC 2986, SEC-07).
//!
//! Parsing never grants anything: requested extensions are policy *inputs*,
//! evaluated server-side later (SEC-03).

use core::fmt;

use crypto_provider::{ParamsEncoding, SignatureAlgorithm, SignatureVerifier};
use der::asn1::Null;
use der::{Decode, Encode};
use spki::AlgorithmIdentifierOwned;
use x509_cert::request::{CertReq, Version};

/// Default maximum CSR size. Large enough for an ML-DSA-87 or composite key and
/// signature, small enough to bound parser work.
pub const DEFAULT_MAX_CSR_LEN: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CsrLimits {
    pub max_len: usize,
}

impl Default for CsrLimits {
    fn default() -> Self {
        Self { max_len: DEFAULT_MAX_CSR_LEN }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CsrError {
    TooLarge { len: usize, max: usize },
    Der(der::Error),
    NonCanonical,
    UnsupportedVersion,
    UnsupportedAlgorithm,
    BadAlgorithmParameters,
    BadSignature,
    CaKeyReuse,
}

impl fmt::Display for CsrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { len, max } => write!(f, "CSR is {len} bytes, maximum {max}"),
            Self::Der(e) => write!(f, "malformed DER: {e}"),
            Self::NonCanonical => f.write_str("CSR is not canonically DER-encoded"),
            Self::UnsupportedVersion => f.write_str("unsupported CSR version"),
            Self::UnsupportedAlgorithm => f.write_str("unsupported or unknown signature algorithm"),
            Self::BadAlgorithmParameters => f.write_str("invalid algorithm parameters encoding"),
            Self::BadSignature => f.write_str("CSR signature (proof of possession) is invalid"),
            Self::CaKeyReuse => f.write_str("CSR public key is a CA key"),
        }
    }
}

impl std::error::Error for CsrError {}

impl From<der::Error> for CsrError {
    fn from(e: der::Error) -> Self {
        Self::Der(e)
    }
}

/// A structurally valid CSR whose signature algorithm is supported.
/// The proof of possession is **not** verified yet: see [`ParsedCsr::verify_pop`].
#[derive(Debug)]
pub struct ParsedCsr {
    req: CertReq,
    algorithm: SignatureAlgorithm,
}

/// Parses a DER CSR strictly: size bound, DER (not BER), no trailing data,
/// version v1, known signature algorithm with exact parameter encoding.
pub fn parse_csr(der_bytes: &[u8], limits: CsrLimits) -> Result<ParsedCsr, CsrError> {
    if der_bytes.len() > limits.max_len {
        return Err(CsrError::TooLarge { len: der_bytes.len(), max: limits.max_len });
    }
    let req = CertReq::from_der(der_bytes)?;
    // Defence in depth: the signed bytes must be exactly what we re-encode.
    if req.to_der()? != der_bytes {
        return Err(CsrError::NonCanonical);
    }
    if req.info.version != Version::V1 {
        return Err(CsrError::UnsupportedVersion);
    }
    let algorithm = check_algorithm(&req.algorithm)?;
    Ok(ParsedCsr { req, algorithm })
}

fn check_algorithm(id: &AlgorithmIdentifierOwned) -> Result<SignatureAlgorithm, CsrError> {
    let algorithm = SignatureAlgorithm::from_oid(&id.oid).ok_or(CsrError::UnsupportedAlgorithm)?;
    let (_, params) = algorithm.oid().ok_or(CsrError::UnsupportedAlgorithm)?;
    let ok = match (params, &id.parameters) {
        (ParamsEncoding::Absent, None) => true,
        (ParamsEncoding::Null, Some(p)) => p.decode_as::<Null>().is_ok(),
        _ => false,
    };
    if ok { Ok(algorithm) } else { Err(CsrError::BadAlgorithmParameters) }
}

impl ParsedCsr {
    pub fn request(&self) -> &CertReq {
        &self.req
    }

    pub fn signature_algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    /// DER SubjectPublicKeyInfo of the requested key.
    pub fn spki_der(&self) -> Result<Vec<u8>, CsrError> {
        Ok(self.req.info.public_key.to_der()?)
    }

    /// Verifies the CSR self-signature over the DER `CertificationRequestInfo`.
    pub fn verify_pop(&self, verifier: &dyn SignatureVerifier) -> Result<(), CsrError> {
        let message = self.req.info.to_der()?;
        let signature = self.req.signature.as_bytes().ok_or(CsrError::BadSignature)?;
        verifier.verify(&self.spki_der()?, self.algorithm, &message, signature).map_err(|_| CsrError::BadSignature)
    }

    /// Rejects a CSR that submits one of the CA's own public keys.
    pub fn ensure_not_ca_key<'a>(&self, ca_spkis: impl IntoIterator<Item = &'a [u8]>) -> Result<(), CsrError> {
        let spki = self.spki_der()?;
        if ca_spkis.into_iter().any(|ca| ca == spki.as_slice()) {
            return Err(CsrError::CaKeyReuse);
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crypto_provider::VerifyError;
    use std::cell::RefCell;

    /// ECDSA P-256 CSR generated with OpenSSL (public material only, see testdata/csr/SOURCES.md).
    const P256_CSR: &[u8] = include_bytes!("../../../testdata/csr/p256.csr.der");
    /// Ed25519 CSR generated with OpenSSL.
    const ED25519_CSR: &[u8] = include_bytes!("../../../testdata/csr/ed25519.csr.der");

    struct RecordingVerifier {
        ok: bool,
        seen: RefCell<Option<(SignatureAlgorithm, Vec<u8>)>>,
    }

    impl SignatureVerifier for RecordingVerifier {
        fn verify(&self, _: &[u8], alg: SignatureAlgorithm, msg: &[u8], _: &[u8]) -> Result<(), VerifyError> {
            *self.seen.borrow_mut() = Some((alg, msg.to_vec()));
            if self.ok { Ok(()) } else { Err(VerifyError::Invalid) }
        }
    }

    #[test]
    fn parses_p256_and_ed25519() {
        let p = parse_csr(P256_CSR, CsrLimits::default()).unwrap();
        assert_eq!(p.signature_algorithm(), SignatureAlgorithm::EcdsaP256Sha256);
        let e = parse_csr(ED25519_CSR, CsrLimits::default()).unwrap();
        assert_eq!(e.signature_algorithm(), SignatureAlgorithm::Ed25519);
    }

    #[test]
    fn pop_is_checked_over_certification_request_info() {
        let p = parse_csr(P256_CSR, CsrLimits::default()).unwrap();
        let v = RecordingVerifier { ok: true, seen: RefCell::new(None) };
        p.verify_pop(&v).unwrap();
        let (alg, msg) = v.seen.borrow().clone().unwrap();
        assert_eq!(alg, SignatureAlgorithm::EcdsaP256Sha256);
        assert_eq!(msg, p.request().info.to_der().unwrap());

        let bad = RecordingVerifier { ok: false, seen: RefCell::new(None) };
        assert_eq!(p.verify_pop(&bad), Err(CsrError::BadSignature));
    }

    #[test]
    fn oversized_input_is_rejected_before_parsing() {
        let err = parse_csr(P256_CSR, CsrLimits { max_len: 10 }).unwrap_err();
        assert!(matches!(err, CsrError::TooLarge { .. }));
    }

    #[test]
    fn trailing_data_and_truncation_are_rejected() {
        let mut trailing = P256_CSR.to_vec();
        trailing.push(0);
        assert!(parse_csr(&trailing, CsrLimits::default()).is_err());
        assert!(parse_csr(&P256_CSR[..P256_CSR.len() - 1], CsrLimits::default()).is_err());
    }

    #[test]
    fn ca_key_reuse_is_rejected() {
        let p = parse_csr(P256_CSR, CsrLimits::default()).unwrap();
        let spki = p.spki_der().unwrap();
        assert_eq!(p.ensure_not_ca_key([spki.as_slice()]), Err(CsrError::CaKeyReuse));
        assert!(p.ensure_not_ca_key([&b"other"[..]]).is_ok());
    }

    #[test]
    fn ecdsa_with_null_parameters_is_rejected() {
        let mut req = CertReq::from_der(P256_CSR).unwrap();
        req.algorithm.parameters = Some(der::Any::encode_from(&Null).unwrap());
        let der = req.to_der().unwrap();
        assert_eq!(parse_csr(&der, CsrLimits::default()).unwrap_err(), CsrError::BadAlgorithmParameters);
    }

    #[test]
    fn unknown_algorithm_is_rejected() {
        let mut req = CertReq::from_der(P256_CSR).unwrap();
        req.algorithm.oid = der::asn1::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.5"); // sha1WithRSA
        let der = req.to_der().unwrap();
        assert_eq!(parse_csr(&der, CsrLimits::default()).unwrap_err(), CsrError::UnsupportedAlgorithm);
    }
}
