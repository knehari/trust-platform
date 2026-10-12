//! RSA-PSS X.509 AlgorithmIdentifier consistency preflight.
//! This is NOT verification of parameters, key strength or signatures.
use x509_cert::{
    der::Encode,
    spki::AlgorithmIdentifierOwned,
    Certificate,
};

const RSASSA_PSS_OID: &str = "1.2.840.113549.1.1.10";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PssIdentifierError {
    WrongAlgorithm,
    MissingParameters,
    InconsistentParameters,
    InvalidDer,
}

/// Reject inconsistent TBS / outer signature identifiers and absent PSS params.
/// Parameter parsing and cryptographic verification MUST follow separately.
pub fn preflight_pss_certificate_identifier(
    cert: &Certificate,
) -> Result<(), PssIdentifierError> {
    check_pss_identifiers(&cert.tbs_certificate.signature, &cert.signature_algorithm)
}

pub fn check_pss_identifiers(
    tbs: &AlgorithmIdentifierOwned,
    outer: &AlgorithmIdentifierOwned,
) -> Result<(), PssIdentifierError> {
    if tbs.oid.to_string() != RSASSA_PSS_OID
        || outer.oid.to_string() != RSASSA_PSS_OID
    {
        return Err(PssIdentifierError::WrongAlgorithm);
    }
    let tbs_params = tbs.parameters.as_ref().ok_or(PssIdentifierError::MissingParameters)?;
    let outer_params = outer.parameters.as_ref().ok_or(PssIdentifierError::MissingParameters)?;
    let tbs_der = tbs_params.to_der().map_err(|_| PssIdentifierError::InvalidDer)?;
    let outer_der = outer_params.to_der().map_err(|_| PssIdentifierError::InvalidDer)?;
    if tbs_der != outer_der {
        return Err(PssIdentifierError::InconsistentParameters);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_cert::der::{asn1::ObjectIdentifier, Any, Decode};

    fn identifier(oid: &str, params: Option<&[u8]>) -> AlgorithmIdentifierOwned {
        AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new(oid).unwrap(),
            parameters: params.map(|bytes| Any::from_der(bytes).unwrap()),
        }
    }

    #[test]
    fn rejects_non_pss_signature_identifiers() {
        let ecdsa = identifier("1.2.840.10045.4.3.2", None);
        let pss = identifier(RSASSA_PSS_OID, Some(&[0x30, 0x00]));
        assert_eq!(check_pss_identifiers(&ecdsa, &pss), Err(PssIdentifierError::WrongAlgorithm));
    }

    #[test]
    fn rejects_implicit_default_and_inconsistent_pss_params() {
        let empty = identifier(RSASSA_PSS_OID, None);
        let pss = identifier(RSASSA_PSS_OID, Some(&[0x30, 0x00]));
        assert_eq!(check_pss_identifiers(&empty, &pss), Err(PssIdentifierError::MissingParameters));
        let different = identifier(RSASSA_PSS_OID, Some(&[0x30, 0x02, 0xa0, 0x00]));
        assert_eq!(
            check_pss_identifiers(&pss, &different),
            Err(PssIdentifierError::InconsistentParameters)
        );
        // This checks consistency ONLY; empty/default ASN.1 params must still
        // be rejected by the future strict RSA-PSS parameter decoder.
        assert_eq!(check_pss_identifiers(&pss, &pss), Ok(()));
    }
}
