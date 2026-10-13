//! Bind externally generated X.509 DER to an issuer-scoped reserved serial.
//! This is an integrity check, not signature verification or issuance authority.
use crate::serial::SerialNumber as ReservedSerial;
use x509_cert::{der::{Decode, Encode}, serial_number::SerialNumber, Certificate};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerialBindingError {
    InvalidCertificate,
    MismatchedSerial,
}

pub fn verify_certificate_reserved_serial(
    certificate_der: &[u8],
    reserved: &ReservedSerial,
) -> Result<(), SerialBindingError> {
    if certificate_der.is_empty() || certificate_der.len() > 64 * 1024 {
        return Err(SerialBindingError::InvalidCertificate);
    }
    let certificate = Certificate::from_der(certificate_der)
        .map_err(|_| SerialBindingError::InvalidCertificate)?;
    if certificate.to_der().map_err(|_| SerialBindingError::InvalidCertificate)? != certificate_der {
        return Err(SerialBindingError::InvalidCertificate);
    }
    let expected = SerialNumber::new(reserved.as_der_content())
        .map_err(|_| SerialBindingError::InvalidCertificate)?;
    if certificate.tbs_certificate.serial_number != expected {
        return Err(SerialBindingError::MismatchedSerial);
    }
    Ok(())
}

#[cfg(all(test, feature = "lab-software"))]
mod tests {
    use super::*;
    use crate::serial::SerialNumber as ReservedSerial;
    use crate::rsa_pss_x509_lab::issue_ephemeral_rsa_pss_root;

    #[test]
    fn mismatched_reserved_serial_is_rejected() {
        let cert = issue_ephemeral_rsa_pss_root().unwrap();
        let der = cert.to_der().unwrap();
        let serial_der = cert.tbs_certificate.serial_number.to_der().unwrap();
        let correct = ReservedSerial::from_positive_der_content(&serial_der[2..]).unwrap();
        assert_eq!(verify_certificate_reserved_serial(&der, &correct), Ok(()));
        let fake = ReservedSerial::from_positive_der_content(&[0x42]).unwrap();
        assert_eq!(
            verify_certificate_reserved_serial(&der, &fake),
            Err(SerialBindingError::MismatchedSerial)
        );
        assert_eq!(
            verify_certificate_reserved_serial(&[0x30, 0x00], &fake),
            Err(SerialBindingError::InvalidCertificate)
        );
    }
}
