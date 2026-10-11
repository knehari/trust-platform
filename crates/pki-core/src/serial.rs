//! RFC 5280-constrained serial representation and lab-only uniqueness store.
//! Production serial reservations MUST use durable transactions and issuer-scoped
//! uniqueness constraints; this in-memory implementation is not production storage.

use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SerialError {
    Empty,
    TooLong,
    NotPositive,
    NonCanonical,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SerialNumber(Vec<u8>);

impl SerialNumber {
    /// Accepts minimally encoded positive DER INTEGER contents, not a full DER TLV.
    /// Maximum 20 octets (including an optional required leading 0x00).
    pub fn from_positive_der_content(bytes: &[u8]) -> Result<Self, SerialError> {
        if bytes.is_empty() {
            return Err(SerialError::Empty);
        }
        if bytes.len() > 20 {
            return Err(SerialError::TooLong);
        }
        if bytes[0] & 0x80 != 0 || bytes.iter().all(|byte| *byte == 0) {
            return Err(SerialError::NotPositive);
        }
        if bytes.len() > 1 && bytes[0] == 0 && bytes[1] & 0x80 == 0 {
            return Err(SerialError::NonCanonical);
        }

        Ok(Self(bytes.to_vec()))
    }

    pub fn as_der_content(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SerialReservationError {
    MissingIssuer,
    AlreadyReserved,
}

/// Concurrency, transaction boundaries and persistence are the responsibility of the adapter.
pub trait SerialReservationStore {
    fn reserve(
        &mut self,
        issuer_id: &str,
        serial: &SerialNumber,
    ) -> Result<(), SerialReservationError>;
}

/// Test double only. Never use as production persistence or high-availability allocator.
#[derive(Debug, Default)]
pub struct InMemorySerialReservations {
    reserved: BTreeSet<(String, SerialNumber)>,
}

impl SerialReservationStore for InMemorySerialReservations {
    fn reserve(
        &mut self,
        issuer_id: &str,
        serial: &SerialNumber,
    ) -> Result<(), SerialReservationError> {
        if issuer_id.trim().is_empty() {
            return Err(SerialReservationError::MissingIssuer);
        }

        if !self.reserved.insert((issuer_id.to_owned(), serial.clone())) {
            return Err(SerialReservationError::AlreadyReserved);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_zero_negative_and_overlong_serials() {
        assert_eq!(
            SerialNumber::from_positive_der_content(&[]),
            Err(SerialError::Empty)
        );
        assert_eq!(
            SerialNumber::from_positive_der_content(&[0]),
            Err(SerialError::NotPositive)
        );
        assert_eq!(
            SerialNumber::from_positive_der_content(&[0x80]),
            Err(SerialError::NotPositive)
        );
        assert_eq!(
            SerialNumber::from_positive_der_content(&[1; 21]),
            Err(SerialError::TooLong)
        );
        assert_eq!(
            SerialNumber::from_positive_der_content(&[0, 1]),
            Err(SerialError::NonCanonical)
        );
    }

    #[test]
    fn high_bit_requires_sign_octet() {
        let serial = SerialNumber::from_positive_der_content(&[0, 0x80]).unwrap();
        assert_eq!(serial.as_der_content(), &[0, 0x80]);
    }

    #[test]
    fn duplicate_is_rejected_per_issuer_and_never_released() {
        let serial = SerialNumber::from_positive_der_content(&[0x12, 0x34]).unwrap();
        let mut store = InMemorySerialReservations::default();
        assert_eq!(store.reserve("ca-a", &serial), Ok(()));
        assert_eq!(
            store.reserve("ca-a", &serial),
            Err(SerialReservationError::AlreadyReserved)
        );
        assert_eq!(store.reserve("ca-b", &serial), Ok(()));
    }

    #[test]
    fn empty_issuer_fails_closed() {
        let serial = SerialNumber::from_positive_der_content(&[1]).unwrap();
        let mut store = InMemorySerialReservations::default();
        assert_eq!(
            store.reserve("", &serial),
            Err(SerialReservationError::MissingIssuer)
        );
    }
}
