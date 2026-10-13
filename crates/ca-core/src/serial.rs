//! Certificate serial numbers (RFC 5280 §4.1.2.2, ADR-0002).
//!
//! 16 octets from the OS CSPRNG with the top bit cleared: 127 bits of entropy,
//! always positive, DER INTEGER content of at most 16 octets (≤ 20 required).

use core::fmt;

use der::Encode;
use x509_cert::serial_number::SerialNumber;

/// Number of random octets per serial.
pub const SERIAL_LEN: usize = 16;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Serial([u8; SERIAL_LEN]);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SerialError {
    Rng,
    Encoding,
}

impl Serial {
    /// Generates a fresh serial from the operating system CSPRNG.
    pub fn generate() -> Result<Self, SerialError> {
        Self::generate_with(|buf| getrandom::fill(buf).map_err(|_| SerialError::Rng))
    }

    /// Generates a serial from `fill`; exposed for deterministic tests.
    pub fn generate_with(mut fill: impl FnMut(&mut [u8]) -> Result<(), SerialError>) -> Result<Self, SerialError> {
        loop {
            let mut bytes = [0u8; SERIAL_LEN];
            fill(&mut bytes)?;
            bytes[0] &= 0x7f; // positive: high bit of the first content octet must be 0
            if bytes.iter().any(|b| *b != 0) {
                return Ok(Self(bytes));
            }
        }
    }

    pub fn as_bytes(&self) -> &[u8; SERIAL_LEN] {
        &self.0
    }

    /// Minimal big-endian magnitude (leading zero octets removed), as stored
    /// under the `UNIQUE (issuer_id, serial)` constraint.
    pub fn canonical(&self) -> &[u8] {
        let start = self.0.iter().position(|b| *b != 0).unwrap_or(SERIAL_LEN - 1);
        self.0.get(start..).unwrap_or(&self.0)
    }

    pub fn to_x509(&self) -> Result<SerialNumber, SerialError> {
        SerialNumber::new(self.canonical()).map_err(|_| SerialError::Encoding)
    }

    /// Full DER encoding (tag, length, content) of the INTEGER.
    pub fn to_der(&self) -> Result<Vec<u8>, SerialError> {
        self.to_x509()?.to_der().map_err(|_| SerialError::Encoding)
    }
}

impl fmt::Debug for Serial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Serial(")?;
        for b in self.canonical() {
            write!(f, "{b:02x}")?;
        }
        write!(f, ")")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn high_bit_is_cleared_and_encoding_fits_rfc5280() {
        let s = Serial::generate_with(|b| {
            b.fill(0xff);
            Ok(())
        })
        .unwrap();
        assert_eq!(s.as_bytes()[0], 0x7f);
        let der = s.to_der().unwrap();
        assert_eq!(der[0], 0x02, "INTEGER tag");
        let content_len = usize::from(der[1]);
        assert!(content_len <= 20);
        assert_eq!(der[2] & 0x80, 0, "must be positive");
    }

    #[test]
    fn zero_is_never_returned() {
        let mut calls = 0;
        let s = Serial::generate_with(|b| {
            calls += 1;
            b.fill(0);
            if calls > 1 {
                b[15] = 1;
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(calls, 2);
        assert_eq!(s.canonical(), &[1]);
    }

    #[test]
    fn leading_zero_octets_are_minimally_encoded() {
        let s = Serial::generate_with(|b| {
            b.fill(0);
            b[14] = 0x80;
            b[15] = 0x01;
            Ok(())
        })
        .unwrap();
        // 0x8001 needs a leading 0x00 in DER to stay positive.
        assert_eq!(s.to_der().unwrap(), vec![0x02, 0x03, 0x00, 0x80, 0x01]);
    }

    #[test]
    fn os_rng_serials_are_distinct() {
        let a = Serial::generate().unwrap();
        let b = Serial::generate().unwrap();
        assert_ne!(a, b);
    }
}
