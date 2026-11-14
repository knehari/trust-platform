//! Signed issuance requests from a registration authority (ADR-0025).
//!
//! A registered RA system (a light RA, or the CLM) signs each issuance
//! request with its P-256 key. The CA verifies the signature over these exact
//! bytes before it accepts the request, stores both, and an audit tool
//! re-verifies them later. The SQL function `ra_issuance_message` (migration
//! 0038) builds the same bytes from the stored request.
//!
//! The RA vouches, by signing, for the names it validated (ADR-0024): the CA
//! does not repeat identity or domain checks, but still applies its profile.

/// A text field too long for its 32-bit length prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldTooLong;

/// What an RA signs to request one certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RaIssuanceRequest<'a> {
    /// The RA system's registered identifier.
    pub ra_id: &'a str,
    pub ca_id: [u8; 16],
    pub profile_id: &'a str,
    /// The RA's idempotency key: one request, one certificate.
    pub request_id: [u8; 16],
    /// SHA-256 of the PKCS#10 DER the RA submits.
    pub csr_sha256: [u8; 32],
    /// The DNS names the RA validated, in the order it submits them.
    pub dns_names: &'a [String],
    pub validity_days: u32,
    /// When the RA signed, in Unix seconds; the CA accepts a narrow window.
    pub signed_at_unix: i64,
}

fn put_text(out: &mut Vec<u8>, text: &str) -> Result<(), FieldTooLong> {
    let length = u32::try_from(text.len()).map_err(|_| FieldTooLong)?;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(text.as_bytes());
    Ok(())
}

/// The signed bytes (version 1): a domain prefix, then every field in order;
/// texts are 32-bit big-endian length-prefixed UTF-8, the name list is
/// prefixed by its count, integers are big-endian.
pub fn ra_issuance_message(request: &RaIssuanceRequest<'_>) -> Result<Vec<u8>, FieldTooLong> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(b"trust-platform:ra-issuance-request:v1\0");
    put_text(&mut out, request.ra_id)?;
    out.extend_from_slice(&request.ca_id);
    put_text(&mut out, request.profile_id)?;
    out.extend_from_slice(&request.request_id);
    out.extend_from_slice(&request.csr_sha256);
    let count = u32::try_from(request.dns_names.len()).map_err(|_| FieldTooLong)?;
    out.extend_from_slice(&count.to_be_bytes());
    for name in request.dns_names {
        put_text(&mut out, name)?;
    }
    out.extend_from_slice(&request.validity_days.to_be_bytes());
    out.extend_from_slice(&request.signed_at_unix.to_be_bytes());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn names() -> Vec<String> {
        vec!["api.lab.invalid".into(), "www.lab.invalid".into()]
    }

    fn request(names: &[String]) -> RaIssuanceRequest<'_> {
        RaIssuanceRequest {
            ra_id: "lab-ra",
            ca_id: [0xdd; 16],
            profile_id: "server",
            request_id: [0x11; 16],
            csr_sha256: [0xab; 32],
            dns_names: names,
            validity_days: 30,
            signed_at_unix: 1_794_225_600,
        }
    }

    // The same bytes as the SQL function of migration 0038
    // (tests/management_ra_channel.sql asserts this digest).
    #[test]
    fn message_matches_the_database() {
        use sha2::{Digest, Sha256};
        let names = names();
        let message = ra_issuance_message(&request(&names)).unwrap();
        assert!(message.starts_with(b"trust-platform:ra-issuance-request:v1\0"));
        assert_eq!(
            hex(&Sha256::digest(&message)),
            "bacfd3cabe918a56fe404ac14fc5372bb151ec7cc3fdcd64484f5511f292454e"
        );
    }

    #[test]
    fn every_field_changes_the_message() {
        let names = names();
        let base = ra_issuance_message(&request(&names)).unwrap();
        let reordered = vec![names[1].clone(), names[0].clone()];
        let fewer = vec![names[0].clone()];
        let joined = vec!["api.lab.invalidwww.lab.invalid".to_string()];
        let variants = [
            RaIssuanceRequest {
                ra_id: "lab-rb",
                ..request(&names)
            },
            RaIssuanceRequest {
                ca_id: [0xde; 16],
                ..request(&names)
            },
            RaIssuanceRequest {
                profile_id: "client",
                ..request(&names)
            },
            RaIssuanceRequest {
                request_id: [0x12; 16],
                ..request(&names)
            },
            RaIssuanceRequest {
                csr_sha256: [0xac; 32],
                ..request(&names)
            },
            request(&reordered),
            request(&fewer),
            request(&joined),
            RaIssuanceRequest {
                validity_days: 31,
                ..request(&names)
            },
            RaIssuanceRequest {
                signed_at_unix: 1_794_225_601,
                ..request(&names)
            },
        ];
        for variant in variants {
            assert_ne!(ra_issuance_message(&variant).unwrap(), base, "{variant:?}");
        }
    }
}
