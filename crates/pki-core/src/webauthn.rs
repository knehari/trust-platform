//! WebAuthn (ES256) assertion verification for signed officer approvals
//! (ADR-0007 §1, proposed; lab only). The authenticator signs
//! `authenticatorData || SHA-256(clientDataJSON)`; the relying party checks
//! the RP id hash, user presence and verification, the ceremony type, the
//! challenge (the SHA-256 of the canonical claim), the origin, the signature
//! counter and the ES256 signature with the enrolled key. Signature
//! verification is `trust_pki_crypto::verify_p256_ecdsa_sha256`; nothing
//! cryptographic is implemented here.
//!
//! Fail closed: attested credential data or extensions in an assertion
//! (flags AT, ED) are refused rather than parsed, and so is a cross-origin
//! ceremony.

use base64ct::{Base64UrlUnpadded, Encoding};
use sha2::{Digest, Sha256};
use trust_pki_crypto::verify_p256_ecdsa_sha256;

/// What the authenticator returned for one `navigator.credentials.get`.
#[derive(Debug, Clone, Copy)]
pub struct Assertion<'a> {
    pub authenticator_data: &'a [u8],
    pub client_data_json: &'a [u8],
    pub signature_der: &'a [u8],
}

/// The relying party the officers' authenticators are bound to.
#[derive(Debug, Clone, Copy)]
pub struct RelyingParty<'a> {
    pub rp_id: &'a str,
    pub origin: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebAuthnError {
    AuthenticatorData,
    RpIdHash,
    UserNotPresent,
    UserNotVerified,
    ClientData,
    CeremonyType,
    Challenge,
    Origin,
    CrossOrigin,
    CounterRegression,
    Signature,
}

const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_AT: u8 = 0x40;
const FLAG_ED: u8 = 0x80;

/// The authenticator's signature counter, after the checks on
/// `authenticatorData` alone.
pub fn authenticator_counter(
    authenticator_data: &[u8],
    rp: &RelyingParty<'_>,
) -> Result<u32, WebAuthnError> {
    if authenticator_data.len() != 37 {
        return Err(WebAuthnError::AuthenticatorData);
    }
    let rp_hash: [u8; 32] = Sha256::digest(rp.rp_id.as_bytes()).into();
    if authenticator_data[..32] != rp_hash {
        return Err(WebAuthnError::RpIdHash);
    }
    let flags = authenticator_data[32];
    if flags & (FLAG_AT | FLAG_ED) != 0 {
        return Err(WebAuthnError::AuthenticatorData);
    }
    if flags & FLAG_UP == 0 {
        return Err(WebAuthnError::UserNotPresent);
    }
    if flags & FLAG_UV == 0 {
        return Err(WebAuthnError::UserNotVerified);
    }
    let mut counter = [0u8; 4];
    counter.copy_from_slice(&authenticator_data[33..37]);
    Ok(u32::from_be_bytes(counter))
}

/// Counter rule: an authenticator without a counter always reports 0; any
/// other value must exceed the stored one (a clone or replay otherwise).
pub fn counter_advances(stored: u32, reported: u32) -> bool {
    (stored == 0 && reported == 0) || reported > stored
}

/// The `challenge` member a browser puts in clientDataJSON.
pub fn challenge_text(challenge: &[u8; 32]) -> String {
    Base64UrlUnpadded::encode_string(challenge)
}

/// Verify one assertion for `expected_challenge` (the claim digest) with the
/// enrolled compressed SEC1 key. Returns the new signature counter.
pub fn verify_assertion(
    assertion: &Assertion<'_>,
    rp: &RelyingParty<'_>,
    public_key_sec1: &[u8],
    expected_challenge: &[u8; 32],
    stored_counter: u32,
) -> Result<u32, WebAuthnError> {
    let counter = authenticator_counter(assertion.authenticator_data, rp)?;
    let client: serde_json::Value = serde_json::from_slice(assertion.client_data_json)
        .map_err(|_| WebAuthnError::ClientData)?;
    let member = |name| client.get(name).and_then(serde_json::Value::as_str);
    if member("type") != Some("webauthn.get") {
        return Err(WebAuthnError::CeremonyType);
    }
    if member("challenge") != Some(challenge_text(expected_challenge).as_str()) {
        return Err(WebAuthnError::Challenge);
    }
    if member("origin") != Some(rp.origin) {
        return Err(WebAuthnError::Origin);
    }
    match client.get("crossOrigin") {
        None | Some(serde_json::Value::Bool(false)) => {}
        Some(_) => return Err(WebAuthnError::CrossOrigin),
    }
    if !counter_advances(stored_counter, counter) {
        return Err(WebAuthnError::CounterRegression);
    }
    let mut signed = assertion.authenticator_data.to_vec();
    signed.extend_from_slice(&Sha256::digest(assertion.client_data_json));
    verify_p256_ecdsa_sha256(public_key_sec1, &signed, assertion.signature_der)
        .map_err(|_| WebAuthnError::Signature)?;
    Ok(counter)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RP: RelyingParty<'static> = RelyingParty {
        rp_id: "officer.lab.invalid",
        origin: "https://officer.lab.invalid",
    };

    fn auth_data(flags: u8, counter: u32) -> Vec<u8> {
        let mut data = Sha256::digest(RP.rp_id.as_bytes()).to_vec();
        data.push(flags);
        data.extend_from_slice(&counter.to_be_bytes());
        data
    }

    #[test]
    fn authenticator_data_checks() {
        assert_eq!(authenticator_counter(&auth_data(0x05, 7), &RP), Ok(7));
        assert_eq!(
            authenticator_counter(&auth_data(0x01, 7), &RP),
            Err(WebAuthnError::UserNotVerified)
        );
        assert_eq!(
            authenticator_counter(&auth_data(0x04, 7), &RP),
            Err(WebAuthnError::UserNotPresent)
        );
        assert_eq!(
            authenticator_counter(&auth_data(0x45, 7), &RP),
            Err(WebAuthnError::AuthenticatorData)
        );
        assert_eq!(
            authenticator_counter(&auth_data(0x85, 7), &RP),
            Err(WebAuthnError::AuthenticatorData)
        );
        let other = RelyingParty {
            rp_id: "evil.invalid",
            ..RP
        };
        assert_eq!(
            authenticator_counter(&auth_data(0x05, 7), &other),
            Err(WebAuthnError::RpIdHash)
        );
        assert_eq!(
            authenticator_counter(&auth_data(0x05, 7)[..36], &RP),
            Err(WebAuthnError::AuthenticatorData)
        );
    }

    #[test]
    fn counter_must_advance_unless_absent() {
        assert!(counter_advances(0, 0));
        assert!(counter_advances(0, 1));
        assert!(counter_advances(5, 6));
        assert!(!counter_advances(5, 5));
        assert!(!counter_advances(5, 0));
    }

    #[test]
    fn client_data_is_checked_before_the_signature() {
        let challenge = [9u8; 32];
        let check = |json: String| {
            verify_assertion(
                &Assertion {
                    authenticator_data: &auth_data(0x05, 1),
                    client_data_json: json.as_bytes(),
                    signature_der: &[0x30, 0x00],
                },
                &RP,
                &[2; 33],
                &challenge,
                0,
            )
            .unwrap_err()
        };
        let text = challenge_text(&challenge);
        assert_eq!(text.len(), 43);
        assert!(!text.contains(['+', '/', '=']));
        assert_eq!(check("not json".into()), WebAuthnError::ClientData);
        assert_eq!(
            check(format!(
                r#"{{"type":"webauthn.create","challenge":"{text}","origin":"{}"}}"#,
                RP.origin
            )),
            WebAuthnError::CeremonyType
        );
        assert_eq!(
            check(format!(
                r#"{{"type":"webauthn.get","challenge":"{}","origin":"{}"}}"#,
                challenge_text(&[8; 32]),
                RP.origin
            )),
            WebAuthnError::Challenge
        );
        assert_eq!(
            check(format!(
                r#"{{"type":"webauthn.get","challenge":"{text}","origin":"https://evil.invalid"}}"#
            )),
            WebAuthnError::Origin
        );
        assert_eq!(
            check(format!(
                r#"{{"type":"webauthn.get","challenge":"{text}","origin":"{}","crossOrigin":true}}"#,
                RP.origin
            )),
            WebAuthnError::CrossOrigin
        );
        assert_eq!(
            check(format!(
                r#"{{"type":"webauthn.get","challenge":"{text}","origin":"{}"}}"#,
                RP.origin
            )),
            WebAuthnError::Signature
        );
    }
}
