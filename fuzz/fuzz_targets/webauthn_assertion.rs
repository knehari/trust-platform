//! ADR-0007 step 2: the WebAuthn assertion verifier receives authenticator
//! output relayed by an untrusted client and must refuse anything malformed
//! or foreign, never panic. One ephemeral lab key signs one valid assertion
//! for a fixed claim digest at start-up.
//!
//! Input layout: the first byte selects the mode.
//! * even: the rest is split into authenticatorData, clientDataJSON and
//!   signature (two length bytes each, then the bytes) and verified as is;
//! * odd: the rest is (part, offset, xor) triples applied to the valid
//!   assertion. The unmodified assertion must verify, and an accepted
//!   mutation may only touch bytes outside what was signed (none here: every
//!   byte is covered), so any accepted mutation is a finding.
#![no_main]

use libfuzzer_sys::fuzz_target;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use trust_pki_core::webauthn::{challenge_text, verify_assertion, Assertion, RelyingParty};
use trust_pki_crypto::{lab::EphemeralP256Signer, SignatureAlgorithm, SigningProvider};

const RP: RelyingParty<'static> = RelyingParty {
    rp_id: "officer.lab.invalid",
    origin: "https://officer.lab.invalid",
};
const CHALLENGE: [u8; 32] = [0x5a; 32];

struct Fixture {
    public_key: Vec<u8>,
    parts: [Vec<u8>; 3],
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let signer = EphemeralP256Signer::generate("fuzz-authenticator").expect("lab key");
        let spki = signer
            .public_key_spki_der(signer.key_ref())
            .expect("public key");
        // The SEC1 point is the last 65 bytes of a P-256 SPKI.
        let public_key = spki[spki.len() - 65..].to_vec();
        let mut data = Sha256::digest(RP.rp_id.as_bytes()).to_vec();
        data.push(0x05);
        data.extend_from_slice(&7u32.to_be_bytes());
        let client = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"{}"}}"#,
            challenge_text(&CHALLENGE),
            RP.origin
        )
        .into_bytes();
        let mut signed = data.clone();
        signed.extend_from_slice(&Sha256::digest(&client));
        let signature = signer
            .sign(signer.key_ref(), SignatureAlgorithm::EcdsaP256Sha256, &signed)
            .expect("signature");
        let fixture = Fixture {
            public_key,
            parts: [data, client, signature],
        };
        assert_eq!(check(&fixture.public_key, &fixture.parts), Ok(7));
        fixture
    })
}

fn check(public_key: &[u8], parts: &[Vec<u8>; 3]) -> Result<u32, trust_pki_core::webauthn::WebAuthnError> {
    verify_assertion(
        &Assertion {
            authenticator_data: &parts[0],
            client_data_json: &parts[1],
            signature_der: &parts[2],
        },
        &RP,
        public_key,
        &CHALLENGE,
        0,
    )
}

fuzz_target!(|data: &[u8]| {
    let fixture = fixture();
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    if mode % 2 == 0 {
        let mut parts: [Vec<u8>; 3] = Default::default();
        let mut input = rest;
        for part in &mut parts {
            if input.len() < 2 {
                break;
            }
            let len = usize::from(u16::from_be_bytes([input[0], input[1]])).min(input.len() - 2);
            *part = input[2..2 + len].to_vec();
            input = &input[2 + len..];
        }
        let _ = check(&fixture.public_key, &parts);
    } else {
        let mut parts = fixture.parts.clone();
        let mut changed = false;
        for triple in rest.chunks_exact(3) {
            let part = &mut parts[usize::from(triple[0] % 3)];
            if part.is_empty() || triple[2] == 0 {
                continue;
            }
            let offset = usize::from(triple[1]) % part.len();
            part[offset] ^= triple[2];
            changed = true;
        }
        if changed && parts != fixture.parts {
            assert!(
                check(&fixture.public_key, &parts).is_err(),
                "a mutated assertion verified"
            );
        }
    }
});
