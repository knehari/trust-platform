//! SEC-07: the independent CRL verifier receives bytes that came back from a
//! signer or store and must reject malformed or foreign CRLs, never panic.
//! One ephemeral lab CA is built once; inputs that are not this CA's CRL for
//! the fixed reservation are expected to be rejected.
#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
use trust_pki_core::crl::{CrlReservation, CrlVerifier, LabCrlVerifier};
use trust_pki_core::lab_ca::EphemeralLabCa;

fn verifier() -> &'static LabCrlVerifier {
    static VERIFIER: OnceLock<LabCrlVerifier> = OnceLock::new();
    VERIFIER.get_or_init(|| {
        let ca = EphemeralLabCa::new("Sovereign Trust Lab Root").expect("lab CA for fuzz harness");
        LabCrlVerifier::new(ca.root_certificate().clone())
    })
}

fn reservation() -> &'static CrlReservation {
    static RESERVATION: OnceLock<CrlReservation> = OnceLock::new();
    RESERVATION.get_or_init(|| CrlReservation {
        ca_id: "lab-root".to_owned(),
        crl_number: 1,
        this_update_unix: 1_800_000_000,
        next_update_unix: 1_800_000_000 + 7 * 24 * 3600,
        entries: Vec::new(),
        expired_certs_on_crl_since_unix: None,
    })
}

fuzz_target!(|data: &[u8]| {
    let _ = verifier().verify(reservation(), data);
});
