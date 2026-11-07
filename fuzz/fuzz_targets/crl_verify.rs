//! SEC-07: the independent CRL verifier receives bytes that came back from a
//! signer or store and must reject malformed or foreign CRLs, never panic.
//! One ephemeral lab CA signs one CRL for a fixed reservation at start-up.
//!
//! Input layout: the first byte selects the mode.
//! * even: the remaining bytes are verified as-is (arbitrary or foreign CRLs,
//!   e.g. the OpenSSL seeds, which another key signed and must be rejected);
//! * odd: the remaining bytes are (offset_hi, offset_lo, xor) triples applied
//!   to the CA's own CRL, so the signature-success path is reachable. The
//!   unmodified CRL must verify, and any accepted mutation must leave the
//!   signed TBS bytes untouched.
#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
use trust_pki_core::crl::{
    build_tbs_cert_list, CrlAssembler, CrlEntry, CrlReservation, CrlVerifier, LabCrlAssembler,
    LabCrlVerifier,
};
use trust_pki_core::lab_ca::EphemeralLabCa;
use trust_pki_core::orchestrator::ExternalSigner;
use trust_pki_core::revocation::RevocationReason;
use trust_pki_core::serial::SerialNumber;

struct Fixture {
    verifier: LabCrlVerifier,
    reservation: CrlReservation,
    crl: Vec<u8>,
    tbs: Vec<u8>,
    tbs_offset: usize,
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let mut ca =
            EphemeralLabCa::new("Sovereign Trust Lab Root").expect("lab CA for fuzz harness");
        // The lab root is valid from now for a few days and the builder
        // requires the issuer to be valid at thisUpdate, so use the clock.
        let now = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock after 1970")
                .as_secs(),
        )
        .expect("clock in range");
        let entry = |serial: &[u8], reason| CrlEntry {
            serial: SerialNumber::from_positive_der_content(serial).expect("fixed serial"),
            revoked_at_unix: now - 60,
            reason,
            invalidity_at_unix: None,
        };
        let reservation = CrlReservation::new(
            "lab-root",
            1,
            now,
            now + 7 * 24 * 3600,
            vec![
                entry(&[0x01], RevocationReason::KeyCompromise),
                entry(&[0x00, 0x80], RevocationReason::CertificateHold),
            ],
            None,
        )
        .expect("valid fixed reservation for fuzz harness");
        let root = ca.root_certificate().clone();
        let tbs = build_tbs_cert_list(&root, &reservation).expect("fixed TBS");
        let key_ref = ca.lab_signer_key_ref().to_owned();
        let signature = ca
            .sign_once(&key_ref, "fuzz-crl", &tbs)
            .expect("lab signature");
        let crl = LabCrlAssembler
            .assemble(&tbs, &signature)
            .expect("assembled CRL");
        let tbs_offset = crl
            .windows(tbs.len())
            .position(|w| w == tbs.as_slice())
            .expect("TBS inside the CRL");
        Fixture {
            verifier: LabCrlVerifier::new(root),
            reservation,
            crl,
            tbs,
            tbs_offset,
        }
    })
}

fuzz_target!(|data: &[u8]| {
    let f = fixture();
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    if mode & 1 == 0 {
        let _ = f.verifier.verify(&f.reservation, rest);
        return;
    }
    let mut crl = f.crl.clone();
    for [hi, lo, xor] in rest.as_chunks::<3>().0 {
        let offset = usize::from(u16::from_be_bytes([*hi, *lo])) % crl.len();
        crl[offset] ^= xor;
    }
    let result = f.verifier.verify(&f.reservation, &crl);
    if crl == f.crl {
        assert!(result.is_ok(), "the CA's own CRL must verify");
    } else if result.is_ok() {
        assert_eq!(
            &crl[f.tbs_offset..f.tbs_offset + f.tbs.len()],
            f.tbs.as_slice(),
            "an accepted CRL must carry exactly the reserved TBS"
        );
    }
});
