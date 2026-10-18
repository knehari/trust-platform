//! SEC-07: X.509 CA certificate and extension parsing must reject, never panic.
//! The harness pins the SHA-256 of the input itself so the fuzzer reaches the
//! DER, basic-constraints and key-usage parsing behind the pin check.
#![no_main]

use libfuzzer_sys::fuzz_target;
use sha2::{Digest, Sha256};
use trust_pki_core::ca_observation::observe_pinned_lab_ca;

fuzz_target!(|data: &[u8]| {
    let pin: [u8; 32] = Sha256::digest(data).into();
    let _ = observe_pinned_lab_ca(data, &pin);
});
