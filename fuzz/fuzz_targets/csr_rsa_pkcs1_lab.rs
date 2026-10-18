//! SEC-07: the lab RSA PKCS#1 PKCS#10 verifier must reject, never panic, on any input.
#![no_main]

use libfuzzer_sys::fuzz_target;
use trust_pki_core::csr::verify_pkcs10_rsa_pkcs1_lab;

fuzz_target!(|data: &[u8]| {
    let _ = verify_pkcs10_rsa_pkcs1_lab(data, "fuzz.lab.invalid");
});
