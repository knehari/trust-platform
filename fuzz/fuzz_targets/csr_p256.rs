//! SEC-07: the strict P-256 PKCS#10 verifier must reject, never panic, on any input.
#![no_main]

use libfuzzer_sys::fuzz_target;
use trust_pki_core::csr::verify_pkcs10_p256;

fuzz_target!(|data: &[u8]| {
    let _ = verify_pkcs10_p256(data, "fuzz.lab.invalid");
});
