//! Fuzz the strict CSR parser (SEC-07). Must never panic, whatever the input.
#![no_main]

use ca_core::csr::{CsrLimits, parse_csr};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(csr) = parse_csr(data, CsrLimits::default()) {
        let _ = csr.spki_der();
    }
});
