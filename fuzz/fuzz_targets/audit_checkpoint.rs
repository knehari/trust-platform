//! ADR-0006 condition 5: checkpoint lines are read back from a file outside
//! the database that someone may have edited. Parsing must never panic, and
//! accept only the canonical form: a line that parses re-serialises to
//! exactly the same text, so two different lines never mean the same
//! checkpoint.
#![no_main]

use libfuzzer_sys::fuzz_target;
use trust_pki_core::audit_chain::{Checkpoint, SignedCheckpoint};

fuzz_target!(|data: &[u8]| {
    let Ok(line) = std::str::from_utf8(data) else {
        return;
    };
    if let Some(checkpoint) = Checkpoint::parse_line(line) {
        assert_eq!(checkpoint.to_line(), line, "non-canonical v1 line accepted");
    }
    if let Some(signed) = SignedCheckpoint::parse_line(line) {
        assert_eq!(signed.to_line(), line, "non-canonical v2 line accepted");
    }
});
