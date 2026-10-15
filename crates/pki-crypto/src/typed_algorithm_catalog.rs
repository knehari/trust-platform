//! Typed algorithm inventory. Enumeration is not cryptographic support.
//! Production selection must require conformance + X.509 + reviewed provider.
use crate::crypto_agility::{AlgorithmSuite, Digest, KeyParameter, SignatureScheme};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Maturity {
    Planned,
    Laboratory,
    ProductionQualified,
}
/// Full candidate inventory. Most suites are deliberately non-executable.
/// Each becomes available only after independent evidence-backed qualification.
pub fn planned_classical_suites() -> Vec<SuiteRecordOwned> {
    use Digest::*;
    use KeyParameter::*;
    use SignatureScheme::*;
    let mut result = Vec::new();
    for (key, key_name) in [
        (Rsa2048, "2048"), (Rsa3072, "3072"),
        (Rsa4096, "4096"), (Rsa8192, "8192"),
    ] {
        for (digest, digest_name) in [
            (Sha256, "sha256"), (Sha384, "sha384"), (Sha512, "sha512"),
        ] {
            for (scheme, prefix) in [(RsaPss, "rsa-pss"), (RsaPkcs1V15, "rsa-pkcs1v15")] {
                let identifier = format!("{prefix}-{key_name}-{digest_name}");
                // Static reference is intentionally NOT exposed: callers must
                // carry the typed suite and stable identifier as owned data.
                result.push(SuiteRecordOwned {
                    suite: AlgorithmSuite { scheme, key, digest },
                    maturity: Maturity::Planned,
                    identifier,
                });
            }
        }
    }
    for (key, digest, identifier) in [
        (P256, Sha256, "ecdsa-p256-sha256"),
        (P384, Sha384, "ecdsa-p384-sha384"),
        (P521, Sha512, "ecdsa-p521-sha512"),
    ] {
        result.push(SuiteRecordOwned { suite: AlgorithmSuite {
            scheme: Ecdsa, key, digest,
        }, maturity: Maturity::Planned, identifier: identifier.to_owned() });
    }
    result.push(SuiteRecordOwned {suite: AlgorithmSuite {
        scheme: SignatureScheme::Ed25519, key: KeyParameter::Ed25519, digest: Intrinsic,
    }, maturity: Maturity::Planned, identifier: "ed25519".to_owned()});
    result.push(SuiteRecordOwned {suite: AlgorithmSuite {
        scheme: SignatureScheme::Ed448, key: KeyParameter::Ed448, digest: Intrinsic,
    }, maturity: Maturity::Planned, identifier: "ed448".to_owned()});
    result
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuiteRecordOwned {
    pub suite: AlgorithmSuite,
    pub maturity: Maturity,
    pub identifier: String,
}
/// No suite can become operational just because it appears in the catalogue.
pub fn production_enabled(record: &SuiteRecordOwned) -> bool {
    record.maturity == Maturity::ProductionQualified
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn full_classical_inventory_is_disabled_without_qualification() {
        let suites = planned_classical_suites();
        assert_eq!(suites.len(), 29);
        assert!(suites.iter().all(|s| !production_enabled(s)));
        assert!(suites.iter().any(|s| s.identifier == "rsa-pss-8192-sha512"));
        assert!(suites.iter().any(|s| s.identifier == "ecdsa-p384-sha384"));
    }
    #[test]
    fn identifiers_are_unique() {
        let suites = planned_classical_suites();
        let names: std::collections::HashSet<_> = suites.iter().map(|s| &s.identifier).collect();
        assert_eq!(names.len(), suites.len());
    }
}
