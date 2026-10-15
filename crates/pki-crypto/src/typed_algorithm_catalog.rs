//! Typed candidate inventory. Listed suites are not executable by default.
use crate::crypto_agility::{AlgorithmSuite, Digest, KeyParameter, SignatureScheme};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Maturity {
    Planned,
    Laboratory,
    ProductionQualified,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuiteRecordOwned {
    pub suite: AlgorithmSuite,
    pub maturity: Maturity,
    pub identifier: String,
}

/// Every candidate starts disabled until independently qualified.
pub fn planned_classical_suites() -> Vec<SuiteRecordOwned> {
    use Digest::{Intrinsic, Sha256, Sha384, Sha512};
    use KeyParameter::{P256, P384, P521, Rsa2048, Rsa3072, Rsa4096, Rsa8192};
    use SignatureScheme::{Ecdsa, RsaPkcs1V15, RsaPss};

    let mut result = Vec::new();
    for (key, size) in [
        (Rsa2048, "2048"),
        (Rsa3072, "3072"),
        (Rsa4096, "4096"),
        (Rsa8192, "8192"),
    ] {
        for (digest, hash) in [
            (Sha256, "sha256"),
            (Sha384, "sha384"),
            (Sha512, "sha512"),
        ] {
            for (scheme, prefix) in [(RsaPss, "rsa-pss"), (RsaPkcs1V15, "rsa-pkcs1v15")] {
                result.push(SuiteRecordOwned {
                    suite: AlgorithmSuite {
                        scheme,
                        key,
                        digest,
                    },
                    maturity: Maturity::Planned,
                    identifier: format!("{prefix}-{size}-{hash}"),
                });
            }
        }
    }
    for (key, digest, identifier) in [
        (P256, Sha256, "ecdsa-p256-sha256"),
        (P384, Sha384, "ecdsa-p384-sha384"),
        (P521, Sha512, "ecdsa-p521-sha512"),
    ] {
        result.push(SuiteRecordOwned {
            suite: AlgorithmSuite {
                scheme: Ecdsa,
                key,
                digest,
            },
            maturity: Maturity::Planned,
            identifier: identifier.to_owned(),
        });
    }
    for (scheme, key, identifier) in [
        (
            SignatureScheme::Ed25519,
            KeyParameter::Ed25519,
            "ed25519",
        ),
        (SignatureScheme::Ed448, KeyParameter::Ed448, "ed448"),
    ] {
        result.push(SuiteRecordOwned {
            suite: AlgorithmSuite {
                scheme,
                key,
                digest: Intrinsic,
            },
            maturity: Maturity::Planned,
            identifier: identifier.to_owned(),
        });
    }
    result
}

/// A catalogue entry alone never enables production use.
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
        assert!(suites
            .iter()
            .any(|s| s.identifier == "rsa-pss-8192-sha512"));
        assert!(suites
            .iter()
            .any(|s| s.identifier == "ecdsa-p384-sha384"));
    }

    #[test]
    fn identifiers_are_unique() {
        let suites = planned_classical_suites();
        let names: std::collections::HashSet<_> =
            suites.iter().map(|s| &s.identifier).collect();
        assert_eq!(names.len(), suites.len());
    }
}
