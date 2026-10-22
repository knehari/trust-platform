//! Advisory syntax checks for inert profile proposals. These never authorize issuance.

use std::collections::BTreeSet;

pub(super) fn syntax_warnings(
    display_name: &str,
    policy_version: &str,
    zones: &[String],
    suites: &[String],
) -> Vec<&'static str> {
    let mut warnings = Vec::new();
    if display_name.trim().is_empty() {
        warnings.push("blank_display_name");
    }
    if policy_version.trim().is_empty() {
        warnings.push("blank_policy_version");
    }
    if zones.iter().any(|zone| !valid_dns_zone(zone)) {
        warnings.push("invalid_dns_zone");
    }
    let mut seen_zones = BTreeSet::new();
    if zones
        .iter()
        .any(|zone| !seen_zones.insert(zone.to_ascii_lowercase()))
    {
        warnings.push("duplicate_dns_zone");
    }
    if suites.iter().any(|suite| !valid_suite_id(suite)) {
        warnings.push("invalid_suite_id");
    }
    let mut seen_suites = BTreeSet::new();
    if suites
        .iter()
        .any(|suite| !seen_suites.insert(suite.to_ascii_lowercase()))
    {
        warnings.push("duplicate_suite_id");
    }
    warnings
}

fn valid_dns_zone(zone: &str) -> bool {
    if zone.is_empty() || zone.len() > 253 || !zone.is_ascii() || zone != zone.to_ascii_lowercase()
    {
        return false;
    }
    zone.split('.').all(|label| {
        (1..=63).contains(&label.len())
            && label
                .bytes()
                .next()
                .is_some_and(|c| c.is_ascii_alphanumeric())
            && label
                .bytes()
                .last()
                .is_some_and(|c| c.is_ascii_alphanumeric())
            && label
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
    })
}

fn valid_suite_id(suite: &str) -> bool {
    (1..=64).contains(&suite.len())
        && suite
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_lab_proposal_has_no_syntax_warnings() {
        assert!(syntax_warnings(
            "Server proposal",
            "v1",
            &["lab.invalid".into()],
            &["P256-SHA256".into()]
        )
        .is_empty());
    }

    #[test]
    fn malformed_and_repeated_values_are_reported_without_authorizing() {
        let warnings = syntax_warnings(
            "  ",
            "\t",
            &[
                "-bad.lab.invalid".into(),
                "lab.invalid".into(),
                "LAB.INVALID".into(),
            ],
            &[
                "P256-SHA256".into(),
                "p256-sha256".into(),
                "suite with spaces".into(),
            ],
        );
        assert_eq!(
            warnings,
            [
                "blank_display_name",
                "blank_policy_version",
                "invalid_dns_zone",
                "duplicate_dns_zone",
                "invalid_suite_id",
                "duplicate_suite_id",
            ]
        );
    }

    #[test]
    fn dns_label_boundaries_are_checked() {
        assert!(valid_dns_zone("a.lab.invalid"));
        for invalid in [
            "",
            ".lab.invalid",
            "lab..invalid",
            "lab.invalid.",
            "a_b.invalid",
            "*.lab.invalid",
            "UPPER.invalid",
        ] {
            assert!(!valid_dns_zone(invalid), "{invalid}");
        }
        assert!(!valid_dns_zone(&format!("{}.invalid", "a".repeat(64))));
    }
}
