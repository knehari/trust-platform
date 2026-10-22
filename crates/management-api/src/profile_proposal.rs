//! Advisory syntax checks for inert profile proposals. These never authorize issuance.

use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

use crate::ProfileDraft;

/// Hashes an unambiguous v1 envelope of the proposed policy snapshot.
/// Creator and recording time are provenance, not policy semantics.
pub(super) fn snapshot_sha256(draft: &ProfileDraft) -> String {
    let mut hash = Sha256::new();
    hash.update(b"trust-platform/profile-draft/v1\0");
    write_text(&mut hash, &draft.ca_id);
    write_text(&mut hash, &draft.profile_id);
    hash.update(draft.revision.to_be_bytes());
    write_text(&mut hash, &draft.display_name);
    write_text(&mut hash, &draft.policy_version);
    hash.update(draft.max_validity_days.to_be_bytes());
    hash.update(draft.max_dns_sans.to_be_bytes());
    write_list(&mut hash, &draft.proposed_dns_zones);
    write_list(&mut hash, &draft.proposed_signature_suites);
    format!("{:x}", hash.finalize())
}

fn write_text(hash: &mut Sha256, value: &str) {
    hash.update((value.len() as u64).to_be_bytes());
    hash.update(value.as_bytes());
}

fn write_list(hash: &mut Sha256, values: &[String]) {
    hash.update((values.len() as u64).to_be_bytes());
    for value in values {
        write_text(hash, value);
    }
}

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

    #[test]
    fn snapshot_digest_binds_policy_fields_and_ignores_provenance() {
        let mut draft = ProfileDraft {
            ca_id: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee".into(),
            profile_id: "server-lab".into(),
            revision: 1,
            display_name: "Server proposal".into(),
            policy_version: "v1".into(),
            max_validity_days: 90,
            max_dns_sans: 5,
            proposed_dns_zones: vec!["lab.invalid".into()],
            proposed_signature_suites: vec!["P256-SHA256".into()],
            created_by: "editor-one".into(),
            created_at: "2026-10-22T00:00:00.000Z".into(),
            status: "DRAFT",
            proposal_warnings: vec![],
            snapshot_sha256: String::new(),
        };
        let initial = snapshot_sha256(&draft);
        assert_eq!(initial.len(), 64);
        draft.created_by = "editor-two".into();
        draft.created_at = "2026-10-23T00:00:00.000Z".into();
        assert_eq!(snapshot_sha256(&draft), initial);
        draft.max_validity_days = 60;
        assert_ne!(snapshot_sha256(&draft), initial);
        draft.max_validity_days = 90;
        draft.proposed_dns_zones.push("other.invalid".into());
        assert_ne!(snapshot_sha256(&draft), initial);
        draft.proposed_dns_zones.pop();
        draft.revision += 1;
        assert_ne!(snapshot_sha256(&draft), initial);
    }
}
