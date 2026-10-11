//! Review-only RFC 3647 CP/CPS draft generator from a validated policy snapshot.
//! Never equate generated prose with deployed practice or regulatory compliance.
use sha2::{Digest, Sha256};
use trust_pki_crypto::SignatureAlgorithm;
use trust_pki_policy::{valid_dns_name, StaticPolicy};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocumentKind {
    Cp,
    Cps,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Configuration,
    AdministrativeDeclaration,
    HumanEvidenceRequired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    pub number: &'static str,
    pub heading: &'static str,
    pub source: Source,
    pub content: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Document {
    pub kind: DocumentKind,
    pub markdown: String,
    pub sha256: [u8; 32],
    pub sections: Vec<Section>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DraftBundle {
    pub cp: Document,
    pub cps: Document,
    pub policy_snapshot_sha256: [u8; 32],
    pub human_review_sections: Vec<&'static str>,
    pub publication_authorized: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DraftError {
    InvalidOid,
    InvalidMetadata,
    InvalidProfile,
    InvalidRepository,
}

pub struct Input<'a> {
    pub policy: &'a StaticPolicy,
    pub policy_oid: &'a str,
    pub edition: &'a str,
    pub issuer: &'a str,
    pub authority: &'a str,
    pub repository: &'a str,
}

fn valid_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'/'))
}
fn valid_label(s: &str) -> bool {
    !s.trim().is_empty()
        && s.len() <= 256
        && !s
            .chars()
            .any(|c| c.is_control() || matches!(c, '#' | '<' | '>' | '*' | '|' | '[' | ']' | '`'))
}
fn valid_oid(s: &str) -> bool {
    if s == "2.5.29.32.0" {
        return false;
    }
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() < 3
        || parts.len() > 32
        || parts.iter().any(|p| {
            p.is_empty()
                || p.len() > 18
                || (p.len() > 1 && p.starts_with('0'))
                || !p.bytes().all(|b| b.is_ascii_digit())
        })
    {
        return false;
    }
    let arcs: Option<Vec<u64>> = parts.iter().map(|p| p.parse::<u64>().ok()).collect();
    match arcs {
        Some(a) => a[0] <= 2 && (a[0] == 2 || a[1] <= 39),
        None => false,
    }
}
fn algo(a: SignatureAlgorithm) -> &'static str {
    match a {
        SignatureAlgorithm::EcdsaP256Sha256 => "ECDSA P-256 with SHA-256",
        SignatureAlgorithm::RsaPssSha256 => "RSA-PSS with SHA-256",
        SignatureAlgorithm::MlDsa65 => "ML-DSA-65 (implementation NOT verified)",
    }
}
pub fn digest_hex(hash: &[u8; 32]) -> String {
    hash.iter().map(|b| format!("{b:02x}")).collect()
}
fn section(
    number: &'static str,
    heading: &'static str,
    source: Source,
    content: String,
) -> Section {
    Section {
        number,
        heading,
        source,
        content,
    }
}
fn manual(number: &'static str, heading: &'static str, evidence: &'static str) -> Section {
    section(
        number,
        heading,
        Source::HumanEvidenceRequired,
        format!("PENDING HUMAN VALIDATION. Required evidence: {evidence}"),
    )
}
fn document(
    kind: DocumentKind,
    input: &Input<'_>,
    zones: &[String],
    algorithms: &[String],
    source_hash: &[u8; 32],
) -> Document {
    let label = match kind {
        DocumentKind::Cp => "Certificate Policy (CP)",
        DocumentKind::Cps => "Certification Practice Statement (CPS)",
    };
    let scope = match kind {
        DocumentKind::Cp => "Proposed requirements derived from a policy configuration, pending policy-authority approval.",
        DocumentKind::Cps => "Proposed operating practices from a software configuration; real deployment is NOT verified.",
    };
    let mut sections = vec![
        section("1", "Introduction", Source::AdministrativeDeclaration,
            format!("Issuer: {}. Policy authority: {}. DRAFT only.", input.issuer, input.authority)),
        section("1.2", "Document identification", Source::AdministrativeDeclaration,
            format!("Edition: {}. Requested certificatePolicies OID: {}. OID ownership NOT verified.",
                input.edition, input.policy_oid)),
        section("1.4", "Certificate usage", Source::Configuration,
            format!("{scope} Issuance profile: {}. Configured DNS zones: {}.",
                input.policy.profile_id, zones.join(", "))),
        manual("1.5", "Policy administration",
            "Written CP/CPS approval, actual OID ownership and designated policy authority."),
        section("2", "Publication and repository responsibilities", Source::AdministrativeDeclaration,
            format!("Proposed repository reference: {}. Publication and access controls NOT verified.",
                input.repository)),
        manual("2.4", "Repository controls",
            "Repository availability, integrity, controlled publication and document supersession."),
        section("3", "Identification and authentication", Source::HumanEvidenceRequired,
            format!("PENDING HUMAN VALIDATION. The policy allowlist contains {} principals. Their identity and deployed authorization are NOT independently verified. Required: identity vetting, RA authorization and proof of possession.", input.policy.allowed_actors.len())),
        section("4", "Certificate life-cycle requirements", Source::Configuration,
            format!("{scope} Signing algorithm(s): {}. Maximum validity: {} days. Maximum DNS SANs: {}. Policy configuration revision: {}.",
                algorithms.join(", "), input.policy.max_validity_days,
                input.policy.max_dns_sans, input.policy.policy_version)),
        manual("4.9", "Revocation and suspension",
            "Authorized revocation requests, SLAs and tested CRL/OCSP publication."),
        manual("5", "Facility and operational controls",
            "Facilities, business continuity, personnel, roles and signed key ceremony records."),
        manual("5.4", "Audit logging",
            "Log integrity, independent evidence storage, trusted time and review procedures."),
        manual("6", "Technical security controls",
            "HSM custody, key ceremony, disaster recovery, entropy and crypto-agility evidence."),
        section("7", "Certificate, CRL and OCSP profiles", Source::Configuration,
            format!("{scope} Requested certificate policy OID: {}. Supported profile algorithms to verify: {}.",
                input.policy_oid, algorithms.join(", "))),
        manual("7.2", "CRL and OCSP profiles",
            "Signed revocation artifacts, test results and validation frequency."),
        manual("8", "Compliance audit and assessment",
            "Independent assessor, ETSI/eIDAS applicability, scope, findings and remediations."),
        manual("9", "Other business and legal matters",
            "Subscriber and relying-party terms, privacy, liability and jurisdiction."),
        manual("9.12", "Amendments",
            "Approval, change management, retention and publication of superseded versions."),
    ];
    if kind == DocumentKind::Cps {
        // RFC 3647 section 6.7 belongs before section 7, not after 9.
        sections.insert(
            12,
            manual(
                "6.7",
                "Network security controls",
                "Observed CA isolation, access policy and mutual TLS tests.",
            ),
        );
    }
    let mut markdown = format!("# {label}  -  DRAFT {}\n\nSTATUS: NOT APPROVED / DO NOT PUBLISH.\nFramework: RFC 3647.\nPolicy snapshot SHA-256: {}.\nNot an ETSI, ANSSI, ISO or eIDAS compliance assertion.\n",
        input.edition, digest_hex(source_hash));
    for s in &sections {
        markdown.push_str(&format!(
            "\n## {} {}\n\nSource: {:?}. {}\n",
            s.number, s.heading, s.source, s.content
        ));
    }
    markdown.push_str("\nPublication prohibited until operational evidence, OID ownership and policy-authority approval are independently validated.\n");
    let sha256 = Sha256::digest(markdown.as_bytes()).into();
    Document {
        kind,
        markdown,
        sha256,
        sections,
    }
}

/// Generates only draft artifacts. No approval/publication code path exists.
pub fn generate(input: &Input<'_>) -> Result<DraftBundle, DraftError> {
    if !valid_oid(input.policy_oid) {
        return Err(DraftError::InvalidOid);
    }
    if !valid_id(input.edition) || !valid_label(input.issuer) || !valid_label(input.authority) {
        return Err(DraftError::InvalidMetadata);
    }
    if !valid_id(input.repository) {
        return Err(DraftError::InvalidRepository);
    }
    let p = input.policy;
    if !valid_id(&p.profile_id)
        || !valid_id(&p.policy_version)
        || p.allowed_actors.is_empty()
        || p.allowed_actors.iter().any(|actor| actor.trim().is_empty())
        || p.allowed_dns_zones.is_empty()
        || p.allowed_ca_signature_algorithms.is_empty()
        || p.max_validity_days == 0
        || p.max_dns_sans == 0
        || p.allowed_dns_zones.iter().any(|z| !valid_dns_name(z))
    {
        return Err(DraftError::InvalidProfile);
    }
    let mut zones = p.allowed_dns_zones.clone();
    zones.sort();
    zones.dedup();
    // Hash the private authorization roster without publishing principal IDs.
    let mut actors = p.allowed_actors.clone();
    actors.sort();
    actors.dedup();
    let mut algorithms: Vec<String> = p
        .allowed_ca_signature_algorithms
        .iter()
        .map(|a| algo(*a).to_owned())
        .collect();
    algorithms.sort();
    algorithms.dedup();
    let mut sha = Sha256::new();
    for field in [
        input.policy_oid,
        input.edition,
        &p.profile_id,
        &p.policy_version,
        input.issuer,
        input.authority,
        input.repository,
    ]
    .into_iter()
    .chain(zones.iter().map(String::as_str))
    .chain(algorithms.iter().map(String::as_str))
    .chain(actors.iter().map(String::as_str))
    {
        sha.update((field.len() as u32).to_be_bytes());
        sha.update(field.as_bytes());
    }
    sha.update(p.max_validity_days.to_be_bytes());
    sha.update((p.max_dns_sans as u64).to_be_bytes());
    let source_hash = sha.finalize().into();
    let cp = document(DocumentKind::Cp, input, &zones, &algorithms, &source_hash);
    let cps = document(DocumentKind::Cps, input, &zones, &algorithms, &source_hash);
    let human_review_sections = cps
        .sections
        .iter()
        .filter(|s| s.source == Source::HumanEvidenceRequired)
        .map(|s| s.number)
        .collect();
    Ok(DraftBundle {
        cp,
        cps,
        policy_snapshot_sha256: source_hash,
        human_review_sections,
        publication_authorized: false,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeReport {
    pub changed_sections: Vec<String>,
    pub reapproval_required: bool,
}
pub fn compare(previous: &Document, current: &Document) -> ChangeReport {
    let mut changed: Vec<String> = current
        .sections
        .iter()
        .filter(|s| previous.sections.iter().find(|o| o.number == s.number) != Some(*s))
        .map(|s| s.number.to_owned())
        .collect();
    changed.extend(
        previous
            .sections
            .iter()
            .filter(|s| !current.sections.iter().any(|c| c.number == s.number))
            .map(|s| s.number.to_owned()),
    );
    changed.sort();
    changed.dedup();
    ChangeReport {
        changed_sections: changed,
        reapproval_required: previous.sha256 != current.sha256,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn policy() -> StaticPolicy {
        StaticPolicy {
            profile_id: "lab-server".into(),
            policy_version: "v1".into(),
            allowed_actors: vec!["private-build-agent".into()],
            allowed_dns_zones: vec!["lab.invalid".into(), "apps.lab.invalid".into()],
            allowed_ca_signature_algorithms: vec![SignatureAlgorithm::EcdsaP256Sha256],
            max_validity_days: 30,
            max_dns_sans: 4,
        }
    }
    fn input(p: &StaticPolicy) -> Input<'_> {
        Input {
            policy: p,
            policy_oid: "1.3.6.1.4.1.55555.1.1",
            edition: "v0.1",
            issuer: "Lab Root CA",
            authority: "Lab Policy Board",
            repository: "pki.example.invalid/repository",
        }
    }
    #[test]
    fn reproducible_cp_cps_sections_and_draft_only() {
        let p = policy();
        let a = generate(&input(&p)).unwrap();
        assert_eq!(a, generate(&input(&p)).unwrap());
        for n in 1..=9 {
            assert!(a.cp.markdown.contains(&format!("\n## {n} ")));
            assert!(a.cps.markdown.contains(&format!("\n## {n} ")));
        }
        assert!(!a.cp.markdown.contains("private-build-agent"));
        assert!(!a.publication_authorized);
        assert!(a.cps.markdown.find("## 6.7 ").unwrap() < a.cps.markdown.find("## 7 ").unwrap());
        assert!(a.human_review_sections.len() >= 9);
    }
    #[test]
    fn changes_to_validity_trigger_review() {
        let mut p = policy();
        let before = generate(&input(&p)).unwrap();
        p.max_validity_days = 7;
        let after = generate(&input(&p)).unwrap();
        let diff = compare(&before.cps, &after.cps);
        assert!(diff.reapproval_required);
        assert!(diff.changed_sections.contains(&"4".to_owned()));
        assert_ne!(before.policy_snapshot_sha256, after.policy_snapshot_sha256);
    }
    #[test]
    fn zone_order_is_canonicalized() {
        let mut p = policy();
        let a = generate(&input(&p)).unwrap();
        p.allowed_dns_zones.reverse();
        assert_eq!(a.cp.sha256, generate(&input(&p)).unwrap().cp.sha256);
    }
    #[test]
    fn human_controls_cannot_be_claimed_implemented() {
        let p = policy();
        let docs = generate(&input(&p)).unwrap();
        assert!(docs.cps.markdown.contains("PENDING HUMAN VALIDATION"));
        assert!(docs.cps.markdown.contains("HSM custody"));
        assert!(docs.cp.markdown.contains("DO NOT PUBLISH"));
    }
    #[test]
    fn oid_and_metadata_validation_fails_closed() {
        let p = policy();
        let mut i = input(&p);
        i.policy_oid = "2.5.29.32.0";
        assert_eq!(generate(&i), Err(DraftError::InvalidOid));
        i.policy_oid = "1.03.6";
        assert_eq!(generate(&i), Err(DraftError::InvalidOid));
        i.policy_oid = "1.3.6.1.4.1.55555.1.1";
        i.issuer = "Issuer\n## Injected heading";
        assert_eq!(generate(&i), Err(DraftError::InvalidMetadata));
    }
    #[test]
    fn invalid_profile_is_rejected() {
        let mut p = policy();
        p.allowed_dns_zones = vec!["*.invalid".into()];
        assert_eq!(generate(&input(&p)), Err(DraftError::InvalidProfile));
    }
    #[test]
    fn authorized_actor_changes_trigger_review_without_disclosing_identities() {
        let mut p = policy();
        let old = generate(&input(&p)).unwrap();
        p.allowed_actors.push("other-privileged-actor".into());
        let current = generate(&input(&p)).unwrap();
        let change = compare(&old.cps, &current.cps);
        assert!(change.reapproval_required);
        assert!(change.changed_sections.contains(&"3".to_owned()));
        assert_ne!(old.policy_snapshot_sha256, current.policy_snapshot_sha256);
        assert!(!current.cps.markdown.contains("other-privileged-actor"));
    }
    #[test]
    fn changing_roster_with_same_count_still_invalidates_source_digest() {
        let mut p = policy();
        let before = generate(&input(&p)).unwrap();
        p.allowed_actors[0] = "renamed-private-actor".into();
        let after = generate(&input(&p)).unwrap();
        assert_ne!(before.policy_snapshot_sha256, after.policy_snapshot_sha256);
        assert!(compare(&before.cp, &after.cp).reapproval_required);
    }
    #[test]
    fn ml_dsa_is_not_claimed_ready() {
        let mut p = policy();
        p.allowed_ca_signature_algorithms
            .push(SignatureAlgorithm::MlDsa65);
        let docs = generate(&input(&p)).unwrap();
        assert!(docs.cps.markdown.contains("implementation NOT verified"));
        assert!(!docs.publication_authorized);
    }
    #[test]
    fn version_change_requires_reapproval() {
        let p = policy();
        let a = generate(&input(&p)).unwrap();
        let mut i = input(&p);
        i.edition = "v0.2";
        let b = generate(&i).unwrap();
        let delta = compare(&a.cp, &b.cp);
        assert!(delta.reapproval_required);
        assert!(delta.changed_sections.contains(&"1.2".into()));
    }
}
