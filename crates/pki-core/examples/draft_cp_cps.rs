//! Lab-only CP/CPS preview exporter. Never publishes to a public repository.
//! Usage: cargo run -p trust-pki-core --example draft_cp_cps -- ./output
use std::{env, fs::{create_dir_all, OpenOptions}, io::Write, path::PathBuf};
use trust_pki_core::cp_cps::{digest_hex, generate, Input};
use trust_pki_crypto::SignatureAlgorithm;
use trust_pki_policy::StaticPolicy;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = PathBuf::from(env::args().nth(1).unwrap_or_else(|| "target/cp-cps-preview".into()));
    create_dir_all(&dir)?;
    let p = StaticPolicy {
        profile_id: "lab-server".into(),
        policy_version: "v1".into(),
        allowed_actors: vec!["lab-agent".into()],
        allowed_dns_zones: vec!["lab.invalid".into()],
        allowed_ca_signature_algorithms: vec![SignatureAlgorithm::EcdsaP256Sha256],
        max_validity_days: 30,
        max_dns_sans: 2,
    };
    let draft = generate(&Input {
        policy: &p,
        policy_oid: "1.3.6.1.4.1.55555.1.1",
        edition: "v0.1",
        issuer: "Sovereign Trust Lab CA",
        authority: "Unapproved Lab Policy Board",
        repository: "repository.lab.invalid/draft",
    }).map_err(|error| format!("draft rejected: {error:?}"))?;
    for (name, contents) in [
        ("certificate-policy.DRAFT.md", &draft.cp.markdown),
        ("certification-practice-statement.DRAFT.md", &draft.cps.markdown),
    ] {
        let path = dir.join(name);
        let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
    }
    println!("CP SHA-256: {}", digest_hex(&draft.cp.sha256));
    println!("CPS SHA-256: {}", digest_hex(&draft.cps.sha256));
    println!("Policy snapshot SHA-256: {}", digest_hex(&draft.policy_snapshot_sha256));
    println!("{} human review sections blocking publication.", draft.human_review_sections.len());
    assert!(!draft.publication_authorized);
    println!("DRAFT GENERATED — NO APPROVAL OR PUBLICATION");
    Ok(())
}
