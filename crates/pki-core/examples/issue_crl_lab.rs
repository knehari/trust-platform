//! Lab-only CRL demo. Writes PUBLIC objects only (root, three leaves, two CRLs, all DER).
//! The CA signing key is ephemeral and is never written to disk.
//!
//! This proves CRL FORMAT INTEROP with OpenSSL only. The in-memory journal and
//! reservations below are not durable and enforce no maker-checker control;
//! maker-checker and durability are proven by migrations 0014/0015 and the
//! `revocation_crl_postgres` integration test.
//!
//! Scenario: CRL 1 = {leaf1 keyCompromise, leaf2 certificateHold}; CRL 2 = {leaf1}
//! (the hold on leaf2 is released). Leaf 3 is never revoked by a complete CRL.
//! CRL 3 is a delta CRL on base 1 (RFC 5280 5.2.4): leaf3 superseded, and
//! leaf2 removeFromCRL; it is written as crl3_delta.der.
//! Usage: cargo run -p trust-pki-core --features lab-software --example issue_crl_lab -- /tmp/lab-crl

use std::{
    env, fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
use trust_pki_core::{
    crl::{CrlEntry, CrlError, CrlReservation, LabCrlAssembler, LabCrlVerifier, ReleasedEntry},
    crl_orchestrator::{crl_once, CrlJournal, CrlPlan},
    csr::verify_pkcs10_p256,
    lab_ca::EphemeralLabCa,
    revocation::RevocationReason,
    serial::SerialNumber,
    x509_extensions::ApprovedPolicyBinding,
};
use trust_pki_crypto::SignatureAlgorithm;
use trust_pki_policy::{AuthenticatedPrincipal, IssuanceRequest, PolicyEngine, StaticPolicy};
use x509_cert::{
    der::{DecodePem, Encode},
    request::CertReq,
};

const CRL_VALIDITY_SECONDS: i64 = 7 * 24 * 3600;

/// Records intent once and keeps the verified CRL in memory; example only.
#[derive(Default)]
struct MemoryJournal {
    intents: Vec<String>,
    persisted: usize,
}

impl CrlJournal for MemoryJournal {
    fn record_intent(
        &mut self,
        plan: &CrlPlan<'_>,
        _tbs_sha256: &[u8; 32],
    ) -> Result<(), CrlError> {
        if self.intents.iter().any(|o| o == plan.operation_ref) {
            return Err(CrlError::JournalFailure);
        }
        self.intents.push(plan.operation_ref.to_owned());
        Ok(())
    }

    fn mark_uncertain(&mut self, _plan: &CrlPlan<'_>) -> Result<(), CrlError> {
        Ok(())
    }

    fn persist_verified(
        &mut self,
        _plan: &CrlPlan<'_>,
        _tbs_sha256: &[u8; 32],
        _crl_sha256: &[u8; 32],
        _crl_der: &[u8],
    ) -> Result<(), CrlError> {
        self.persisted += 1;
        Ok(())
    }
}

fn serial(byte: u8) -> Result<SerialNumber, String> {
    SerialNumber::from_positive_der_content(&[byte]).map_err(|e| format!("invalid serial: {e:?}"))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output = PathBuf::from(env::args().nth(1).unwrap_or_else(|| "lab-crl".into()));
    fs::create_dir_all(&output)?;

    let csr = CertReq::from_pem(include_str!("../tests/fixtures/ecdsa-p256-request.pem"))?;
    let verified = verify_pkcs10_p256(&csr.to_der()?, "api.lab.invalid")
        .map_err(|e| format!("CSR rejected: {e:?}"))?;

    let policy = StaticPolicy {
        profile_id: "lab-server".into(),
        policy_version: "v1".into(),
        allowed_actors: vec!["lab-issuer".into()],
        allowed_dns_zones: vec!["lab.invalid".into()],
        allowed_ca_signature_algorithms: vec![SignatureAlgorithm::EcdsaP256Sha256],
        max_validity_days: 3,
        max_dns_sans: 2,
    };
    let principal = AuthenticatedPrincipal {
        subject_id: "lab-issuer",
    };
    let sans = ["api.lab.invalid"];
    let request = IssuanceRequest {
        profile_id: "lab-server",
        subject_common_name: "api.lab.invalid",
        dns_sans: &sans,
        validity_days: 1,
        ca_signature_algorithm: SignatureAlgorithm::EcdsaP256Sha256,
    };
    let decision = policy
        .authorize(&principal, &request)
        .map_err(|e| format!("policy rejected: {e:?}"))?;

    let mut ca = EphemeralLabCa::new("Sovereign Trust Lab Root")
        .map_err(|e| format!("cannot initialize lab CA: {e:?}"))?;
    // Example-only policy OID, not an assigned enterprise OID or published CP.
    let binding = ApprovedPolicyBinding::new("1.3.6.1.4.1.55555.1.1", "lab-cp-v1", [9u8; 32])
        .map_err(|e| format!("invalid policy binding: {e:?}"))?;

    let mut leaves = Vec::new();
    for n in 1u8..=3 {
        let leaf = ca
            .issue_leaf(&verified, &decision, &serial(n)?, &binding)
            .map_err(|e| format!("lab issuance rejected: {e:?}"))?;
        leaves.push(leaf.to_der()?);
    }

    // Whole seconds, so thisUpdate <= now < nextUpdate for any verifier.
    let now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
    let entry = |n: u8, reason: RevocationReason| -> Result<CrlEntry, String> {
        Ok(CrlEntry {
            serial: serial(n)?,
            revoked_at_unix: now,
            reason,
            invalidity_at_unix: None,
        })
    };
    let reservation = |number: u64, entries: Vec<CrlEntry>| {
        CrlReservation::new(
            "lab-root",
            number,
            now,
            now + CRL_VALIDITY_SECONDS,
            entries,
            None,
        )
        .map_err(|e| format!("invalid CRL reservation: {e:?}"))
    };
    let reservations = [
        reservation(
            1,
            vec![
                entry(1, RevocationReason::KeyCompromise)?,
                entry(2, RevocationReason::CertificateHold)?,
            ],
        )?
        // Example URL only: OpenSSL applies delta CRLs only to a base that
        // advertises them.
        .with_freshest_crl("http://crl.lab.invalid/delta/lab-root.crl")
        .map_err(|e| format!("invalid freshest CRL: {e:?}"))?,
        reservation(2, vec![entry(1, RevocationReason::KeyCompromise)?])?,
        CrlReservation::new_delta(
            "lab-root",
            3,
            1,
            now,
            now + CRL_VALIDITY_SECONDS,
            vec![entry(3, RevocationReason::Superseded)?],
            vec![ReleasedEntry {
                serial: serial(2)?,
                released_at_unix: now,
            }],
        )
        .map_err(|e| format!("invalid delta CRL reservation: {e:?}"))?,
    ];

    let root = ca.root_certificate().clone();
    let verifier = LabCrlVerifier::new(root.clone());
    let mut journal = MemoryJournal::default();
    let signer_key_ref = ca.lab_signer_key_ref().to_owned();
    let mut crls = Vec::new();
    for reservation in &reservations {
        let operation_ref = format!("lab-crl-{}", reservation.crl_number());
        let plan = CrlPlan {
            reservation,
            issuer: &root,
            signer_key_ref: &signer_key_ref,
            operation_ref: &operation_ref,
        };
        let crl = crl_once(&mut journal, &mut ca, &LabCrlAssembler, &verifier, &plan)
            .map_err(|e| format!("CRL issuance failed: {e:?}"))?;
        crls.push(crl);
    }

    fs::write(output.join("root.der"), ca.root_certificate().to_der()?)?;
    for (i, leaf) in leaves.iter().enumerate() {
        fs::write(output.join(format!("leaf{}.der", i + 1)), leaf)?;
    }
    for (reservation, crl) in reservations.iter().zip(&crls) {
        let name = match reservation.base_crl_number() {
            None => format!("crl{}.der", reservation.crl_number()),
            Some(_) => format!("crl{}_delta.der", reservation.crl_number()),
        };
        fs::write(output.join(name), crl)?;
    }

    println!(
        "Generated PUBLIC lab certificates and CRLs in {}",
        output.display()
    );
    println!("No private keys written to disk. This lab issuer is ephemeral and non-production.");
    Ok(())
}
