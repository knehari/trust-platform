//! Lab-only X.509 issuer demo. Writes PUBLIC CERTIFICATES ONLY.
//! CA signing key is ephemeral and is never written to disk.
//! Usage: cargo run -p trust-pki-core --features lab-software --example issue_lab -- /tmp/lab-public-certs

use std::{env, fs, path::PathBuf};
use trust_pki_core::{
    csr::verify_pkcs10_p256, lab_ca::EphemeralLabCa, serial::SerialNumber,
    x509_extensions::ApprovedPolicyBinding,
};
use trust_pki_crypto::SignatureAlgorithm;
use trust_pki_policy::{AuthenticatedPrincipal, IssuanceRequest, PolicyEngine, StaticPolicy};
use x509_cert::{
    der::{pem::LineEnding, DecodePem, Encode, EncodePem},
    request::CertReq,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output = PathBuf::from(
        env::args()
            .nth(1)
            .unwrap_or_else(|| "lab-public-certs".into()),
    );
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
    let serial = SerialNumber::from_positive_der_content(&[0x02])
        .map_err(|e| format!("invalid serial: {e:?}"))?;
    // Example-only policy OID, not an assigned enterprise OID or published CP.
    let binding = ApprovedPolicyBinding::new("1.3.6.1.4.1.55555.1.1", "lab-cp-v1", [9u8; 32])
        .map_err(|e| format!("invalid policy binding: {e:?}"))?;
    let leaf = ca
        .issue_leaf(&verified, &decision, &serial, &binding)
        .map_err(|e| format!("lab issuance rejected: {e:?}"))?;

    fs::write(
        output.join("root.pem"),
        ca.root_certificate().to_pem(LineEnding::LF)?,
    )?;
    fs::write(output.join("leaf.pem"), leaf.to_pem(LineEnding::LF)?)?;

    println!("Generated PUBLIC lab certificates in {}", output.display());
    println!("No private keys written to disk. This lab issuer is ephemeral and non-production.");
    Ok(())
}
