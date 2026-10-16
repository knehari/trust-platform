//! Disposable RSA-PSS SHA384/SHA512 server chain for OpenSSL interoperability.
use std::{env, fs};
use trust_pki_core::{
    csr::verify_pkcs10_p256, rsa_pss_x509_lab::issue_ephemeral_rsa_pss_server_chain_for_digest,
    serial::SerialNumber as ReservedSerial, x509_extensions::ApprovedPolicyBinding,
};
use trust_pki_crypto::{
    crypto_agility::{AlgorithmSuite, Digest, KeyParameter, SignatureScheme},
    rsa_pss_lab::generate_lab_serial,
    SignatureAlgorithm,
};
use trust_pki_policy::{AuthenticatedPrincipal, IssuanceRequest, PolicyEngine, StaticPolicy};
use x509_cert::{
    der::{DecodePem, Encode},
    request::CertReq,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let digest = match args.next().as_deref() {
        Some("sha384") => Digest::Sha384,
        Some("sha512") => Digest::Sha512,
        _ => return Err("expected sha384 or sha512".into()),
    };
    let output = args.next().ok_or("output directory required")?;
    if args.next().is_some() {
        return Err("unexpected argument".into());
    }
    fs::create_dir_all(&output)?;
    let csr = CertReq::from_pem(include_str!("../tests/fixtures/ecdsa-p256-request.pem"))?;
    let verified = verify_pkcs10_p256(&csr.to_der()?, "api.lab.invalid")
        .map_err(|_| "verified CSR required")?;
    let policy = StaticPolicy {
        profile_id: "lab-rsa-server".into(),
        policy_version: "v1".into(),
        allowed_actors: vec!["lab-requester".into()],
        allowed_dns_zones: vec!["lab.invalid".into()],
        allowed_ca_signature_algorithms: vec![SignatureAlgorithm::RsaPssSha256],
        max_validity_days: 3,
        max_dns_sans: 3,
    };
    let principal = AuthenticatedPrincipal {
        subject_id: "lab-requester",
    };
    let names = ["api.lab.invalid"];
    let request = IssuanceRequest {
        profile_id: "lab-rsa-server",
        subject_common_name: "api.lab.invalid",
        dns_sans: &names,
        validity_days: 1,
        ca_signature_algorithm: SignatureAlgorithm::RsaPssSha256,
    };
    let approved = policy
        .authorize(&principal, &request)
        .map_err(|_| "lab authorization denied")?;
    let binding = ApprovedPolicyBinding::new("1.3.6.1.4.1.55555.1.1", "lab-cp-v1", [9u8; 32])
        .map_err(|_| "policy binding failed")?;
    // Local fixture only: production must retrieve this from PostgreSQL.
    let serial = ReservedSerial::from_positive_der_content(&generate_lab_serial())
        .map_err(|_| "invalid lab serial")?;
    let suite = AlgorithmSuite {
        scheme: SignatureScheme::RsaPss,
        key: KeyParameter::Rsa3072,
        digest,
    };
    let (root, leaf) = issue_ephemeral_rsa_pss_server_chain_for_digest(
        &verified,
        &approved,
        &binding,
        &serial,
        digest,
        &[suite],
    )
    .map_err(|_| "RSA-PSS typed lab chain failed")?;
    trust_pki_core::rsa_pss_issuer_verify_lab::verify_typed_rsa_pss_issuer_signature(
        &root, &leaf, suite,
    )
    .map_err(|_| "typed RSA-PSS issuer signature verification failed")?;
    fs::write(format!("{output}/root.der"), root.to_der()?)?;
    fs::write(format!("{output}/leaf.der"), leaf.to_der()?)?;
    Ok(())
}
