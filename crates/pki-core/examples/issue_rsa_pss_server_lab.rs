//! Disposable RSA-PSS signed server chain for OpenSSL interop testing.
use std::{env, fs};
use trust_pki_core::{
    csr::verify_pkcs10_p256, rsa_pss_x509_lab::issue_ephemeral_rsa_pss_server_chain,
    serial::SerialNumber as ReservedSerial, x509_extensions::ApprovedPolicyBinding,
};
use trust_pki_crypto::{rsa_pss_lab::generate_lab_serial, SignatureAlgorithm};
use trust_pki_policy::{AuthenticatedPrincipal, IssuanceRequest, PolicyEngine, StaticPolicy};
use x509_cert::{
    der::{DecodePem, Encode},
    request::CertReq,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output = env::args().nth(1).ok_or("output directory required")?;
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
    let (root, leaf) =
        issue_ephemeral_rsa_pss_server_chain(&verified, &approved, &binding, &serial)
            .map_err(|_| "RSA-PSS lab chain failed")?;
    fs::write(format!("{output}/root.der"), root.to_der()?)?;
    fs::write(format!("{output}/leaf.der"), leaf.to_der()?)?;
    Ok(())
}
