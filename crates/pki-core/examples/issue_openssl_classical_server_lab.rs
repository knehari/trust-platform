//! Disposable TLS server chain signed with P-384, P-521, Ed25519 or Ed448.
#![cfg(unix)]
use std::{env, fs};
use trust_pki_core::{
    csr::verify_pkcs10_p256,
    openssl_classical_server_lab::issue_openssl_classical_server_chain_lab,
    serial::SerialNumber as ReservedSerial, x509_extensions::ApprovedPolicyBinding,
};
use trust_pki_crypto::{
    crypto_agility::{AlgorithmSuite, Digest, KeyParameter, SignatureScheme},
    rsa_pss_lab::generate_lab_serial,
};
use trust_pki_policy::{
    native_typed_policy::{NativeTypedIssuanceRequest, NativeTypedPolicy},
    AuthenticatedPrincipal,
};
use x509_cert::{
    der::{DecodePem, Encode},
    request::CertReq,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let suite = match args.next().as_deref() {
        Some("p384") => AlgorithmSuite {
            scheme: SignatureScheme::Ecdsa,
            key: KeyParameter::P384,
            digest: Digest::Sha384,
        },
        Some("p521") => AlgorithmSuite {
            scheme: SignatureScheme::Ecdsa,
            key: KeyParameter::P521,
            digest: Digest::Sha512,
        },
        Some("ed25519") => AlgorithmSuite {
            scheme: SignatureScheme::Ed25519,
            key: KeyParameter::Ed25519,
            digest: Digest::Intrinsic,
        },
        Some("ed448") => AlgorithmSuite {
            scheme: SignatureScheme::Ed448,
            key: KeyParameter::Ed448,
            digest: Digest::Intrinsic,
        },
        _ => return Err("expected p384, p521, ed25519 or ed448".into()),
    };
    let target = args.next().ok_or("output directory required")?;
    if args.next().is_some() {
        return Err("unexpected argument".into());
    }
    fs::create_dir_all(&target)?;
    let csr = CertReq::from_pem(include_str!("../tests/fixtures/ecdsa-p256-request.pem"))?;
    let verified = verify_pkcs10_p256(&csr.to_der()?, "api.lab.invalid")
        .map_err(|_| "verified CSR required")?;
    let policy = NativeTypedPolicy {
        profile_id: "classical-tls-lab".into(),
        policy_version: "v2".into(),
        allowed_actors: vec!["lab-requester".into()],
        allowed_dns_zones: vec!["lab.invalid".into()],
        allowed_issuer_suites: vec![suite],
        allowed_subject_keys: vec![KeyParameter::P256],
        max_validity_days: 3,
        max_dns_sans: 3,
    };
    let names = ["api.lab.invalid"];
    let approval = policy
        .authorize(
            &AuthenticatedPrincipal {
                subject_id: "lab-requester",
            },
            &NativeTypedIssuanceRequest {
                profile_id: "classical-tls-lab",
                subject_common_name: "api.lab.invalid",
                dns_sans: &names,
                validity_days: 1,
                issuer_suite: suite,
                subject_key: KeyParameter::P256,
            },
        )
        .map_err(|_| "typed policy denial")?;
    let binding = ApprovedPolicyBinding::new("1.3.6.1.4.1.55555.1.1", "lab-cp-v1", [9u8; 32])
        .map_err(|_| "CP binding denied")?;
    let serial = ReservedSerial::from_positive_der_content(&generate_lab_serial())
        .map_err(|_| "invalid serial")?;
    let (root, leaf) =
        issue_openssl_classical_server_chain_lab(&verified, &approval, &binding, &serial)
            .map_err(|_| "lab TLS chain issuance failed")?;
    fs::write(format!("{target}/root.der"), root.to_der()?)?;
    fs::write(format!("{target}/leaf.der"), leaf.to_der()?)?;
    Ok(())
}
