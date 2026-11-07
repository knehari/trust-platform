//! Lab-only RFC 5280 path-validation suite (section 6) over certificates and
//! CRLs produced by the platform's lab issuer and CRL pipeline.
//!
//! Each case states the expected outcome, and an independent validator,
//! rustls-webpki, must agree: the platform's own checks are not the judge.
//! With TRUST_PATH_VALIDATION_EXPORT_DIR set, the artifacts and a manifest of
//! the same cases are written there (public objects only) and
//! tests/rfc5280_path_validation.sh replays every case with OpenSSL.
//!
//! The lab issuer has one level (a root with pathLenConstraint 0, end-entity
//! leaves); the cases cover what that shape can exercise:
//! - 6.1.3 (a)(1) signature, (a)(2) validity period, (a)(3) revocation,
//!   (a)(4) issuer name chaining;
//! - 6.1.4 (k) basicConstraints cA, and the root's pathLenConstraint 0;
//! - 4.2.1.12 extended key usage, 4.2.1.6 subject alternative name;
//! - CRL validation (6.3): signature by the issuer's key, nextUpdate.
//!
//! Intermediates, name constraints and policy processing are not covered:
//! the lab issuer cannot produce them.
#![cfg(feature = "lab-software")]

use std::{
    fmt::Write as _,
    fs,
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use trust_pki_core::{
    crl::{CrlEntry, CrlError, CrlReservation, LabCrlAssembler, LabCrlVerifier},
    crl_orchestrator::{crl_once, CrlJournal, CrlPlan},
    csr::verify_pkcs10_p256,
    lab_ca::EphemeralLabCa,
    revocation::RevocationReason,
    serial::SerialNumber,
    x509_extensions::{self, ApprovedPolicyBinding},
};
use trust_pki_crypto::{lab::EphemeralP256Signer, SignatureAlgorithm, SigningProvider};
use trust_pki_policy::{AuthenticatedPrincipal, IssuanceRequest, PolicyEngine, StaticPolicy};
use webpki::{
    anchor_from_trusted_cert, CertRevocationList, EndEntityCert, ExpirationPolicy, KeyUsage,
    OwnedCertRevocationList, RevocationCheckDepth, RevocationOptionsBuilder, UnknownStatusPolicy,
};
use x509_cert::{
    attr::Attributes,
    certificate::{Certificate, TbsCertificate, Version},
    der::{
        asn1::{BitString, ObjectIdentifier},
        Decode, Encode,
    },
    name::Name,
    request::{CertReq, CertReqInfo},
    serial_number::SerialNumber as X509Serial,
    spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned},
    time::Validity,
};

const ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const HOUR: u64 = 3600;

#[derive(Default)]
struct MemoryJournal {
    intents: Vec<String>,
}

impl CrlJournal for MemoryJournal {
    fn record_intent(&mut self, plan: &CrlPlan<'_>, _tbs: &[u8; 32]) -> Result<(), CrlError> {
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
        _tbs: &[u8; 32],
        _crl: &[u8; 32],
        _der: &[u8],
    ) -> Result<(), CrlError> {
        Ok(())
    }
}

fn ecdsa_sha256() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: ECDSA_WITH_SHA256,
        parameters: None,
    }
}

fn serial(byte: u8) -> SerialNumber {
    SerialNumber::from_positive_der_content(&[byte]).expect("serial")
}

/// A PKCS#10 request for `cn` signed by a key this test holds.
fn request(key: &EphemeralP256Signer, cn: &str) -> Vec<u8> {
    let spki = SubjectPublicKeyInfoOwned::from_der(
        &key.public_key_spki_der(key.key_ref()).expect("public key"),
    )
    .expect("SPKI");
    let info = CertReqInfo {
        version: x509_cert::request::Version::V1,
        subject: cn.parse::<Name>().expect("name"),
        public_key: spki,
        attributes: Attributes::new(),
    };
    let signature = key
        .sign(
            key.key_ref(),
            SignatureAlgorithm::EcdsaP256Sha256,
            &info.to_der().expect("info"),
        )
        .expect("sign");
    CertReq {
        info,
        algorithm: ecdsa_sha256(),
        signature: BitString::from_bytes(&signature).expect("signature"),
    }
    .to_der()
    .expect("request")
}

/// Signs `tbs` with `key`: only for certificates the platform would never
/// issue (the negative cases).
fn sign(tbs: TbsCertificate, key: &EphemeralP256Signer) -> Vec<u8> {
    let signature = key
        .sign(
            key.key_ref(),
            SignatureAlgorithm::EcdsaP256Sha256,
            &tbs.to_der().expect("tbs"),
        )
        .expect("sign");
    Certificate {
        tbs_certificate: tbs,
        signature_algorithm: ecdsa_sha256(),
        signature: BitString::from_bytes(&signature).expect("signature"),
    }
    .to_der()
    .expect("certificate")
}

fn unix(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH).expect("time").as_secs()
}

struct Lab {
    ca: EphemeralLabCa,
    other: EphemeralLabCa,
    /// The key behind `leaves[0]`; the others use the shared fixture request.
    leaf_key: EphemeralP256Signer,
    leaves: Vec<Vec<u8>>,
    now: u64,
}

impl Lab {
    fn new() -> Self {
        let policy = StaticPolicy {
            profile_id: "lab-server".into(),
            policy_version: "v1".into(),
            allowed_actors: vec!["lab-issuer".into()],
            allowed_dns_zones: vec!["lab.invalid".into()],
            allowed_ca_signature_algorithms: vec![SignatureAlgorithm::EcdsaP256Sha256],
            max_validity_days: 3,
            max_dns_sans: 2,
        };
        let sans = ["api.lab.invalid"];
        let decision = policy
            .authorize(
                &AuthenticatedPrincipal {
                    subject_id: "lab-issuer",
                },
                &IssuanceRequest {
                    profile_id: "lab-server",
                    subject_common_name: "api.lab.invalid",
                    dns_sans: &sans,
                    validity_days: 1,
                    ca_signature_algorithm: SignatureAlgorithm::EcdsaP256Sha256,
                },
            )
            .expect("policy");
        let binding = ApprovedPolicyBinding::new("1.3.6.1.4.1.55555.1.1", "lab-cp-v1", [9u8; 32])
            .expect("binding");
        let mut ca = EphemeralLabCa::new("Sovereign Trust Lab Root").expect("lab CA");
        // Same name, another key: a look-alike issuer.
        let other = EphemeralLabCa::new("Sovereign Trust Lab Root").expect("other CA");
        let leaf_key = EphemeralP256Signer::generate("path-validation-leaf").expect("key");
        let own = verify_pkcs10_p256(&request(&leaf_key, "CN=api.lab.invalid"), "api.lab.invalid")
            .expect("own request");
        let fixture = <CertReq as x509_cert::der::DecodePem>::from_pem(include_str!(
            "fixtures/ecdsa-p256-request.pem"
        ))
        .expect("fixture PEM");
        let shared = verify_pkcs10_p256(&fixture.to_der().expect("fixture"), "api.lab.invalid")
            .expect("fixture request");
        let mut leaves = Vec::new();
        for (n, csr) in [(1u8, &own), (2, &shared), (3, &shared)] {
            let leaf = ca
                .issue_leaf(csr, &decision, &serial(n), &binding)
                .expect("issue");
            leaves.push(leaf.to_der().expect("leaf"));
        }
        Self {
            ca,
            other,
            leaf_key,
            leaves,
            now: unix(SystemTime::now()),
        }
    }

    fn root(&self) -> Vec<u8> {
        self.ca.root_certificate().to_der().expect("root")
    }

    /// A CRL from the platform pipeline (`crl_once`: intent, one signature,
    /// independent verification) of `ca`, valid `validity` seconds.
    fn crl(
        ca: &mut EphemeralLabCa,
        number: u64,
        entries: &[(u8, RevocationReason)],
        this: u64,
        validity: u64,
    ) -> Vec<u8> {
        let entries = entries
            .iter()
            .map(|(n, reason)| CrlEntry {
                serial: serial(*n),
                revoked_at_unix: this as i64,
                reason: *reason,
                invalidity_at_unix: None,
            })
            .collect();
        let reservation = CrlReservation::new(
            "lab-root",
            number,
            this as i64,
            (this + validity) as i64,
            entries,
            None,
        )
        .expect("reservation");
        let root = ca.root_certificate().clone();
        let key_ref = ca.lab_signer_key_ref().to_owned();
        let operation = format!("path-crl-{number}");
        let plan = CrlPlan {
            reservation: &reservation,
            issuer: &root,
            signer_key_ref: &key_ref,
            operation_ref: &operation,
        };
        crl_once(
            &mut MemoryJournal::default(),
            ca,
            &LabCrlAssembler,
            &LabCrlVerifier::new(root.clone()),
            &plan,
        )
        .expect("CRL")
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Expect {
    Valid,
    Invalid,
}

#[derive(Clone, Copy)]
enum Usage {
    ServerAuth,
    ClientAuth,
}

struct Case {
    name: &'static str,
    expect: Expect,
    leaf: &'static str,
    chain: Vec<&'static str>,
    anchor: &'static str,
    crls: Vec<&'static str>,
    at: u64,
    usage: Usage,
    host: Option<&'static str>,
}

/// The artifacts by name, and the cases over them.
fn suite(lab: &mut Lab) -> (Vec<(&'static str, Vec<u8>)>, Vec<Case>) {
    let now = lab.now;
    let root = lab.root();
    let other_root = lab.other.root_certificate().to_der().expect("other root");
    let leaf = |i: usize| lab.leaves[i].clone();
    let not_before = unix(
        Certificate::from_der(&lab.leaves[0])
            .expect("leaf")
            .tbs_certificate
            .validity
            .not_before
            .to_system_time(),
    );
    let not_after = unix(
        Certificate::from_der(&lab.leaves[0])
            .expect("leaf")
            .tbs_certificate
            .validity
            .not_after
            .to_system_time(),
    );

    // Altered copies of leaf1: one signature byte, then one byte of the
    // signed SAN ("api" -> "apj"); both keep a well-formed encoding.
    let mut bad_signature = leaf(0);
    let last = bad_signature.len() - 1;
    bad_signature[last] ^= 0x01;
    let mut bad_tbs = leaf(0);
    let at = bad_tbs
        .windows(15)
        .position(|w| w == b"api.lab.invalid")
        .expect("SAN in leaf");
    bad_tbs[at + 2] = b'j';

    // A certificate signed with leaf1's key, as if leaf1 were a CA
    // (6.1.4 (k): leaf1 has cA false; the root's pathLenConstraint is 0).
    // CRLs start at `now`: thisUpdate may not precede the issuer's notBefore.
    let parent = Certificate::from_der(&lab.leaves[0]).expect("leaf");
    let child_key = EphemeralP256Signer::generate("path-validation-child").expect("key");
    let child_spki = SubjectPublicKeyInfoOwned::from_der(
        &child_key
            .public_key_spki_der(child_key.key_ref())
            .expect("public key"),
    )
    .expect("SPKI");
    // leaf1's own extensions, with the key identifiers of this link (AKI =
    // leaf1's key), so validators look for leaf1 as the issuer.
    let mut child_extensions: Vec<_> = parent
        .tbs_certificate
        .extensions
        .clone()
        .unwrap_or_default()
        .into_iter()
        .filter(|e| !matches!(e.extn_id.to_string().as_str(), "2.5.29.35" | "2.5.29.14"))
        .collect();
    let leaf1_key_id =
        x509_extensions::key_identifier(&parent.tbs_certificate.subject_public_key_info)
            .expect("leaf1 key id");
    child_extensions.push(x509_extensions::authority_key_identifier(&leaf1_key_id).expect("AKI"));
    child_extensions.push(
        x509_extensions::subject_key_identifier(
            &x509_extensions::key_identifier(&child_spki).expect("child key id"),
        )
        .expect("SKI"),
    );
    let child = sign(
        TbsCertificate {
            version: Version::V3,
            serial_number: X509Serial::new(&[0x77]).expect("serial"),
            signature: ecdsa_sha256(),
            issuer: parent.tbs_certificate.subject.clone(),
            validity: Validity::from_now(Duration::from_secs(12 * HOUR)).expect("validity"),
            subject: "CN=evil.lab.invalid".parse().expect("name"),
            subject_public_key_info: child_spki,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: Some(child_extensions),
        },
        &lab.leaf_key,
    );

    let crl_revoked = Lab::crl(
        &mut lab.ca,
        1,
        &[
            (1, RevocationReason::KeyCompromise),
            (2, RevocationReason::CertificateHold),
        ],
        now,
        7 * 24 * HOUR,
    );
    let crl_released = Lab::crl(
        &mut lab.ca,
        2,
        &[(1, RevocationReason::KeyCompromise)],
        now,
        7 * 24 * HOUR,
    );
    let crl_short = Lab::crl(&mut lab.ca, 3, &[], now, HOUR);
    let crl_other = Lab::crl(&mut lab.other, 1, &[], now, 7 * 24 * HOUR);

    let artifacts = vec![
        ("root", root),
        ("other_root", other_root),
        ("leaf1", leaf(0)),
        ("leaf2", leaf(1)),
        ("leaf3", leaf(2)),
        ("leaf1_bad_signature", bad_signature),
        ("leaf1_bad_tbs", bad_tbs),
        ("child_of_leaf1", child),
        ("crl_revoked", crl_revoked),
        ("crl_released", crl_released),
        ("crl_short", crl_short),
        ("crl_other_key", crl_other),
    ];
    let case = |name, expect, leaf, anchor, crls: Vec<&'static str>, at, usage, host| Case {
        name,
        expect,
        leaf,
        chain: vec![],
        anchor,
        crls,
        at,
        usage,
        host,
    };
    use Expect::*;
    use Usage::*;
    let mut cases = vec![
        case(
            "valid_leaf",
            Valid,
            "leaf1",
            "root",
            vec![],
            now,
            ServerAuth,
            Some("api.lab.invalid"),
        ),
        case(
            "before_not_before",
            Invalid,
            "leaf1",
            "root",
            vec![],
            not_before - HOUR,
            ServerAuth,
            None,
        ),
        case(
            "after_not_after",
            Invalid,
            "leaf1",
            "root",
            vec![],
            not_after + HOUR,
            ServerAuth,
            None,
        ),
        case(
            "same_name_other_key_anchor",
            Invalid,
            "leaf1",
            "other_root",
            vec![],
            now,
            ServerAuth,
            None,
        ),
        case(
            "altered_signature",
            Invalid,
            "leaf1_bad_signature",
            "root",
            vec![],
            now,
            ServerAuth,
            None,
        ),
        case(
            "altered_signed_content",
            Invalid,
            "leaf1_bad_tbs",
            "root",
            vec![],
            now,
            ServerAuth,
            None,
        ),
        case(
            "wrong_host_name",
            Invalid,
            "leaf1",
            "root",
            vec![],
            now,
            ServerAuth,
            Some("other.lab.invalid"),
        ),
        case(
            "wrong_extended_key_usage",
            Invalid,
            "leaf1",
            "root",
            vec![],
            now,
            ClientAuth,
            None,
        ),
        case(
            "revoked_key_compromise",
            Invalid,
            "leaf1",
            "root",
            vec!["crl_revoked"],
            now,
            ServerAuth,
            None,
        ),
        case(
            "on_hold",
            Invalid,
            "leaf2",
            "root",
            vec!["crl_revoked"],
            now,
            ServerAuth,
            None,
        ),
        case(
            "not_listed",
            Valid,
            "leaf3",
            "root",
            vec!["crl_revoked"],
            now,
            ServerAuth,
            None,
        ),
        case(
            "hold_released",
            Valid,
            "leaf2",
            "root",
            vec!["crl_released"],
            now,
            ServerAuth,
            None,
        ),
        case(
            "still_revoked_on_next_crl",
            Invalid,
            "leaf1",
            "root",
            vec!["crl_released"],
            now,
            ServerAuth,
            None,
        ),
        case(
            "crl_within_next_update",
            Valid,
            "leaf3",
            "root",
            vec!["crl_short"],
            now,
            ServerAuth,
            None,
        ),
        case(
            "crl_past_next_update",
            Invalid,
            "leaf3",
            "root",
            vec!["crl_short"],
            now + 2 * HOUR,
            ServerAuth,
            None,
        ),
        case(
            "crl_signed_by_other_key",
            Invalid,
            "leaf3",
            "root",
            vec!["crl_other_key"],
            now,
            ServerAuth,
            None,
        ),
    ];
    cases.push(Case {
        name: "end_entity_used_as_ca",
        expect: Invalid,
        leaf: "child_of_leaf1",
        chain: vec!["leaf1"],
        anchor: "root",
        crls: vec![],
        at: now,
        usage: ServerAuth,
        host: None,
    });
    (artifacts, cases)
}

/// Why each invalid case must fail: the webpki error, and the OpenSSL
/// verify error text tests/rfc5280_path_validation.sh looks for. A case
/// rejected for another reason is a failure of the suite.
fn reasons(case: &str) -> (&'static str, &'static str) {
    match case {
        "before_not_before" => ("CertNotValidYet", "certificate is not yet valid"),
        "after_not_after" => ("CertExpired", "certificate has expired"),
        // OpenSSL matches the leaf's authority key identifier first, so it
        // finds no issuer; webpki matches by name and fails the signature.
        "same_name_other_key_anchor" => (
            "InvalidSignatureForPublicKey",
            "unable to get local issuer certificate",
        ),
        "altered_signature" | "altered_signed_content" => (
            "InvalidSignatureForPublicKey",
            "certificate signature failure",
        ),
        "wrong_host_name" => ("CertNotValidForName", "hostname mismatch"),
        "wrong_extended_key_usage" => ("RequiredEkuNotFound", "unsuitable certificate purpose"),
        "revoked_key_compromise" | "on_hold" | "still_revoked_on_next_crl" => {
            ("CertRevoked", "certificate revoked")
        }
        "crl_past_next_update" => ("CrlExpired", "CRL has expired"),
        // OpenSSL skips a CRL whose authority key identifier does not match
        // and then has no CRL for the issuer: status unknown, refused.
        "crl_signed_by_other_key" => (
            "InvalidCrlSignatureForPublicKey",
            "unable to get certificate CRL",
        ),
        "end_entity_used_as_ca" => ("EndEntityUsedAsCa", "invalid CA certificate"),
        _ => ("", ""),
    }
}

fn webpki_outcome(artifacts: &[(&str, Vec<u8>)], case: &Case) -> Result<(), String> {
    use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
    let get = |name: &str| {
        artifacts
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, der)| der.clone())
            .unwrap_or_else(|| panic!("no artifact {name}"))
    };
    let anchor_der = CertificateDer::from(get(case.anchor));
    let anchors = [anchor_from_trusted_cert(&anchor_der)
        .map_err(|e| format!("anchor: {e:?}"))?
        .to_owned()];
    let leaf_der = CertificateDer::from(get(case.leaf));
    let leaf = EndEntityCert::try_from(&leaf_der).map_err(|e| format!("parse: {e:?}"))?;
    let chain: Vec<CertificateDer<'static>> = case
        .chain
        .iter()
        .map(|name| CertificateDer::from(get(name)))
        .collect();
    let crls: Vec<CertRevocationList<'static>> = case
        .crls
        .iter()
        .map(|name| {
            OwnedCertRevocationList::from_der(&get(name))
                .map(CertRevocationList::from)
                .map_err(|e| format!("CRL {name}: {e:?}"))
        })
        .collect::<Result<_, _>>()?;
    let crl_refs: Vec<&CertRevocationList<'_>> = crls.iter().collect();
    let revocation = if crl_refs.is_empty() {
        None
    } else {
        Some(
            RevocationOptionsBuilder::new(&crl_refs)
                .map_err(|_| "no CRL".to_owned())?
                .with_depth(RevocationCheckDepth::EndEntity)
                .with_status_policy(UnknownStatusPolicy::Deny)
                .with_expiration_policy(ExpirationPolicy::Enforce)
                .build(),
        )
    };
    let usage = match case.usage {
        Usage::ServerAuth => KeyUsage::server_auth(),
        Usage::ClientAuth => KeyUsage::client_auth(),
    };
    leaf.verify_for_usage(
        &[webpki::ring::ECDSA_P256_SHA256],
        &anchors,
        &chain,
        UnixTime::since_unix_epoch(Duration::from_secs(case.at)),
        usage,
        revocation,
        None,
    )
    .map_err(|e| format!("{e:?}"))?;
    if let Some(host) = case.host {
        leaf.verify_is_valid_for_subject_name(
            &ServerName::try_from(host).map_err(|_| "host name".to_owned())?,
        )
        .map_err(|e| format!("{e:?}"))?;
    }
    Ok(())
}

#[test]
fn platform_artifacts_follow_rfc5280_path_validation() {
    let mut lab = Lab::new();
    let (artifacts, cases) = suite(&mut lab);
    let mut disagreements = Vec::new();
    for case in &cases {
        let outcome = webpki_outcome(&artifacts, case);
        eprintln!("{}: webpki {outcome:?}", case.name);
        let got = if outcome.is_ok() {
            Expect::Valid
        } else {
            Expect::Invalid
        };
        let (reason, _) = reasons(case.name);
        let right_reason = match &outcome {
            Ok(()) => reason.is_empty(),
            Err(error) => !reason.is_empty() && error.contains(reason),
        };
        if got != case.expect || !right_reason {
            disagreements.push(format!(
                "{}: expected {:?} ({reason}), webpki {outcome:?}",
                case.name, case.expect
            ));
        }
    }
    assert!(disagreements.is_empty(), "{disagreements:#?}");
    assert!(cases.len() >= 17);

    if let Ok(dir) = std::env::var("TRUST_PATH_VALIDATION_EXPORT_DIR") {
        let dir = PathBuf::from(dir);
        fs::create_dir_all(&dir).expect("export dir");
        for (name, der) in &artifacts {
            let ext = if name.starts_with("crl") {
                "crl"
            } else {
                "der"
            };
            fs::write(dir.join(format!("{name}.{ext}")), der).expect("write");
        }
        // case|expect|leaf|chain|anchor|crls|at|purpose|host|openssl reason
        let mut manifest = String::new();
        for case in &cases {
            let _ = writeln!(
                manifest,
                "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
                case.name,
                if case.expect == Expect::Valid {
                    "valid"
                } else {
                    "invalid"
                },
                case.leaf,
                case.chain.join(","),
                case.anchor,
                case.crls.join(","),
                case.at,
                match case.usage {
                    Usage::ServerAuth => "sslserver",
                    Usage::ClientAuth => "sslclient",
                },
                case.host.unwrap_or(""),
                reasons(case.name).1
            );
        }
        fs::write(dir.join("manifest"), manifest).expect("manifest");
    }
}
