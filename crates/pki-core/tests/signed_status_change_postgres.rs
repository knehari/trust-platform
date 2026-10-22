//! Lab-only PostgreSQL integration for signed status-change approvals
//! (migration 0029, ADR-0007 step 2). Officers' authenticators are simulated
//! with ephemeral P-256 lab keys producing real ES256 WebAuthn assertions.
//! Requires TRUST_CI_DATABASE_URL (a superuser login).
#![cfg(all(feature = "postgres-store", feature = "lab-software"))]

use postgres::{Client, NoTls};
use sha2::{Digest, Sha256};
use std::env;
use trust_pki_core::{
    lab_ca::EphemeralLabCa,
    officer_credential::{canonical_officer_key, CredentialChangeKind},
    revocation::{CertificateStatus, OfficerIdentity, RevocationReason, StatusAction},
    revocation_store::{
        AdminChange, AdminFamily, CredentialContent, EvidenceFamily, OfficerGrantAction,
        PgRevocationStore, RevocationStoreError, SignedStep,
    },
    serial::SerialNumber,
    webauthn::{challenge_text, Assertion, RelyingParty, WebAuthnError},
};
use trust_pki_crypto::{lab::EphemeralP256Signer, SignatureAlgorithm, SigningProvider};
use x509_cert::{der::Decode, spki::SubjectPublicKeyInfoOwned};

const ISSUER: &str = "https://idp.lab.invalid";
const RP: RelyingParty<'static> = RelyingParty {
    rp_id: "officer.lab.invalid",
    origin: "https://officer.lab.invalid",
};

fn database_url() -> Option<String> {
    match env::var("TRUST_CI_DATABASE_URL") {
        Ok(url) => Some(url),
        Err(_) => {
            assert_ne!(
                env::var("TRUST_REQUIRE_DATABASE").as_deref(),
                Ok("1"),
                "TRUST_CI_DATABASE_URL is required for PostgreSQL integration tests"
            );
            None
        }
    }
}

fn url_as(url: &str, role: &str) -> String {
    let separator = if url.contains('?') { '&' } else { '?' };
    format!("{url}{separator}options=-crole%3D{role}")
}

fn sqlstate(error: &RevocationStoreError) -> Option<String> {
    match error {
        RevocationStoreError::Database(e) => e.code().map(|c| c.code().to_owned()),
        _ => None,
    }
}

/// A simulated FIDO2 authenticator: one lab P-256 key and a counter.
struct Authenticator {
    signer: EphemeralP256Signer,
    counter: u32,
    flags: u8,
    origin: &'static str,
}

impl Authenticator {
    fn new() -> Self {
        Self {
            signer: EphemeralP256Signer::generate("officer-authenticator").unwrap(),
            counter: 0,
            flags: 0x05, // user present and verified
            origin: RP.origin,
        }
    }

    fn public_key(&self) -> Vec<u8> {
        let spki = self
            .signer
            .public_key_spki_der(self.signer.key_ref())
            .unwrap();
        SubjectPublicKeyInfoOwned::from_der(&spki)
            .unwrap()
            .subject_public_key
            .raw_bytes()
            .to_vec()
    }

    /// authenticatorData, clientDataJSON and the ES256 signature over
    /// `authenticatorData || SHA-256(clientDataJSON)` for `challenge`.
    fn sign(&mut self, challenge: &[u8; 32]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        self.counter += 1;
        let mut data = Sha256::digest(RP.rp_id.as_bytes()).to_vec();
        data.push(self.flags);
        data.extend_from_slice(&self.counter.to_be_bytes());
        let client = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"{}","crossOrigin":false}}"#,
            challenge_text(challenge),
            self.origin
        )
        .into_bytes();
        let mut signed = data.clone();
        signed.extend_from_slice(&Sha256::digest(&client));
        let signature = self
            .signer
            .sign(
                self.signer.key_ref(),
                SignatureAlgorithm::EcdsaP256Sha256,
                &signed,
            )
            .unwrap();
        (data, client, signature)
    }
}

struct Lab {
    url: String,
    ca_id: String,
    serial: SerialNumber,
    officer: PgRevocationStore,
    admin: PgRevocationStore,
    maker: Authenticator,
    checker: Authenticator,
    maker_credential: Vec<u8>,
    checker_credential: Vec<u8>,
}

const MAKER: OfficerIdentity<'static> = OfficerIdentity {
    issuer: ISSUER,
    subject: "maker",
};
const CHECKER: OfficerIdentity<'static> = OfficerIdentity {
    issuer: ISSUER,
    subject: "checker",
};
const ADMIN_A: OfficerIdentity<'static> = OfficerIdentity {
    issuer: ISSUER,
    subject: "admin-a",
};
const ADMIN_B: OfficerIdentity<'static> = OfficerIdentity {
    issuer: ISSUER,
    subject: "admin-b",
};

/// A CA with a registered issuer certificate, one issued certificate,
/// maker/checker grants, two CA admins and one enrolled credential each.
fn lab(url: &str) -> Lab {
    let mut owner = Client::connect(url, NoTls).unwrap();
    let ca_id: String = owner
        .query_one(
            "INSERT INTO ca(ca_id, display_name, policy_version)
             VALUES (gen_random_uuid(), 'Signed Approval CA', 'v1') RETURNING ca_id::text",
            &[],
        )
        .unwrap()
        .get(0);
    owner
        .batch_execute(&format!(
            "INSERT INTO ca_revocation_policy(ca_id, suspension_allowed) VALUES ('{ca_id}', true);
             INSERT INTO revocation_officer_grant(issuer, subject, ca_id)
                 VALUES ('{ISSUER}', 'maker', '{ca_id}'), ('{ISSUER}', 'checker', '{ca_id}');
             INSERT INTO ca_admin_grant(issuer, subject, ca_id)
                 VALUES ('{ISSUER}', 'admin-a', '{ca_id}'), ('{ISSUER}', 'admin-b', '{ca_id}');
             INSERT INTO certificate_request(request_id, ca_id, idempotency_key, csr_sha256,
                 requester_id, policy_version, state)
                 VALUES (gen_random_uuid(), '{ca_id}', 'signed-1', sha256('csr'::bytea),
                         'requester', 'v1', 'PUBLISHED');
             INSERT INTO serial_reservation(ca_id, serial_der_content, request_id)
                 SELECT '{ca_id}', '\\x01', request_id FROM certificate_request
                 WHERE ca_id = '{ca_id}';
             INSERT INTO certificate(ca_id, serial_der_content, request_id, fingerprint_sha256,
                 certificate_der, signed_at)
                 SELECT ca_id, serial_der_content, request_id, sha256('der'::bytea),
                        '\\x3003020101', now()
                 FROM serial_reservation WHERE ca_id = '{ca_id}';"
        ))
        .unwrap();
    let root = EphemeralLabCa::new("Sovereign Trust Lab Root")
        .unwrap()
        .root_certificate()
        .clone();
    PgRevocationStore::connect_lab(url)
        .unwrap()
        .register_ca_issuer(&ca_id, &root, "bootstrap")
        .unwrap();
    let mut admin = PgRevocationStore::connect_lab(&url_as(url, "trust_ca_admin")).unwrap();
    let (maker, checker) = (Authenticator::new(), Authenticator::new());
    let credential = |tag: u8| {
        let mut id = ca_id.replace('-', "").into_bytes();
        id.push(tag);
        id
    };
    let (maker_credential, checker_credential) = (credential(1), credential(2));
    for (id, officer, person, key) in [
        (
            &maker_credential,
            &MAKER,
            "person-maker",
            maker.public_key(),
        ),
        (
            &checker_credential,
            &CHECKER,
            "person-checker",
            checker.public_key(),
        ),
    ] {
        let content = CredentialContent {
            ca_id: &ca_id,
            credential_id: id,
            officer,
            person_id: person,
            public_key_sec1: &key,
        };
        let change = admin
            .propose_credential_enrollment(&content, &ADMIN_A)
            .unwrap();
        admin
            .approve_credential_change(&change, CredentialChangeKind::Enroll, &content, &ADMIN_B)
            .unwrap();
    }
    owner
        .execute(
            "UPDATE ca_revocation_policy SET signed_approvals_required = true
             WHERE ca_id = $1::text::uuid",
            &[&ca_id],
        )
        .unwrap();
    Lab {
        url: url.to_owned(),
        officer: PgRevocationStore::connect_lab(&url_as(url, "trust_revocation_officer_api"))
            .unwrap(),
        admin,
        ca_id,
        serial: SerialNumber::from_positive_der_content(&[0x01]).unwrap(),
        maker,
        checker,
        maker_credential,
        checker_credential,
    }
}

impl Lab {
    fn propose_challenge(&mut self) -> String {
        self.officer
            .issue_proposal_challenge(
                &self.ca_id,
                &self.serial,
                StatusAction::Revoke,
                Some(RevocationReason::KeyCompromise),
                None,
                &MAKER,
                120,
            )
            .unwrap()
    }

    fn submit(
        &mut self,
        challenge: &str,
        signer_is_maker: bool,
        signed_claim_of: Option<&str>,
    ) -> Result<String, RevocationStoreError> {
        let claim_challenge = signed_claim_of.unwrap_or(challenge);
        let digest = self
            .officer
            .signed_challenge(claim_challenge)
            .unwrap()
            .digest()
            .unwrap();
        let (authenticator, credential) = if signer_is_maker {
            (&mut self.maker, self.maker_credential.clone())
        } else {
            (&mut self.checker, self.checker_credential.clone())
        };
        let (data, client, signature) = authenticator.sign(&digest);
        self.officer.submit_signed(
            challenge,
            &credential,
            &Assertion {
                authenticator_data: &data,
                client_data_json: &client,
                signature_der: &signature,
            },
            &RP,
        )
    }

    fn signed_proposal(&mut self) -> String {
        let challenge = self.propose_challenge();
        self.submit(&challenge, true, None).unwrap()
    }
}

/// Signed maker-checker end to end; unsigned paths refused once the CA
/// requires signatures; challenges are single-use; the setting is one-way;
/// the stored evidence re-verifies offline.
#[test]
fn signed_double_control_end_to_end() {
    let Some(url) = database_url() else { return };
    let mut lab = lab(&url);
    let unsigned = lab
        .officer
        .propose(
            &lab.ca_id,
            &lab.serial,
            StatusAction::Revoke,
            Some(RevocationReason::KeyCompromise),
            None,
            &MAKER,
        )
        .unwrap_err();
    assert_eq!(sqlstate(&unsigned).as_deref(), Some("42501"));

    let change = lab.signed_proposal();
    let unsigned = lab
        .officer
        .approve(
            &change,
            &CHECKER,
            StatusAction::Revoke,
            Some(RevocationReason::KeyCompromise),
        )
        .unwrap_err();
    assert_eq!(sqlstate(&unsigned).as_deref(), Some("42501"));
    // The maker cannot ask to approve their own change.
    let own = lab
        .officer
        .issue_approval_challenge(&change, &MAKER, 120)
        .unwrap_err();
    assert_eq!(sqlstate(&own).as_deref(), Some("23514"));

    let challenge = lab
        .officer
        .issue_approval_challenge(&change, &CHECKER, 120)
        .unwrap();
    assert_eq!(lab.submit(&challenge, false, None).unwrap(), change);
    assert_eq!(
        lab.officer.status(&lab.ca_id, &lab.serial).unwrap(),
        CertificateStatus::Revoked
    );
    // The challenge is spent.
    assert!(matches!(
        lab.submit(&challenge, false, None).unwrap_err(),
        RevocationStoreError::SignedApprovalRefused
    ));
    lab.officer.reverify_signed_change(&change, &RP).unwrap();

    let mut owner = Client::connect(&lab.url, NoTls).unwrap();
    let off = owner
        .execute(
            "UPDATE ca_revocation_policy SET signed_approvals_required = false
             WHERE ca_id = $1::text::uuid",
            &[&lab.ca_id],
        )
        .unwrap_err();
    assert_eq!(off.code().map(|c| c.code()), Some("23514"));
}

/// Each assertion defect of ADR-0007's evidence list is refused.
#[test]
fn signed_approvals_refuse_bad_assertions() {
    let Some(url) = database_url() else { return };
    let mut lab = lab(&url);
    let change = lab.signed_proposal();
    let challenge = |lab: &mut Lab| {
        lab.officer
            .issue_approval_challenge(&change, &CHECKER, 120)
            .unwrap()
    };

    // A claim signed for another challenge (or change, CA, issuer).
    let (first, second) = (challenge(&mut lab), challenge(&mut lab));
    assert!(matches!(
        lab.submit(&first, false, Some(&second)).unwrap_err(),
        RevocationStoreError::InvalidAssertion(WebAuthnError::Challenge)
    ));
    // No user verification.
    lab.checker.flags = 0x01;
    assert!(matches!(
        lab.submit(&first, false, None).unwrap_err(),
        RevocationStoreError::InvalidAssertion(WebAuthnError::UserNotVerified)
    ));
    lab.checker.flags = 0x05;
    // Phishing origin.
    lab.checker.origin = "https://officer.lab.invalid.evil.invalid";
    assert!(matches!(
        lab.submit(&first, false, None).unwrap_err(),
        RevocationStoreError::InvalidAssertion(WebAuthnError::Origin)
    ));
    lab.checker.origin = RP.origin;
    // Another officer's credential (the maker's) on the checker's challenge.
    assert!(matches!(
        lab.submit(&first, true, None).unwrap_err(),
        RevocationStoreError::SignedApprovalRefused
    ));
    // Counter regression: a cloned authenticator replays an old count.
    lab.checker.counter = 10;
    lab.submit(&first, false, None).unwrap();
    assert_eq!(
        lab.officer.status(&lab.ca_id, &lab.serial).unwrap(),
        CertificateStatus::Revoked
    );
    let mut owner = Client::connect(&lab.url, NoTls).unwrap();
    owner
        .execute(
            "INSERT INTO certificate_request(request_id, ca_id, idempotency_key, csr_sha256,
                 requester_id, policy_version, state)
             VALUES (gen_random_uuid(), $1::text::uuid, 'signed-2', sha256('csr2'::bytea),
                     'requester', 'v1', 'PUBLISHED')",
            &[&lab.ca_id],
        )
        .unwrap();
    owner
        .batch_execute(&format!(
            "INSERT INTO serial_reservation(ca_id, serial_der_content, request_id)
                 SELECT ca_id, '\\x02', request_id FROM certificate_request
                 WHERE ca_id = '{0}' AND idempotency_key = 'signed-2';
             INSERT INTO certificate(ca_id, serial_der_content, request_id, fingerprint_sha256,
                 certificate_der, signed_at)
                 SELECT ca_id, serial_der_content, request_id, sha256('der2'::bytea),
                        '\\x3003020102', now()
                 FROM serial_reservation WHERE ca_id = '{0}' AND serial_der_content = '\\x02';",
            lab.ca_id
        ))
        .unwrap();
    lab.serial = SerialNumber::from_positive_der_content(&[0x02]).unwrap();
    let second_change = lab.signed_proposal();
    let next = challenge_for(&mut lab, &second_change);
    lab.checker.counter = 5; // the stored count is 11
    assert!(matches!(
        lab.submit(&next, false, None).unwrap_err(),
        RevocationStoreError::InvalidAssertion(WebAuthnError::CounterRegression)
    ));
    // Expired challenge (refused by the database clock).
    lab.checker.counter = 20;
    let short = lab
        .officer
        .issue_approval_challenge(&second_change, &CHECKER, 1)
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1200));
    assert_eq!(
        sqlstate(&lab.submit(&short, false, None).unwrap_err()).as_deref(),
        Some("23514")
    );
    // The maker's credential removed mid-flow voids the pending proposal.
    let maker_key = lab.maker.public_key();
    let removal = lab
        .admin
        .propose_credential_removal(&lab.ca_id, &lab.maker_credential, &MAKER, &ADMIN_A)
        .unwrap();
    let maker_credential = lab.maker_credential.clone();
    lab.admin
        .approve_credential_change(
            &removal,
            CredentialChangeKind::Remove,
            &CredentialContent {
                ca_id: &lab.ca_id,
                credential_id: &maker_credential,
                officer: &MAKER,
                person_id: "person-maker",
                public_key_sec1: &maker_key,
            },
            &ADMIN_B,
        )
        .unwrap();
    let voided = lab.submit(&next, false, None).unwrap_err();
    assert_eq!(sqlstate(&voided).as_deref(), Some("23514"), "{voided:?}");
    assert_eq!(
        lab.officer.status(&lab.ca_id, &lab.serial).unwrap(),
        CertificateStatus::Valid
    );
}

fn challenge_for(lab: &mut Lab, change: &str) -> String {
    lab.officer
        .issue_approval_challenge(change, &CHECKER, 120)
        .unwrap()
}

/// A forged assertion sent straight to the database function (bypassing the
/// Rust core) passes the database's own checks, which cannot verify ECDSA;
/// offline re-verification of the stored evidence exposes it. Other service
/// roles cannot call the function at all.
#[test]
fn forged_assertion_is_exposed_by_reverification() {
    let Some(url) = database_url() else { return };
    let mut lab = lab(&url);
    let change = lab.signed_proposal();
    let challenge = challenge_for(&mut lab, &change);
    let digest = lab
        .officer
        .signed_challenge(&challenge)
        .unwrap()
        .claim
        .digest();
    let (data, client, _) = lab.checker.sign(&digest);
    // A well-formed signature by another key over the same bytes.
    let (_, _, forged) = Authenticator::new().sign(&digest);

    let mut signer_role = Client::connect(&url_as(&url, "trust_crl_signer"), NoTls).unwrap();
    let denied = signer_role
        .query_one(
            "SELECT approve_signed_status_change($1::text::uuid, $2, $3, $4, $5)",
            &[&challenge, &lab.checker_credential, &data, &client, &forged],
        )
        .unwrap_err();
    assert_eq!(denied.code().map(|c| c.code()), Some("42501"));

    let mut direct = Client::connect(&url_as(&url, "trust_revocation_officer_api"), NoTls).unwrap();
    direct
        .query_one(
            "SELECT approve_signed_status_change($1::text::uuid, $2, $3, $4, $5)",
            &[&challenge, &lab.checker_credential, &data, &client, &forged],
        )
        .unwrap();
    assert!(matches!(
        lab.officer
            .reverify_signed_change(&change, &RP)
            .unwrap_err(),
        RevocationStoreError::InvalidAssertion(WebAuthnError::Signature)
    ));
}

/// ADR-0007 §6: one signed officer may put a certificate on hold as a
/// precaution when the CA's CPS allows suspension and the CA sets a
/// confirmation deadline. The hold is applied at once, re-verifies
/// offline with its single signature, and stays listed (overdue past the
/// deadline) until a dual-controlled revocation or release follows.
#[test]
fn precautionary_hold_by_one_signed_officer() {
    let Some(url) = database_url() else { return };
    let mut lab = lab(&url);
    let mut owner = Client::connect(&lab.url, NoTls).unwrap();
    let serial = lab.serial.clone();

    // Not enabled for the CA: refused before anything is signed.
    let disabled = lab
        .officer
        .issue_precaution_challenge(&lab.ca_id, &serial, &MAKER, 120)
        .unwrap_err();
    assert_eq!(sqlstate(&disabled).as_deref(), Some("23514"));
    // A deadline needs the CPS reference for suspension.
    let no_cps = owner
        .execute(
            "UPDATE ca_revocation_policy SET precautionary_hold_hours = 24
             WHERE ca_id = $1::text::uuid",
            &[&lab.ca_id],
        )
        .unwrap_err();
    assert_eq!(no_cps.code().map(|c| c.code()), Some("23514"));
    owner
        .execute(
            "UPDATE ca_revocation_policy
             SET suspension_cps_ref = 'CPS 4.9.13', precautionary_hold_hours = 24
             WHERE ca_id = $1::text::uuid",
            &[&lab.ca_id],
        )
        .unwrap();

    let challenge = lab
        .officer
        .issue_precaution_challenge(&lab.ca_id, &serial, &MAKER, 120)
        .unwrap();
    let claim = lab.officer.signed_challenge(&challenge).unwrap().claim;
    assert_eq!(claim.action, "PRECAUTIONARY_SUSPEND");
    // Another officer's key cannot answer the maker's challenge.
    assert!(matches!(
        lab.submit(&challenge, false, None).unwrap_err(),
        RevocationStoreError::SignedApprovalRefused
    ));
    let change = lab.submit(&challenge, true, None).unwrap();
    assert_eq!(
        lab.officer.status(&lab.ca_id, &serial).unwrap(),
        CertificateStatus::Suspended
    );
    assert!(matches!(
        lab.submit(&challenge, true, None).unwrap_err(),
        RevocationStoreError::SignedApprovalRefused
    ));
    lab.officer.reverify_signed_change(&change, &RP).unwrap();
    // A second precaution on a held certificate is refused at once.
    let again = lab
        .officer
        .issue_precaution_challenge(&lab.ca_id, &serial, &MAKER, 120)
        .unwrap_err();
    assert_eq!(sqlstate(&again).as_deref(), Some("23514"));

    let holds = lab.officer.precautionary_holds(&lab.ca_id).unwrap();
    assert_eq!(holds.len(), 1);
    assert_eq!(holds[0].change_id, change);
    assert!(!holds[0].overdue);
    let window = holds[0].confirm_by_unix - holds[0].held_at_unix;
    assert_eq!(window, 24 * 3600);

    // Past the deadline it is reported as overdue (the deadline is moved
    // back by a superuser here; nothing else can update a decided change).
    owner
        .batch_execute(&format!(
            "ALTER TABLE certificate_status_change DISABLE TRIGGER certificate_status_change_guard;
             UPDATE certificate_status_change
             SET confirm_by = decided_at + interval '1 microsecond'
             WHERE change_id = '{change}';
             ALTER TABLE certificate_status_change ENABLE TRIGGER certificate_status_change_guard"
        ))
        .unwrap();
    let holds = lab.officer.precautionary_holds(&lab.ca_id).unwrap();
    assert!(holds[0].overdue);
    let mut operator = PgRevocationStore::connect_lab(&url_as(&url, "trust_crl_operator")).unwrap();
    assert_eq!(operator.precautionary_holds(&lab.ca_id).unwrap().len(), 1);
    let report = operator.crl_housekeeping(&lab.ca_id, 3600, 3600).unwrap();
    assert_eq!(report.overdue_precautionary_holds, 1);
    assert!(report.needs_attention());

    // Confirmation is the ordinary signed double control: hold -> revoked.
    let definitive = lab.signed_proposal();
    // A lone maker signature of an ordinary proposal is not evidence.
    assert!(matches!(
        lab.officer.reverify_signed_change(&definitive, &RP),
        Err(RevocationStoreError::SignedApprovalRefused)
    ));
    let approval = lab
        .officer
        .issue_approval_challenge(&definitive, &CHECKER, 120)
        .unwrap();
    lab.submit(&approval, false, None).unwrap();
    assert_eq!(
        lab.officer.status(&lab.ca_id, &serial).unwrap(),
        CertificateStatus::Revoked
    );
    assert!(lab
        .officer
        .precautionary_holds(&lab.ca_id)
        .unwrap()
        .is_empty());
    lab.officer.reverify_signed_change(&change, &RP).unwrap();
    lab.officer
        .reverify_signed_change(&definitive, &RP)
        .unwrap();
    let audit: i64 = owner
        .query_one(
            "SELECT count(*) FROM audit_event
             WHERE event_type = 'certificate.status.precautionary_hold'
               AND decision LIKE '%change=' || $1 || '%'",
            &[&change],
        )
        .unwrap()
        .get(0);
    assert_eq!(audit, 1);
}

const THIRD: OfficerIdentity<'static> = OfficerIdentity {
    issuer: ISSUER,
    subject: "third",
};

fn admin_submit(
    store: &mut PgRevocationStore,
    authenticator: &mut Authenticator,
    credential_id: &[u8],
    challenge: &str,
    change: Option<&AdminChange<'_>>,
) -> Result<String, RevocationStoreError> {
    let digest = store.admin_challenge(challenge).unwrap().claim.digest();
    let (data, client, signature) = authenticator.sign(&digest);
    store.submit_signed_admin(
        challenge,
        credential_id,
        &Assertion {
            authenticator_data: &data,
            client_data_json: &client,
            signature_der: &signature,
        },
        &RP,
        change,
    )
}

/// ADR-0007 `trust-platform/ca-admin/v1` (migration 0037): once a CA
/// requires signed administration, officer grants and credential
/// enrolment need a maker and a checker CA admin signing the canonical
/// claim with distinct enrolled keys and persons; unsigned paths, content
/// substitution, another admin's key and self-approval are refused; the
/// evidence re-verifies offline.
#[test]
fn signed_ca_admin_changes() {
    let Some(url) = database_url() else { return };
    let mut lab = lab(&url);
    let ca = lab.ca_id.clone();
    let mut owner = Client::connect(&lab.url, NoTls).unwrap();
    let mut boot = PgRevocationStore::connect_lab(&lab.url).unwrap();
    let (mut admin_a, mut admin_b) = (Authenticator::new(), Authenticator::new());
    let credential = |tag: u8| {
        let mut id = ca.replace('-', "").into_bytes();
        id.push(tag);
        id
    };
    let (a_id, b_id) = (credential(3), credential(4));

    // DBA bootstrap; an officer's key or person cannot become an admin's.
    let reused_key = boot
        .enroll_admin_credential(
            &ca,
            &b_id,
            &ADMIN_B,
            "person-admin-b",
            &lab.maker.public_key(),
        )
        .unwrap_err();
    assert_eq!(sqlstate(&reused_key).as_deref(), Some("23514"));
    let reused_person = boot
        .enroll_admin_credential(&ca, &b_id, &ADMIN_B, "person-maker", &admin_b.public_key())
        .unwrap_err();
    assert_eq!(sqlstate(&reused_person).as_deref(), Some("23514"));
    boot.enroll_admin_credential(
        &ca,
        &a_id,
        &ADMIN_A,
        "person-admin-a",
        &admin_a.public_key(),
    )
    .unwrap();
    boot.enroll_admin_credential(
        &ca,
        &b_id,
        &ADMIN_B,
        "person-admin-b",
        &admin_b.public_key(),
    )
    .unwrap();
    // A service holding trust_ca_admin cannot bootstrap admin keys.
    let rogue = Authenticator::new();
    let denied = lab
        .admin
        .enroll_admin_credential(
            &ca,
            &credential(9),
            &ADMIN_A,
            "person-admin-a",
            &rogue.public_key(),
        )
        .unwrap_err();
    assert_eq!(sqlstate(&denied).as_deref(), Some("42501"));

    owner
        .execute(
            "UPDATE ca_revocation_policy SET signed_admin_required = true
             WHERE ca_id = $1::text::uuid",
            &[&ca],
        )
        .unwrap();
    let unsigned = lab
        .admin
        .propose_officer_grant(&ca, OfficerGrantAction::Grant, &THIRD, &ADMIN_A)
        .unwrap_err();
    assert_eq!(sqlstate(&unsigned).as_deref(), Some("42501"));

    // Signed officer grant: A proposes, B approves.
    let grant = AdminChange::Officer(OfficerGrantAction::Grant, &THIRD);
    let challenge = lab
        .admin
        .issue_admin_proposal_challenge(&ca, &grant, &ADMIN_A, 120)
        .unwrap();
    // The content handed over must be the content signed.
    let other = OfficerIdentity {
        issuer: ISSUER,
        subject: "someone-else",
    };
    let substituted = AdminChange::Officer(OfficerGrantAction::Grant, &other);
    assert!(matches!(
        admin_submit(
            &mut lab.admin,
            &mut admin_a,
            &a_id,
            &challenge,
            Some(&substituted)
        )
        .unwrap_err(),
        RevocationStoreError::SignedApprovalRefused
    ));
    // Bypassing the Rust check: the database compares the change it creates.
    {
        let digest = lab
            .admin
            .admin_challenge(&challenge)
            .unwrap()
            .claim
            .digest();
        let (data, client, signature) = admin_a.sign(&digest);
        let mut direct = Client::connect(&url_as(&url, "trust_ca_admin"), NoTls).unwrap();
        let error = direct
            .query_one(
                "SELECT propose_signed_admin_change($1::text::uuid, $2, $3, $4, $5,
                     NULL, NULL, $6, $7, NULL, NULL)",
                &[
                    &challenge,
                    &a_id,
                    &data,
                    &client,
                    &signature,
                    &ISSUER,
                    &"someone-else",
                ],
            )
            .unwrap_err();
        assert_eq!(error.code().map(|c| c.code()), Some("23514"));
        assert!(error
            .as_db_error()
            .is_some_and(|e| e.message().contains("differs from the signed content")));
    }
    let change = admin_submit(
        &mut lab.admin,
        &mut admin_a,
        &a_id,
        &challenge,
        Some(&grant),
    )
    .unwrap();
    // The maker cannot ask to approve; B's challenge refuses A's key.
    let own = lab
        .admin
        .issue_admin_approval_challenge(AdminFamily::CaAdmin, &change, &ADMIN_A, 120)
        .unwrap_err();
    assert_eq!(sqlstate(&own).as_deref(), Some("23514"));
    let approval = lab
        .admin
        .issue_admin_approval_challenge(AdminFamily::CaAdmin, &change, &ADMIN_B, 120)
        .unwrap();
    assert!(matches!(
        admin_submit(&mut lab.admin, &mut admin_a, &a_id, &approval, None).unwrap_err(),
        RevocationStoreError::SignedApprovalRefused
    ));
    // Unsigned approval of the signed proposal is refused too.
    let unsigned = lab
        .admin
        .approve_officer_grant(&change, OfficerGrantAction::Grant, &THIRD, &ADMIN_B)
        .unwrap_err();
    assert_eq!(sqlstate(&unsigned).as_deref(), Some("42501"));
    assert_eq!(
        admin_submit(&mut lab.admin, &mut admin_b, &b_id, &approval, None).unwrap(),
        change
    );
    assert!(matches!(
        admin_submit(&mut lab.admin, &mut admin_b, &b_id, &approval, None).unwrap_err(),
        RevocationStoreError::SignedApprovalRefused
    ));
    let granted: i64 = owner
        .query_one(
            "SELECT count(*) FROM revocation_officer_grant
             WHERE ca_id = $1::text::uuid AND subject = 'third'",
            &[&ca],
        )
        .unwrap()
        .get(0);
    assert_eq!(granted, 1);
    lab.admin
        .reverify_admin_change(AdminFamily::CaAdmin, &change, &RP)
        .unwrap();

    // Signed credential enrolment for the new officer.
    let third = Authenticator::new();
    let third_key = third.public_key();
    let third_id = credential(5);
    let content = CredentialContent {
        ca_id: &ca,
        credential_id: &third_id,
        officer: &THIRD,
        person_id: "person-third",
        public_key_sec1: &third_key,
    };
    let enroll = AdminChange::Credential(CredentialChangeKind::Enroll, &content);
    let challenge = lab
        .admin
        .issue_admin_proposal_challenge(&ca, &enroll, &ADMIN_B, 120)
        .unwrap();
    let change = admin_submit(
        &mut lab.admin,
        &mut admin_b,
        &b_id,
        &challenge,
        Some(&enroll),
    )
    .unwrap();
    let approval = lab
        .admin
        .issue_admin_approval_challenge(AdminFamily::Credential, &change, &ADMIN_A, 120)
        .unwrap();
    admin_submit(&mut lab.admin, &mut admin_a, &a_id, &approval, None).unwrap();
    let active: i64 = owner
        .query_one(
            "SELECT count(*) FROM officer_credential
             WHERE credential_id = $1 AND status = 'ACTIVE'",
            &[&third_id],
        )
        .unwrap()
        .get(0);
    assert_eq!(active, 1);
    lab.admin
        .reverify_admin_change(AdminFamily::Credential, &change, &RP)
        .unwrap();
    // Evidence for one family is not evidence for the other.
    assert!(lab
        .admin
        .reverify_admin_change(AdminFamily::CaAdmin, &change, &RP)
        .is_err());

    let off = owner
        .execute(
            "UPDATE ca_revocation_policy SET signed_admin_required = false
             WHERE ca_id = $1::text::uuid",
            &[&ca],
        )
        .unwrap_err();
    assert_eq!(off.code().map(|c| c.code()), Some("23514"));
}

/// A second issued certificate (serial 0x02) on the lab CA.
fn second_certificate(owner: &mut Client, ca: &str) {
    owner
        .batch_execute(&format!(
            "INSERT INTO certificate_request(request_id, ca_id, idempotency_key, csr_sha256,
                 requester_id, policy_version, state)
                 VALUES (gen_random_uuid(), '{ca}', 'signed-2', sha256('csr2'::bytea),
                         'requester', 'v1', 'PUBLISHED');
             INSERT INTO serial_reservation(ca_id, serial_der_content, request_id)
                 SELECT '{ca}', '\\x02', request_id FROM certificate_request
                 WHERE ca_id = '{ca}' AND idempotency_key = 'signed-2';
             INSERT INTO certificate(ca_id, serial_der_content, request_id, fingerprint_sha256,
                 certificate_der, signed_at)
                 SELECT ca_id, serial_der_content, request_id, sha256('der2'::bytea),
                        '\\x3003020102', now()
                 FROM serial_reservation WHERE ca_id = '{ca}' AND serial_der_content = '\\x02';"
        ))
        .unwrap();
}

/// One officer cannot hold more certificates as a precaution than the CA's
/// limit while those holds await confirmation (migration 0038); another
/// officer still can, and a confirmed hold frees the slot.
#[test]
fn precautionary_holds_are_capped_per_officer() {
    let Some(url) = database_url() else { return };
    let mut lab = lab(&url);
    let ca = lab.ca_id.clone();
    let mut owner = Client::connect(&lab.url, NoTls).unwrap();
    second_certificate(&mut owner, &ca);
    owner
        .batch_execute(&format!(
            "UPDATE ca_revocation_policy
                 SET suspension_cps_ref = 'CPS 4.9.13', precautionary_hold_hours = 24,
                     precautionary_hold_limit = 1
                 WHERE ca_id = '{ca}';"
        ))
        .unwrap();
    let first = SerialNumber::from_positive_der_content(&[0x01]).unwrap();
    let second = SerialNumber::from_positive_der_content(&[0x02]).unwrap();
    let hold = |lab: &mut Lab, serial: &SerialNumber, maker: bool| {
        let officer = if maker { &MAKER } else { &CHECKER };
        let challenge = lab
            .officer
            .issue_precaution_challenge(&ca, serial, officer, 120)
            .unwrap();
        lab.submit(&challenge, maker, None)
    };
    hold(&mut lab, &first, true).unwrap();
    let capped = hold(&mut lab, &second, true).unwrap_err();
    assert_eq!(sqlstate(&capped).as_deref(), Some("23514"));
    assert_eq!(
        lab.officer.status(&ca, &second).unwrap(),
        CertificateStatus::Valid
    );
    // Confirming the first hold (dual-controlled revocation) frees the slot.
    let definitive = lab.signed_proposal();
    let approval = lab
        .officer
        .issue_approval_challenge(&definitive, &CHECKER, 120)
        .unwrap();
    lab.submit(&approval, false, None).unwrap();
    hold(&mut lab, &second, true).unwrap();
    assert_eq!(
        lab.officer.status(&ca, &second).unwrap(),
        CertificateStatus::Suspended
    );
    let limit = owner
        .execute(
            "UPDATE ca_revocation_policy SET precautionary_hold_limit = 0
             WHERE ca_id = $1::text::uuid",
            &[&ca],
        )
        .unwrap_err();
    assert_eq!(limit.code().map(|c| c.code()), Some("23514"));
}

/// Once a CA requires signatures, a proposal is closed only with a signed
/// rejection (a checker, distinct key and person) or a signed withdrawal
/// (the maker), each with its own domain-separated claim (migration 0039);
/// the unsigned paths are refused and the evidence re-verifies offline.
#[test]
fn signed_rejection_and_withdrawal() {
    let Some(url) = database_url() else { return };
    let mut lab = lab(&url);

    let change = lab.signed_proposal();
    let unsigned = lab.officer.reject(&change, &CHECKER).unwrap_err();
    assert_eq!(sqlstate(&unsigned).as_deref(), Some("42501"));
    // The maker cannot reject their own proposal; the checker cannot
    // withdraw it.
    let own = lab
        .officer
        .issue_close_challenge(&change, &MAKER, SignedStep::Reject, 120)
        .unwrap_err();
    assert_eq!(sqlstate(&own).as_deref(), Some("23514"));
    let other = lab
        .officer
        .issue_close_challenge(&change, &CHECKER, SignedStep::Withdraw, 120)
        .unwrap_err();
    assert_eq!(sqlstate(&other).as_deref(), Some("23514"));
    let reject = lab
        .officer
        .issue_close_challenge(&change, &CHECKER, SignedStep::Reject, 120)
        .unwrap();
    // An approval-style signature over the plain claim does not verify.
    let approval = lab
        .officer
        .issue_approval_challenge(&change, &CHECKER, 120)
        .unwrap();
    assert!(matches!(
        lab.submit(&reject, false, Some(&approval)).unwrap_err(),
        RevocationStoreError::InvalidAssertion(WebAuthnError::Challenge)
    ));
    assert_eq!(lab.submit(&reject, false, None).unwrap(), change);
    assert!(matches!(
        lab.submit(&reject, false, None).unwrap_err(),
        RevocationStoreError::SignedApprovalRefused
    ));
    assert_eq!(
        lab.officer.status(&lab.ca_id, &lab.serial).unwrap(),
        CertificateStatus::Valid
    );
    lab.officer.reverify_signed_change(&change, &RP).unwrap();
    // The approval challenge issued before the rejection is now useless.
    assert_eq!(
        sqlstate(&lab.submit(&approval, false, None).unwrap_err()).as_deref(),
        Some("23514")
    );

    let change = lab.signed_proposal();
    let unsigned = lab.officer.withdraw(&change, &MAKER).unwrap_err();
    assert_eq!(sqlstate(&unsigned).as_deref(), Some("42501"));
    let withdraw = lab
        .officer
        .issue_close_challenge(&change, &MAKER, SignedStep::Withdraw, 120)
        .unwrap();
    assert_eq!(lab.submit(&withdraw, true, None).unwrap(), change);
    lab.officer.reverify_signed_change(&change, &RP).unwrap();
    let mut owner = Client::connect(&lab.url, NoTls).unwrap();
    let statuses: Vec<String> = owner
        .query(
            "SELECT status FROM certificate_status_change
             WHERE ca_id = $1::text::uuid ORDER BY proposed_at",
            &[&lab.ca_id],
        )
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect();
    assert_eq!(statuses, ["REJECTED", "WITHDRAWN"]);
}

const ADMIN_C: OfficerIdentity<'static> = OfficerIdentity {
    issuer: ISSUER,
    subject: "admin-c",
};

/// ADR-0007 §5 for CA admins (migration 0040): once a CA requires signed
/// administration, admin keys are enrolled and removed only by a signed
/// maker-checker change between two other admins; the DBA bootstrap is
/// closed; nobody changes their own key; a removed key no longer signs.
#[test]
fn admin_keys_enrolled_and_removed_under_dual_control() {
    let Some(url) = database_url() else { return };
    let mut lab = lab(&url);
    let ca = lab.ca_id.clone();
    let mut owner = Client::connect(&lab.url, NoTls).unwrap();
    let mut boot = PgRevocationStore::connect_lab(&lab.url).unwrap();
    let (mut admin_a, mut admin_b, mut admin_c) = (
        Authenticator::new(),
        Authenticator::new(),
        Authenticator::new(),
    );
    let credential = |tag: u8| {
        let mut id = ca.replace('-', "").into_bytes();
        id.push(tag);
        id
    };
    let (a_id, b_id, c_id) = (credential(3), credential(4), credential(6));
    let a_key = admin_a.public_key();
    let c_key = admin_c.public_key();
    boot.enroll_admin_credential(&ca, &a_id, &ADMIN_A, "person-admin-a", &a_key)
        .unwrap();
    boot.enroll_admin_credential(
        &ca,
        &b_id,
        &ADMIN_B,
        "person-admin-b",
        &admin_b.public_key(),
    )
    .unwrap();
    owner
        .batch_execute(&format!(
            "INSERT INTO ca_admin_grant(issuer, subject, ca_id) VALUES ('{ISSUER}', 'admin-c', '{ca}');
             UPDATE ca_revocation_policy SET signed_admin_required = true WHERE ca_id = '{ca}'"
        ))
        .unwrap();
    // The DBA bootstrap is closed once signed administration is required.
    let closed = boot
        .enroll_admin_credential(&ca, &c_id, &ADMIN_C, "person-admin-c", &c_key)
        .unwrap_err();
    assert_eq!(sqlstate(&closed).as_deref(), Some("42501"));

    // An admin cannot enrol a key for themselves.
    let spare = Authenticator::new().public_key();
    let own_id = credential(7);
    let own = CredentialContent {
        ca_id: &ca,
        credential_id: &own_id,
        officer: &ADMIN_A,
        person_id: "person-admin-a",
        public_key_sec1: &spare,
    };
    let own = AdminChange::AdminCredential(CredentialChangeKind::Enroll, &own);
    let challenge = lab
        .admin
        .issue_admin_proposal_challenge(&ca, &own, &ADMIN_A, 120)
        .unwrap();
    let refused =
        admin_submit(&mut lab.admin, &mut admin_a, &a_id, &challenge, Some(&own)).unwrap_err();
    assert_eq!(sqlstate(&refused).as_deref(), Some("23514"));

    // A proposes C's key, B approves.
    let c_content = CredentialContent {
        ca_id: &ca,
        credential_id: &c_id,
        officer: &ADMIN_C,
        person_id: "person-admin-c",
        public_key_sec1: &c_key,
    };
    let enroll = AdminChange::AdminCredential(CredentialChangeKind::Enroll, &c_content);
    let challenge = lab
        .admin
        .issue_admin_proposal_challenge(&ca, &enroll, &ADMIN_A, 120)
        .unwrap();
    let change = admin_submit(
        &mut lab.admin,
        &mut admin_a,
        &a_id,
        &challenge,
        Some(&enroll),
    )
    .unwrap();
    let approval = lab
        .admin
        .issue_admin_approval_challenge(AdminFamily::AdminCredential, &change, &ADMIN_B, 120)
        .unwrap();
    admin_submit(&mut lab.admin, &mut admin_b, &b_id, &approval, None).unwrap();
    lab.admin
        .reverify_admin_change(AdminFamily::AdminCredential, &change, &RP)
        .unwrap();

    // C (newly enrolled) proposes removing A's key, B approves.
    let a_content = CredentialContent {
        ca_id: &ca,
        credential_id: &a_id,
        officer: &ADMIN_A,
        person_id: "person-admin-a",
        public_key_sec1: &a_key,
    };
    let remove = AdminChange::AdminCredential(CredentialChangeKind::Remove, &a_content);
    let challenge = lab
        .admin
        .issue_admin_proposal_challenge(&ca, &remove, &ADMIN_C, 120)
        .unwrap();
    let change = admin_submit(
        &mut lab.admin,
        &mut admin_c,
        &c_id,
        &challenge,
        Some(&remove),
    )
    .unwrap();
    let approval = lab
        .admin
        .issue_admin_approval_challenge(AdminFamily::AdminCredential, &change, &ADMIN_B, 120)
        .unwrap();
    admin_submit(&mut lab.admin, &mut admin_b, &b_id, &approval, None).unwrap();
    let statuses: Vec<(String, String)> = owner
        .query(
            "SELECT subject, status FROM ca_admin_credential
             WHERE ca_id = $1::text::uuid ORDER BY subject",
            &[&ca],
        )
        .unwrap()
        .iter()
        .map(|row| (row.get(0), row.get(1)))
        .collect();
    assert_eq!(
        statuses,
        [
            ("admin-a".to_owned(), "REMOVED".to_owned()),
            ("admin-b".to_owned(), "ACTIVE".to_owned()),
            ("admin-c".to_owned(), "ACTIVE".to_owned()),
        ]
    );
    // A's removed key no longer signs anything.
    let grant = AdminChange::Officer(OfficerGrantAction::Grant, &THIRD);
    let challenge = lab
        .admin
        .issue_admin_proposal_challenge(&ca, &grant, &ADMIN_A, 120)
        .unwrap();
    assert!(matches!(
        admin_submit(
            &mut lab.admin,
            &mut admin_a,
            &a_id,
            &challenge,
            Some(&grant)
        )
        .unwrap_err(),
        RevocationStoreError::SignedApprovalRefused
    ));
}

/// Migration 0041: the audit role re-verifies every signed change of a CA
/// offline, without officer or admin rights, and a signature altered in the
/// database is reported for that change alone.
#[test]
fn auditor_reverifies_every_signed_change() {
    let Some(url) = database_url() else { return };
    let mut lab = lab(&url);
    let rejected = lab.signed_proposal();
    let reject = lab
        .officer
        .issue_close_challenge(&rejected, &CHECKER, SignedStep::Reject, 120)
        .unwrap();
    lab.submit(&reject, false, None).unwrap();
    let approved = lab.signed_proposal();
    let approval = lab
        .officer
        .issue_approval_challenge(&approved, &CHECKER, 120)
        .unwrap();
    lab.submit(&approval, false, None).unwrap();

    // An open proposal (maker signature only) on a second certificate.
    let mut owner = Client::connect(&lab.url, NoTls).unwrap();
    second_certificate(&mut owner, &lab.ca_id);
    let challenge = lab
        .officer
        .issue_proposal_challenge(
            &lab.ca_id,
            &SerialNumber::from_positive_der_content(&[0x02]).unwrap(),
            StatusAction::Revoke,
            Some(RevocationReason::KeyCompromise),
            None,
            &MAKER,
            120,
        )
        .unwrap();
    let pending = lab.submit(&challenge, true, None).unwrap();

    let mut auditor =
        PgRevocationStore::connect_lab(&url_as(&url, "trust_audit_verifier")).unwrap();
    let findings = auditor.audit_signed_evidence(&lab.ca_id, &RP).unwrap();
    let mut ids: Vec<&str> = findings.iter().map(|f| f.change_id.as_str()).collect();
    ids.sort_unstable();
    let mut expected = [rejected.as_str(), approved.as_str(), pending.as_str()];
    expected.sort_unstable();
    assert_eq!(ids, expected);
    assert!(findings.iter().all(|f| f.result.is_ok()), "{findings:?}");
    // The auditor cannot act.
    let denied = auditor
        .issue_approval_challenge(&approved, &CHECKER, 120)
        .unwrap_err();
    assert_eq!(sqlstate(&denied).as_deref(), Some("42501"));

    // A superuser alters the checker's stored signature of one change.
    owner
        .batch_execute(&format!(
            "ALTER TABLE status_change_signature DISABLE TRIGGER status_change_signature_append_only;
             UPDATE status_change_signature
                SET signature_der = set_byte(signature_der, octet_length(signature_der) - 1,
                        get_byte(signature_der, octet_length(signature_der) - 1) # 1)
              WHERE change_id = '{approved}' AND role = 'CHECKER';
             ALTER TABLE status_change_signature ENABLE TRIGGER status_change_signature_append_only"
        ))
        .unwrap();
    let findings = auditor.audit_signed_evidence(&lab.ca_id, &RP).unwrap();
    for finding in &findings {
        assert_eq!(finding.family, EvidenceFamily::StatusChange);
        if finding.change_id == approved {
            assert!(matches!(
                finding.result,
                Err(RevocationStoreError::InvalidAssertion(_))
            ));
        } else {
            assert!(finding.result.is_ok());
        }
    }
}

/// Migration 0042: once a CA requires signed administration, a pending
/// CA-admin change is rejected only with a signed REJECT claim by another
/// admin (distinct key and person); the unsigned rejection is refused and
/// the evidence re-verifies.
#[test]
fn signed_ca_admin_rejection() {
    let Some(url) = database_url() else { return };
    let mut lab = lab(&url);
    let ca = lab.ca_id.clone();
    let mut owner = Client::connect(&lab.url, NoTls).unwrap();
    let mut boot = PgRevocationStore::connect_lab(&lab.url).unwrap();
    let (mut admin_a, mut admin_b) = (Authenticator::new(), Authenticator::new());
    let credential = |tag: u8| {
        let mut id = ca.replace('-', "").into_bytes();
        id.push(tag);
        id
    };
    let (a_id, b_id) = (credential(3), credential(4));
    boot.enroll_admin_credential(
        &ca,
        &a_id,
        &ADMIN_A,
        "person-admin-a",
        &admin_a.public_key(),
    )
    .unwrap();
    boot.enroll_admin_credential(
        &ca,
        &b_id,
        &ADMIN_B,
        "person-admin-b",
        &admin_b.public_key(),
    )
    .unwrap();
    owner
        .execute(
            "UPDATE ca_revocation_policy SET signed_admin_required = true
             WHERE ca_id = $1::text::uuid",
            &[&ca],
        )
        .unwrap();
    let grant = AdminChange::Officer(OfficerGrantAction::Grant, &THIRD);
    let challenge = lab
        .admin
        .issue_admin_proposal_challenge(&ca, &grant, &ADMIN_A, 120)
        .unwrap();
    let change = admin_submit(
        &mut lab.admin,
        &mut admin_a,
        &a_id,
        &challenge,
        Some(&grant),
    )
    .unwrap();

    let mut direct = Client::connect(&url_as(&url, "trust_ca_admin"), NoTls).unwrap();
    let unsigned = direct
        .query_one(
            "SELECT reject_ca_admin_change($1::text::uuid, $2, 'admin-b')",
            &[&change, &ISSUER],
        )
        .unwrap_err();
    assert_eq!(unsigned.code().map(|c| c.code()), Some("42501"));
    let own = lab
        .admin
        .issue_admin_rejection_challenge(AdminFamily::CaAdmin, &change, &ADMIN_A, 120)
        .unwrap_err();
    assert_eq!(sqlstate(&own).as_deref(), Some("23514"));
    let reject = lab
        .admin
        .issue_admin_rejection_challenge(AdminFamily::CaAdmin, &change, &ADMIN_B, 120)
        .unwrap();
    assert_eq!(
        admin_submit(&mut lab.admin, &mut admin_b, &b_id, &reject, None).unwrap(),
        change
    );
    let status: String = owner
        .query_one(
            "SELECT status FROM ca_admin_change WHERE change_id = $1::text::uuid",
            &[&change],
        )
        .unwrap()
        .get(0);
    assert_eq!(status, "REJECTED");
    lab.admin
        .reverify_admin_change(AdminFamily::CaAdmin, &change, &RP)
        .unwrap();
    // The rejected grant was not applied, and approving is no longer possible.
    let approval = lab
        .admin
        .issue_admin_approval_challenge(AdminFamily::CaAdmin, &change, &ADMIN_B, 120)
        .unwrap_err();
    assert_eq!(sqlstate(&approval).as_deref(), Some("23514"));
}

/// Migration 0044: a checker lists pending CA-admin changes with their
/// content; the digest is recomputed from the content, and content altered
/// in the database makes the listing fail closed instead of showing the
/// checker something other than what the maker signed.
#[test]
fn pending_admin_changes_show_the_signed_content() {
    let Some(url) = database_url() else { return };
    let mut lab = lab(&url);
    let ca = lab.ca_id.clone();
    let mut owner = Client::connect(&lab.url, NoTls).unwrap();
    owner
        .batch_execute(&format!(
            "INSERT INTO revocation_officer_grant(issuer, subject, ca_id)
                 VALUES ('{ISSUER}', 'third', '{ca}')"
        ))
        .unwrap();
    let key = Authenticator::new().public_key();
    let credential_id = {
        let mut id = ca.replace('-', "").into_bytes();
        id.push(8);
        id
    };
    let content = CredentialContent {
        ca_id: &ca,
        credential_id: &credential_id,
        officer: &THIRD,
        person_id: "person-third",
        public_key_sec1: &key,
    };
    let change = lab
        .admin
        .propose_credential_enrollment(&content, &ADMIN_A)
        .unwrap();
    let pending = lab.admin.pending_admin_changes(&ca).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].change_id, change);
    assert_eq!(pending[0].family, AdminFamily::Credential);
    assert_eq!(pending[0].kind, "ENROLL_CREDENTIAL");
    assert_eq!(pending[0].officer_subject.as_deref(), Some("third"));
    assert!(!pending[0].maker_signed);

    owner
        .batch_execute(&format!(
            "ALTER TABLE officer_credential_change DISABLE TRIGGER officer_credential_change_guard;
             UPDATE officer_credential_change SET person_id = 'someone-else'
              WHERE change_id = '{change}';
             ALTER TABLE officer_credential_change ENABLE TRIGGER officer_credential_change_guard"
        ))
        .unwrap();
    assert!(matches!(
        lab.admin.pending_admin_changes(&ca),
        Err(RevocationStoreError::InconsistentResult)
    ));
    // Officers cannot read pending CA administration.
    let denied = lab.officer.pending_admin_changes(&ca).unwrap_err();
    assert_eq!(sqlstate(&denied).as_deref(), Some("42501"));
}

fn breakglass_submit(
    store: &mut PgRevocationStore,
    authenticator: &mut Authenticator,
    credential_id: &[u8],
    challenge: &str,
    content: &CredentialContent<'_>,
) -> Result<String, RevocationStoreError> {
    let digest = store.admin_challenge(challenge).unwrap().claim.digest();
    let (data, client, signature) = authenticator.sign(&digest);
    store.submit_breakglass(
        challenge,
        credential_id,
        &Assertion {
            authenticator_data: &data,
            client_data_json: &client,
            signature_der: &signature,
        },
        &RP,
        content,
    )
}

fn breakglass_review(
    store: &mut PgRevocationStore,
    authenticator: &mut Authenticator,
    credential_id: &[u8],
    use_id: &str,
    reviewer: &OfficerIdentity<'_>,
) -> Result<bool, RevocationStoreError> {
    let challenge = store
        .issue_breakglass_review_challenge(use_id, reviewer, 120)
        .unwrap();
    let digest = store.admin_challenge(&challenge).unwrap().claim.digest();
    let (data, client, signature) = authenticator.sign(&digest);
    store.submit_breakglass_review(
        &challenge,
        credential_id,
        &Assertion {
            authenticator_data: &data,
            client_data_json: &client,
            signature_der: &signature,
        },
        &RP,
    )
}

/// Migration 0045 (minimal lab break-glass): when a signed-administration
/// CA has lost its admin keys, a separate DBA-enrolled emergency key may
/// enrol admin keys again, and nothing else; only while fewer than two
/// admin keys are active; each use is audited, alerted by housekeeping
/// until two other admins (distinct keys and persons) have signed a
/// review, and re-verifies offline.
#[test]
fn break_glass_restores_admin_keys_under_review() {
    let Some(url) = database_url() else { return };
    let mut lab = lab(&url);
    let ca = lab.ca_id.clone();
    let mut owner = Client::connect(&lab.url, NoTls).unwrap();
    let mut boot = PgRevocationStore::connect_lab(&lab.url).unwrap();
    let (lost_a, lost_b, mut emergency) = (
        Authenticator::new(),
        Authenticator::new(),
        Authenticator::new(),
    );
    let credential = |tag: u8| {
        let mut id = ca.replace('-', "").into_bytes();
        id.push(tag);
        id
    };
    let (old_a, old_b, bg_id) = (credential(3), credential(4), credential(20));
    let old_a_key = lost_a.public_key();
    boot.enroll_admin_credential(&ca, &old_a, &ADMIN_A, "person-admin-a", &old_a_key)
        .unwrap();
    boot.enroll_admin_credential(
        &ca,
        &old_b,
        &ADMIN_B,
        "person-admin-b",
        &lost_b.public_key(),
    )
    .unwrap();
    owner
        .batch_execute(&format!(
            "INSERT INTO ca_admin_grant(issuer, subject, ca_id) VALUES ('{ISSUER}', 'admin-c', '{ca}');
             UPDATE ca_revocation_policy SET signed_admin_required = true WHERE ca_id = '{ca}'"
        ))
        .unwrap();

    // The DBA enrols the emergency key; an admin key cannot be one.
    let reused = boot
        .enroll_breakglass_credential(
            &ca,
            &credential(21),
            "custodian",
            "person-custodian",
            &old_a_key,
        )
        .unwrap_err();
    assert_eq!(sqlstate(&reused).as_deref(), Some("23514"));
    boot.enroll_breakglass_credential(
        &ca,
        &bg_id,
        "custodian",
        "person-custodian",
        &emergency.public_key(),
    )
    .unwrap();

    let (mut admin_a, mut admin_b, mut admin_c) = (
        Authenticator::new(),
        Authenticator::new(),
        Authenticator::new(),
    );
    let (a_id, b_id, c_id) = (credential(11), credential(12), credential(13));
    let (a_key, b_key, c_key) = (
        admin_a.public_key(),
        admin_b.public_key(),
        admin_c.public_key(),
    );
    let a_content = CredentialContent {
        ca_id: &ca,
        credential_id: &a_id,
        officer: &ADMIN_A,
        person_id: "person-admin-a",
        public_key_sec1: &a_key,
    };
    let b_content = CredentialContent {
        ca_id: &ca,
        credential_id: &b_id,
        officer: &ADMIN_B,
        person_id: "person-admin-b",
        public_key_sec1: &b_key,
    };
    // Not an emergency while two admin keys are active.
    let refused = lab
        .admin
        .issue_breakglass_challenge(&bg_id, &a_content, 120)
        .unwrap_err();
    assert_eq!(sqlstate(&refused).as_deref(), Some("23514"));

    // Both admins lose their authenticators; the DBA retires the keys.
    for id in [&old_a, &old_b] {
        owner
            .execute("SELECT remove_ca_admin_credential($1)", &[id])
            .unwrap();
    }

    // The emergency key enrols A's new key; substituted content is refused.
    let challenge = lab
        .admin
        .issue_breakglass_challenge(&bg_id, &a_content, 120)
        .unwrap();
    assert!(matches!(
        breakglass_submit(
            &mut lab.admin,
            &mut emergency,
            &bg_id,
            &challenge,
            &b_content
        )
        .unwrap_err(),
        RevocationStoreError::SignedApprovalRefused
    ));
    let use_a = breakglass_submit(
        &mut lab.admin,
        &mut emergency,
        &bg_id,
        &challenge,
        &a_content,
    )
    .unwrap();
    // A consumed challenge does not sign twice.
    assert!(matches!(
        breakglass_submit(
            &mut lab.admin,
            &mut emergency,
            &bg_id,
            &challenge,
            &a_content
        )
        .unwrap_err(),
        RevocationStoreError::SignedApprovalRefused
    ));
    let challenge = lab
        .admin
        .issue_breakglass_challenge(&bg_id, &b_content, 120)
        .unwrap();
    // An admin key is not an emergency key.
    assert!(matches!(
        breakglass_submit(&mut lab.admin, &mut admin_a, &a_id, &challenge, &b_content).unwrap_err(),
        RevocationStoreError::SignedApprovalRefused
    ));
    let use_b = breakglass_submit(
        &mut lab.admin,
        &mut emergency,
        &bg_id,
        &challenge,
        &b_content,
    )
    .unwrap();

    // Two admin keys again: no further break-glass.
    let c_content = CredentialContent {
        ca_id: &ca,
        credential_id: &c_id,
        officer: &ADMIN_C,
        person_id: "person-admin-c",
        public_key_sec1: &c_key,
    };
    let refused = lab
        .admin
        .issue_breakglass_challenge(&bg_id, &c_content, 120)
        .unwrap_err();
    assert_eq!(sqlstate(&refused).as_deref(), Some("23514"));
    // The emergency key signs nothing else: it is no admin credential.
    let grant = AdminChange::Officer(OfficerGrantAction::Grant, &THIRD);
    let challenge = lab
        .admin
        .issue_admin_proposal_challenge(&ca, &grant, &ADMIN_A, 120)
        .unwrap();
    assert!(matches!(
        admin_submit(
            &mut lab.admin,
            &mut emergency,
            &bg_id,
            &challenge,
            Some(&grant)
        )
        .unwrap_err(),
        RevocationStoreError::SignedApprovalRefused
    ));
    let used: i64 = owner
        .query_one(
            "SELECT count(*) FROM audit_event
             WHERE ca_id = $1::text::uuid AND event_type = 'ca_admin.breakglass.used'",
            &[&ca],
        )
        .unwrap()
        .get(0);
    assert_eq!(used, 2);

    // Housekeeping alerts while the uses are unreviewed; one is overdue
    // (its deadline moved back by a superuser).
    owner
        .batch_execute(&format!(
            "ALTER TABLE breakglass_use DISABLE TRIGGER breakglass_use_guard;
             UPDATE breakglass_use SET review_by = used_at + interval '1 microsecond'
             WHERE use_id = '{use_b}';
             ALTER TABLE breakglass_use ENABLE TRIGGER breakglass_use_guard"
        ))
        .unwrap();
    let mut operator = PgRevocationStore::connect_lab(&url_as(&url, "trust_crl_operator")).unwrap();
    let report = operator.crl_housekeeping(&ca, 3600, 3600).unwrap();
    assert_eq!(
        (report.open_breakglass_uses, report.overdue_breakglass_uses),
        (2, 1)
    );
    assert!(report.needs_attention());

    // Ordinary dual control works again: A proposes C's key, B approves.
    let enroll = AdminChange::AdminCredential(CredentialChangeKind::Enroll, &c_content);
    let challenge = lab
        .admin
        .issue_admin_proposal_challenge(&ca, &enroll, &ADMIN_A, 120)
        .unwrap();
    let change = admin_submit(
        &mut lab.admin,
        &mut admin_a,
        &a_id,
        &challenge,
        Some(&enroll),
    )
    .unwrap();
    let approval = lab
        .admin
        .issue_admin_approval_challenge(AdminFamily::AdminCredential, &change, &ADMIN_B, 120)
        .unwrap();
    admin_submit(&mut lab.admin, &mut admin_b, &b_id, &approval, None).unwrap();

    // Reviews: never by the enrolled admin, never twice by one reviewer.
    let own = lab
        .admin
        .issue_breakglass_review_challenge(&use_a, &ADMIN_A, 120)
        .unwrap_err();
    assert_eq!(sqlstate(&own).as_deref(), Some("23514"));
    assert!(!breakglass_review(&mut lab.admin, &mut admin_b, &b_id, &use_a, &ADMIN_B).unwrap());
    let twice = lab
        .admin
        .issue_breakglass_review_challenge(&use_a, &ADMIN_B, 120)
        .unwrap_err();
    assert_eq!(sqlstate(&twice).as_deref(), Some("23514"));
    assert!(breakglass_review(&mut lab.admin, &mut admin_c, &c_id, &use_a, &ADMIN_C).unwrap());
    assert!(!breakglass_review(&mut lab.admin, &mut admin_a, &a_id, &use_b, &ADMIN_A).unwrap());
    assert!(breakglass_review(&mut lab.admin, &mut admin_c, &c_id, &use_b, &ADMIN_C).unwrap());
    let uses = lab.admin.breakglass_uses(&ca).unwrap();
    assert_eq!(uses.len(), 2);
    assert!(uses
        .iter()
        .all(|u| u.reviewed && u.reviews == 2 && !u.overdue));
    let report = operator.crl_housekeeping(&ca, 3600, 3600).unwrap();
    assert_eq!(
        (report.open_breakglass_uses, report.overdue_breakglass_uses),
        (0, 0)
    );

    // The auditor re-verifies both uses; an altered signature is exposed.
    let mut auditor =
        PgRevocationStore::connect_lab(&url_as(&url, "trust_audit_verifier")).unwrap();
    let breakglass = |findings: Vec<trust_pki_core::revocation_store::EvidenceFinding>| {
        findings
            .into_iter()
            .filter(|f| f.family == EvidenceFamily::BreakGlass)
            .map(|f| (f.change_id, f.result))
            .collect::<Vec<_>>()
    };
    let findings = breakglass(auditor.audit_signed_evidence(&ca, &RP).unwrap());
    assert_eq!(findings.len(), 2);
    assert!(findings.iter().all(|(_, r)| r.is_ok()), "{findings:?}");
    owner
        .batch_execute(&format!(
            "ALTER TABLE breakglass_review DISABLE TRIGGER breakglass_review_append_only;
             UPDATE breakglass_review
                SET signature_der = set_byte(signature_der, octet_length(signature_der) - 1,
                        get_byte(signature_der, octet_length(signature_der) - 1) # 1)
              WHERE use_id = '{use_b}' AND reviewer_subject = 'admin-c';
             ALTER TABLE breakglass_review ENABLE TRIGGER breakglass_review_append_only"
        ))
        .unwrap();
    for (use_id, result) in breakglass(auditor.audit_signed_evidence(&ca, &RP).unwrap()) {
        if use_id == use_b {
            assert!(matches!(
                result,
                Err(RevocationStoreError::InvalidAssertion(_))
            ));
        } else {
            assert!(result.is_ok());
        }
    }
}

/// Migration 0046: the break-glass custodian is a person who never signs on
/// the CA. A custodian cannot be an officer or admin of it, and the
/// emergency key cannot enrol an admin key for the custodian.
#[test]
fn breakglass_custodian_is_never_a_signer() {
    let Some(url) = database_url() else { return };
    let lab = lab(&url);
    let ca = lab.ca_id.clone();
    let mut owner = Client::connect(&lab.url, NoTls).unwrap();
    let mut boot = PgRevocationStore::connect_lab(&lab.url).unwrap();
    let mut admin = PgRevocationStore::connect_lab(&url_as(&url, "trust_ca_admin")).unwrap();
    let credential = |tag: u8| {
        let mut id = ca.replace('-', "").into_bytes();
        id.push(tag);
        id
    };
    let (old_a, old_b, bg_id) = (credential(3), credential(4), credential(20));
    boot.enroll_admin_credential(
        &ca,
        &old_a,
        &ADMIN_A,
        "person-admin-a",
        &Authenticator::new().public_key(),
    )
    .unwrap();
    boot.enroll_admin_credential(
        &ca,
        &old_b,
        &ADMIN_B,
        "person-admin-b",
        &Authenticator::new().public_key(),
    )
    .unwrap();
    owner
        .batch_execute(&format!(
            "UPDATE ca_revocation_policy SET signed_admin_required = true WHERE ca_id = '{ca}'"
        ))
        .unwrap();
    let mut emergency = Authenticator::new();
    let key = emergency.public_key();
    // An admin's or an officer's person cannot hold the emergency key.
    for person in ["person-admin-a", "person-maker"] {
        let refused = boot
            .enroll_breakglass_credential(&ca, &bg_id, "custodian", person, &key)
            .unwrap_err();
        assert_eq!(sqlstate(&refused).as_deref(), Some("23514"), "{person}");
    }
    boot.enroll_breakglass_credential(&ca, &bg_id, "custodian", "person-custodian", &key)
        .unwrap();
    for id in [&old_a, &old_b] {
        owner
            .execute("SELECT remove_ca_admin_credential($1)", &[id])
            .unwrap();
    }
    // The custodian cannot enrol an admin key for themselves.
    let a_key = Authenticator::new().public_key();
    let a_id = credential(11);
    let own = CredentialContent {
        ca_id: &ca,
        credential_id: &a_id,
        officer: &ADMIN_A,
        person_id: "person-custodian",
        public_key_sec1: &a_key,
    };
    let challenge = admin.issue_breakglass_challenge(&bg_id, &own, 120).unwrap();
    let refused =
        breakglass_submit(&mut admin, &mut emergency, &bg_id, &challenge, &own).unwrap_err();
    assert_eq!(sqlstate(&refused).as_deref(), Some("23514"));
    // The admin's own person is accepted.
    let content = CredentialContent {
        person_id: "person-admin-a",
        ..own
    };
    let challenge = admin
        .issue_breakglass_challenge(&bg_id, &content, 120)
        .unwrap();
    breakglass_submit(&mut admin, &mut emergency, &bg_id, &challenge, &content).unwrap();
}

/// Migration 0045's "fewer than two admin keys" rule holds under
/// concurrency: with two custodians (two emergency keys), a second use
/// waits for the CA lock held by a first, still-open use, then is refused.
/// Without the lock both would read one active key and enrol a third.
#[test]
fn concurrent_breakglass_uses_cannot_exceed_two_admin_keys() {
    let Some(url) = database_url() else { return };
    let lab = lab(&url);
    let ca = lab.ca_id.clone();
    let mut owner = Client::connect(&lab.url, NoTls).unwrap();
    let mut boot = PgRevocationStore::connect_lab(&lab.url).unwrap();
    let credential = |tag: u8| {
        let mut id = ca.replace('-', "").into_bytes();
        id.push(tag);
        id
    };
    boot.enroll_admin_credential(
        &ca,
        &credential(3),
        &ADMIN_A,
        "person-admin-a",
        &Authenticator::new().public_key(),
    )
    .unwrap();
    owner
        .batch_execute(&format!(
            "INSERT INTO ca_admin_grant(issuer, subject, ca_id) VALUES ('{ISSUER}', 'admin-c', '{ca}');
             UPDATE ca_revocation_policy SET signed_admin_required = true WHERE ca_id = '{ca}'"
        ))
        .unwrap();
    let (mut first, mut second) = (Authenticator::new(), Authenticator::new());
    let (first_id, second_id) = (credential(20), credential(21));
    boot.enroll_breakglass_credential(
        &ca,
        &first_id,
        "custodian-1",
        "person-custodian-1",
        &first.public_key(),
    )
    .unwrap();
    boot.enroll_breakglass_credential(
        &ca,
        &second_id,
        "custodian-2",
        "person-custodian-2",
        &second.public_key(),
    )
    .unwrap();

    let admin_url = url_as(&url, "trust_ca_admin");
    let mut admin = PgRevocationStore::connect_lab(&admin_url).unwrap();
    let (b_key, c_key) = (
        canonical_officer_key(&Authenticator::new().public_key()).unwrap(),
        canonical_officer_key(&Authenticator::new().public_key()).unwrap(),
    );
    let (b_id, c_id) = (credential(12), credential(13));
    let b_content = CredentialContent {
        ca_id: &ca,
        credential_id: &b_id,
        officer: &ADMIN_B,
        person_id: "person-admin-b",
        public_key_sec1: &b_key,
    };
    let c_content = CredentialContent {
        ca_id: &ca,
        credential_id: &c_id,
        officer: &ADMIN_C,
        person_id: "person-admin-c",
        public_key_sec1: &c_key,
    };
    // Both challenges are admissible: one admin key is active.
    let first_challenge = admin
        .issue_breakglass_challenge(&first_id, &b_content, 120)
        .unwrap();
    let second_challenge = admin
        .issue_breakglass_challenge(&second_id, &c_content, 120)
        .unwrap();

    // The first use runs inside a transaction that stays open.
    let digest = admin
        .admin_challenge(&first_challenge)
        .unwrap()
        .claim
        .digest();
    let (data, client, signature) = first.sign(&digest);
    let mut open = Client::connect(&admin_url, NoTls).unwrap();
    let mut transaction = open.transaction().unwrap();
    transaction
        .query_one(
            "SELECT breakglass_enroll_admin_credential($1::text::uuid, $2, $3, $4, $5,
                                                      $6, $7, $8, $9, $10)::text",
            &[
                &first_challenge,
                &first_id,
                &data,
                &client,
                &signature,
                &b_id,
                &ADMIN_B.issuer,
                &ADMIN_B.subject,
                &"person-admin-b",
                &&b_key[..],
            ],
        )
        .unwrap();

    // The second use, from another session, must wait for the CA lock.
    let racer_url = format!("{admin_url}&application_name=breakglass-racer-{ca}");
    let racer = std::thread::spawn({
        let ca = ca.clone();
        move || {
            let mut store = PgRevocationStore::connect_lab(&racer_url).unwrap();
            let content = CredentialContent {
                ca_id: &ca,
                credential_id: &c_id,
                officer: &ADMIN_C,
                person_id: "person-admin-c",
                public_key_sec1: &c_key,
            };
            breakglass_submit(
                &mut store,
                &mut second,
                &second_id,
                &second_challenge,
                &content,
            )
        }
    });
    let waiting = waits_for_lock(&mut owner, &format!("breakglass-racer-{ca}"));
    transaction.commit().unwrap();
    let outcome = racer.join().unwrap();
    assert!(
        waiting,
        "the second use did not wait for the CA lock: {outcome:?}"
    );
    assert_eq!(sqlstate(&outcome.unwrap_err()).as_deref(), Some("23514"));
    let active: i64 = owner
        .query_one(
            "SELECT count(*) FROM ca_admin_credential
             WHERE ca_id = $1::text::uuid AND status = 'ACTIVE'",
            &[&ca],
        )
        .unwrap()
        .get(0);
    assert_eq!(active, 2);
}

/// True once a session named `application_name` waits on a lock (polled
/// for up to 10 seconds).
fn waits_for_lock(owner: &mut Client, application_name: &str) -> bool {
    (0..100).any(|_| {
        let waiting: i64 = owner
            .query_one(
                "SELECT count(*) FROM pg_stat_activity
                 WHERE application_name = $1 AND wait_event_type = 'Lock'",
                &[&application_name],
            )
            .unwrap()
            .get(0);
        if waiting == 0 {
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        waiting > 0
    })
}

/// ADR-0007 evidence "concurrency tests for challenge consumption": a
/// checker's approval challenge answered twice at once (two valid
/// assertions, two sessions) is consumed once. The second answer passes the
/// Rust core's checks (the first is not committed yet), waits for the
/// database locks, then is refused; one CHECKER signature is stored.
#[test]
fn concurrent_answers_consume_a_status_challenge_once() {
    let Some(url) = database_url() else { return };
    let mut lab = lab(&url);
    let mut owner = Client::connect(&lab.url, NoTls).unwrap();
    let change = lab.signed_proposal();
    let challenge = challenge_for(&mut lab, &change);
    let digest = lab
        .officer
        .signed_challenge(&challenge)
        .unwrap()
        .digest()
        .unwrap();
    let (data, client, signature) = lab.checker.sign(&digest);
    let second = lab.checker.sign(&digest);
    let officer_url = url_as(&url, "trust_revocation_officer_api");
    let mut open = Client::connect(&officer_url, NoTls).unwrap();
    let mut transaction = open.transaction().unwrap();
    transaction
        .query_one(
            "SELECT approve_signed_status_change($1::text::uuid, $2, $3, $4, $5)::text",
            &[
                &challenge,
                &lab.checker_credential,
                &data,
                &client,
                &signature,
            ],
        )
        .unwrap();
    let name = format!("status-racer-{change}");
    let racer = std::thread::spawn({
        let url = format!("{officer_url}&application_name={name}");
        let (challenge, credential) = (challenge.clone(), lab.checker_credential.clone());
        move || {
            let (data, client, signature) = second;
            PgRevocationStore::connect_lab(&url).unwrap().submit_signed(
                &challenge,
                &credential,
                &Assertion {
                    authenticator_data: &data,
                    client_data_json: &client,
                    signature_der: &signature,
                },
                &RP,
            )
        }
    });
    let waiting = waits_for_lock(&mut owner, &name);
    transaction.commit().unwrap();
    let outcome = racer.join().unwrap();
    assert!(waiting, "the second answer did not wait: {outcome:?}");
    assert!(
        matches!(outcome, Err(RevocationStoreError::Database(_))),
        "{outcome:?}"
    );
    let row = owner
        .query_one(
            "SELECT (SELECT count(*) FROM status_change_signature
                     WHERE change_id = $1::text::uuid AND role = 'CHECKER'),
                    (SELECT status FROM certificate_status_change
                     WHERE change_id = $1::text::uuid)",
            &[&change],
        )
        .unwrap();
    assert_eq!(
        (row.get::<_, i64>(0), row.get::<_, String>(1)),
        (1, "APPROVED".to_owned())
    );
    lab.officer.reverify_signed_change(&change, &RP).unwrap();
}

/// The same for a CA-admin approval challenge (migration 0037).
#[test]
fn concurrent_answers_consume_an_admin_challenge_once() {
    let Some(url) = database_url() else { return };
    let mut lab = lab(&url);
    let ca = lab.ca_id.clone();
    let mut owner = Client::connect(&lab.url, NoTls).unwrap();
    let mut boot = PgRevocationStore::connect_lab(&lab.url).unwrap();
    let (mut admin_a, mut admin_b) = (Authenticator::new(), Authenticator::new());
    let credential = |tag: u8| {
        let mut id = ca.replace('-', "").into_bytes();
        id.push(tag);
        id
    };
    let (a_id, b_id) = (credential(3), credential(4));
    boot.enroll_admin_credential(
        &ca,
        &a_id,
        &ADMIN_A,
        "person-admin-a",
        &admin_a.public_key(),
    )
    .unwrap();
    boot.enroll_admin_credential(
        &ca,
        &b_id,
        &ADMIN_B,
        "person-admin-b",
        &admin_b.public_key(),
    )
    .unwrap();
    owner
        .execute(
            "UPDATE ca_revocation_policy SET signed_admin_required = true
             WHERE ca_id = $1::text::uuid",
            &[&ca],
        )
        .unwrap();
    let grant = AdminChange::Officer(OfficerGrantAction::Grant, &THIRD);
    let challenge = lab
        .admin
        .issue_admin_proposal_challenge(&ca, &grant, &ADMIN_A, 120)
        .unwrap();
    let change = admin_submit(
        &mut lab.admin,
        &mut admin_a,
        &a_id,
        &challenge,
        Some(&grant),
    )
    .unwrap();
    let challenge = lab
        .admin
        .issue_admin_approval_challenge(AdminFamily::CaAdmin, &change, &ADMIN_B, 120)
        .unwrap();
    let digest = lab
        .admin
        .admin_challenge(&challenge)
        .unwrap()
        .claim
        .digest();
    let (data, client, signature) = admin_b.sign(&digest);
    let second = admin_b.sign(&digest);
    let admin_url = url_as(&url, "trust_ca_admin");
    let mut open = Client::connect(&admin_url, NoTls).unwrap();
    let mut transaction = open.transaction().unwrap();
    transaction
        .execute(
            "SELECT approve_signed_admin_change($1::text::uuid, $2, $3, $4, $5)",
            &[&challenge, &b_id, &data, &client, &signature],
        )
        .unwrap();
    let name = format!("admin-racer-{change}");
    let racer = std::thread::spawn({
        let url = format!("{admin_url}&application_name={name}");
        let (challenge, b_id) = (challenge.clone(), b_id.clone());
        move || {
            let (data, client, signature) = second;
            PgRevocationStore::connect_lab(&url)
                .unwrap()
                .submit_signed_admin(
                    &challenge,
                    &b_id,
                    &Assertion {
                        authenticator_data: &data,
                        client_data_json: &client,
                        signature_der: &signature,
                    },
                    &RP,
                    None,
                )
        }
    });
    let waiting = waits_for_lock(&mut owner, &name);
    transaction.commit().unwrap();
    let outcome = racer.join().unwrap();
    assert!(waiting, "the second answer did not wait: {outcome:?}");
    assert!(
        matches!(outcome, Err(RevocationStoreError::Database(_))),
        "{outcome:?}"
    );
    let row = owner
        .query_one(
            "SELECT (SELECT count(*) FROM ca_admin_signature
                     WHERE family = 'CA_ADMIN' AND change_id = $1::text::uuid
                       AND role = 'CHECKER'),
                    (SELECT status FROM ca_admin_change WHERE change_id = $1::text::uuid)",
            &[&change],
        )
        .unwrap();
    assert_eq!(
        (row.get::<_, i64>(0), row.get::<_, String>(1)),
        (1, "APPROVED".to_owned())
    );
    lab.admin
        .reverify_admin_change(AdminFamily::CaAdmin, &change, &RP)
        .unwrap();
}

/// Several officers together cannot hold more certificates as a precaution
/// than the CA's own limit (migration 0047); a confirmed hold frees a slot.
#[test]
fn precautionary_holds_are_capped_per_ca() {
    let Some(url) = database_url() else { return };
    let mut lab = lab(&url);
    let ca = lab.ca_id.clone();
    let mut owner = Client::connect(&lab.url, NoTls).unwrap();
    second_certificate(&mut owner, &ca);
    owner
        .batch_execute(&format!(
            "UPDATE ca_revocation_policy
                 SET suspension_cps_ref = 'CPS 4.9.13', precautionary_hold_hours = 24,
                     precautionary_hold_limit = 3, precautionary_hold_ca_limit = 1
                 WHERE ca_id = '{ca}';"
        ))
        .unwrap();
    let first = SerialNumber::from_positive_der_content(&[0x01]).unwrap();
    let second = SerialNumber::from_positive_der_content(&[0x02]).unwrap();
    let hold = |lab: &mut Lab, serial: &SerialNumber, maker: bool| {
        let officer = if maker { &MAKER } else { &CHECKER };
        let challenge = lab
            .officer
            .issue_precaution_challenge(&ca, serial, officer, 120)
            .unwrap();
        lab.submit(&challenge, maker, None)
    };
    hold(&mut lab, &first, true).unwrap();
    // Another officer, well under their own limit, is stopped by the CA's.
    let capped = hold(&mut lab, &second, false).unwrap_err();
    assert_eq!(sqlstate(&capped).as_deref(), Some("23514"));
    assert_eq!(
        lab.officer.status(&ca, &second).unwrap(),
        CertificateStatus::Valid
    );
    // Confirming the first hold (dual-controlled revocation) frees the slot.
    let definitive = lab.signed_proposal();
    let approval = lab
        .officer
        .issue_approval_challenge(&definitive, &CHECKER, 120)
        .unwrap();
    lab.submit(&approval, false, None).unwrap();
    hold(&mut lab, &second, false).unwrap();
    assert_eq!(
        lab.officer.status(&ca, &second).unwrap(),
        CertificateStatus::Suspended
    );
    for bad in [0, 1001] {
        let refused = owner
            .execute(
                "UPDATE ca_revocation_policy SET precautionary_hold_ca_limit = $2
                 WHERE ca_id = $1::text::uuid",
                &[&ca, &(bad as i16)],
            )
            .unwrap_err();
        assert_eq!(refused.code().map(|c| c.code()), Some("23514"));
    }
}

/// The CA cap holds under concurrency (migration 0047): while one officer's
/// hold is still uncommitted, another officer's hold waits for the per-CA
/// lock, then is refused. With 0038's per-officer lock both would pass.
#[test]
fn concurrent_holds_by_two_officers_respect_the_ca_cap() {
    let Some(url) = database_url() else { return };
    let mut lab = lab(&url);
    let ca = lab.ca_id.clone();
    let mut owner = Client::connect(&lab.url, NoTls).unwrap();
    second_certificate(&mut owner, &ca);
    owner
        .batch_execute(&format!(
            "UPDATE ca_revocation_policy
                 SET suspension_cps_ref = 'CPS 4.9.13', precautionary_hold_hours = 24,
                     precautionary_hold_limit = 3, precautionary_hold_ca_limit = 1
                 WHERE ca_id = '{ca}';"
        ))
        .unwrap();
    let first = SerialNumber::from_positive_der_content(&[0x01]).unwrap();
    let second = SerialNumber::from_positive_der_content(&[0x02]).unwrap();
    let maker_challenge = lab
        .officer
        .issue_precaution_challenge(&ca, &first, &MAKER, 120)
        .unwrap();
    let checker_challenge = lab
        .officer
        .issue_precaution_challenge(&ca, &second, &CHECKER, 120)
        .unwrap();
    let digest =
        |lab: &mut Lab, id: &str| lab.officer.signed_challenge(id).unwrap().digest().unwrap();
    let maker_digest = digest(&mut lab, &maker_challenge);
    let (data, client, signature) = lab.maker.sign(&maker_digest);
    let checker_digest = digest(&mut lab, &checker_challenge);
    let checker_assertion = lab.checker.sign(&checker_digest);
    let officer_url = url_as(&url, "trust_revocation_officer_api");
    let mut open = Client::connect(&officer_url, NoTls).unwrap();
    let mut transaction = open.transaction().unwrap();
    transaction
        .query_one(
            "SELECT apply_precautionary_hold($1::text::uuid, $2, $3, $4, $5)::text",
            &[
                &maker_challenge,
                &lab.maker_credential,
                &data,
                &client,
                &signature,
            ],
        )
        .unwrap();
    let name = format!("hold-racer-{ca}");
    let racer = std::thread::spawn({
        let url = format!("{officer_url}&application_name={name}");
        let credential = lab.checker_credential.clone();
        move || {
            let (data, client, signature) = checker_assertion;
            PgRevocationStore::connect_lab(&url).unwrap().submit_signed(
                &checker_challenge,
                &credential,
                &Assertion {
                    authenticator_data: &data,
                    client_data_json: &client,
                    signature_der: &signature,
                },
                &RP,
            )
        }
    });
    let waiting = waits_for_lock(&mut owner, &name);
    transaction.commit().unwrap();
    let outcome = racer.join().unwrap();
    assert!(waiting, "the second hold did not wait: {outcome:?}");
    assert_eq!(sqlstate(&outcome.unwrap_err()).as_deref(), Some("23514"));
    assert_eq!(lab.officer.precautionary_holds(&ca).unwrap().len(), 1);
}

/// The person and key separation between the officer, admin and
/// break-glass registries holds under concurrency (migration 0048): while
/// a custodian's enrolment is uncommitted, enrolling an admin key for the
/// same person waits, then is refused. Before 0048 both committed.
#[test]
fn concurrent_custodian_and_admin_enrolment_stay_disjoint() {
    let Some(url) = database_url() else { return };
    let lab = lab(&url);
    let ca = lab.ca_id.clone();
    let mut owner = Client::connect(&lab.url, NoTls).unwrap();
    let credential = |tag: u8| {
        let mut id = ca.replace('-', "").into_bytes();
        id.push(tag);
        id
    };
    let custodian_key = canonical_officer_key(&Authenticator::new().public_key()).unwrap();
    let mut open = Client::connect(&url, NoTls).unwrap();
    let mut transaction = open.transaction().unwrap();
    transaction
        .execute(
            "SELECT enroll_breakglass_credential($1::text::uuid, $2, 'custodian', 'person-x', $3)",
            &[&ca, &credential(20), &&custodian_key[..]],
        )
        .unwrap();
    let name = format!("registry-racer-{ca}");
    let racer = std::thread::spawn({
        let separator = if url.contains('?') { '&' } else { '?' };
        let url = format!("{url}{separator}application_name={name}");
        let (ca, id) = (ca.clone(), credential(3));
        move || {
            PgRevocationStore::connect_lab(&url)
                .unwrap()
                .enroll_admin_credential(
                    &ca,
                    &id,
                    &ADMIN_A,
                    "person-x",
                    &Authenticator::new().public_key(),
                )
        }
    });
    let waiting = waits_for_lock(&mut owner, &name);
    transaction.commit().unwrap();
    let outcome = racer.join().unwrap();
    assert!(waiting, "the admin enrolment did not wait: {outcome:?}");
    assert_eq!(sqlstate(&outcome.unwrap_err()).as_deref(), Some("23514"));
    let admins: i64 = owner
        .query_one(
            "SELECT count(*) FROM ca_admin_credential
             WHERE ca_id = $1::text::uuid AND person_id = 'person-x'",
            &[&ca],
        )
        .unwrap()
        .get(0);
    assert_eq!(admins, 0);
}

/// One actor cannot pile up open challenges on a CA (migration 0049): at
/// most 16 unexpired, unconsumed status-change and 16 CA-admin challenges
/// each. Other actors are unaffected; expired or consumed challenges stop
/// counting.
#[test]
fn open_challenges_are_capped_per_actor() {
    let Some(url) = database_url() else { return };
    let mut lab = lab(&url);
    let ca = lab.ca_id.clone();
    for _ in 0..15 {
        lab.propose_challenge();
    }
    // The 16th is consumed: it no longer counts.
    let change = lab.signed_proposal();
    // A 16th open one, short-lived.
    lab.officer
        .issue_proposal_challenge(
            &ca,
            &lab.serial,
            StatusAction::Revoke,
            Some(RevocationReason::KeyCompromise),
            None,
            &MAKER,
            1,
        )
        .unwrap();
    let flood = lab
        .officer
        .issue_proposal_challenge(
            &ca,
            &lab.serial,
            StatusAction::Revoke,
            Some(RevocationReason::KeyCompromise),
            None,
            &MAKER,
            120,
        )
        .unwrap_err();
    assert_eq!(sqlstate(&flood).as_deref(), Some("23514"));
    // Another officer still gets one.
    lab.officer
        .issue_approval_challenge(&change, &CHECKER, 120)
        .unwrap();
    // The short-lived ones expire and free their slots.
    std::thread::sleep(std::time::Duration::from_millis(1500));
    lab.propose_challenge();

    let grant = AdminChange::Officer(OfficerGrantAction::Grant, &THIRD);
    for _ in 0..16 {
        lab.admin
            .issue_admin_proposal_challenge(&ca, &grant, &ADMIN_A, 120)
            .unwrap();
    }
    let flood = lab
        .admin
        .issue_admin_proposal_challenge(&ca, &grant, &ADMIN_A, 120)
        .unwrap_err();
    assert_eq!(sqlstate(&flood).as_deref(), Some("23514"));
    lab.admin
        .issue_admin_proposal_challenge(&ca, &grant, &ADMIN_B, 120)
        .unwrap();
}

/// ADR-0007 evidence "a credential removed mid-flow" and "the counter of a
/// removed credential", for all three registries: a challenge issued before
/// the key's removal cannot be answered with it afterwards (in the Rust
/// core, and for officers also straight at the database), and a removed
/// key's counter is frozen even for a superuser's UPDATE.
#[test]
fn removed_credentials_never_sign_again() {
    let Some(url) = database_url() else { return };
    let mut lab = lab(&url);
    let ca = lab.ca_id.clone();
    let mut owner = Client::connect(&lab.url, NoTls).unwrap();
    let mut boot = PgRevocationStore::connect_lab(&lab.url).unwrap();
    let frozen = |owner: &mut Client, table: &str, id: &[u8]| {
        let before: i64 = owner
            .query_one(
                &format!("SELECT sign_count FROM {table} WHERE credential_id = $1"),
                &[&id],
            )
            .unwrap()
            .get(0);
        let refused = owner
            .execute(
                &format!("UPDATE {table} SET sign_count = sign_count + 1 WHERE credential_id = $1"),
                &[&id],
            )
            .unwrap_err();
        assert_eq!(refused.code().map(|c| c.code()), Some("23514"), "{table}");
        before
    };

    // Officer: the checker's key is removed between challenge and answer.
    let change = lab.signed_proposal();
    let challenge = challenge_for(&mut lab, &change);
    let checker_key = lab.checker.public_key();
    let checker_id = lab.checker_credential.clone();
    let removal = lab
        .admin
        .propose_credential_removal(&ca, &checker_id, &CHECKER, &ADMIN_A)
        .unwrap();
    lab.admin
        .approve_credential_change(
            &removal,
            CredentialChangeKind::Remove,
            &CredentialContent {
                ca_id: &ca,
                credential_id: &checker_id,
                officer: &CHECKER,
                person_id: "person-checker",
                public_key_sec1: &checker_key,
            },
            &ADMIN_B,
        )
        .unwrap();
    let count = frozen(&mut owner, "officer_credential", &checker_id);
    assert!(matches!(
        lab.submit(&challenge, false, None).unwrap_err(),
        RevocationStoreError::SignedApprovalRefused
    ));
    let digest = lab
        .officer
        .signed_challenge(&challenge)
        .unwrap()
        .digest()
        .unwrap();
    let (data, client, signature) = lab.checker.sign(&digest);
    let mut officer_db =
        Client::connect(&url_as(&url, "trust_revocation_officer_api"), NoTls).unwrap();
    let direct = officer_db
        .query_one(
            "SELECT approve_signed_status_change($1::text::uuid, $2, $3, $4, $5)::text",
            &[&challenge, &checker_id, &data, &client, &signature],
        )
        .unwrap_err();
    assert_eq!(direct.code().map(|c| c.code()), Some("42501"));
    assert_eq!(frozen(&mut owner, "officer_credential", &checker_id), count);

    // CA admin: the DBA removes A's key between challenge and answer.
    let (mut admin_a, admin_b) = (Authenticator::new(), Authenticator::new());
    let credential = |tag: u8| {
        let mut id = ca.replace('-', "").into_bytes();
        id.push(tag);
        id
    };
    let (a_id, b_id) = (credential(3), credential(4));
    boot.enroll_admin_credential(
        &ca,
        &a_id,
        &ADMIN_A,
        "person-admin-a",
        &admin_a.public_key(),
    )
    .unwrap();
    boot.enroll_admin_credential(
        &ca,
        &b_id,
        &ADMIN_B,
        "person-admin-b",
        &admin_b.public_key(),
    )
    .unwrap();
    owner
        .execute(
            "UPDATE ca_revocation_policy SET signed_admin_required = true
             WHERE ca_id = $1::text::uuid",
            &[&ca],
        )
        .unwrap();
    let grant = AdminChange::Officer(OfficerGrantAction::Grant, &THIRD);
    let challenge = lab
        .admin
        .issue_admin_proposal_challenge(&ca, &grant, &ADMIN_A, 120)
        .unwrap();
    owner
        .execute("SELECT remove_ca_admin_credential($1)", &[&a_id])
        .unwrap();
    let count = frozen(&mut owner, "ca_admin_credential", &a_id);
    assert!(matches!(
        admin_submit(
            &mut lab.admin,
            &mut admin_a,
            &a_id,
            &challenge,
            Some(&grant)
        )
        .unwrap_err(),
        RevocationStoreError::SignedApprovalRefused
    ));
    assert_eq!(frozen(&mut owner, "ca_admin_credential", &a_id), count);

    // Break-glass: the DBA removes the emergency key between challenge and
    // answer; no new challenge is issued for it.
    let mut emergency = Authenticator::new();
    let bg_id = credential(20);
    boot.enroll_breakglass_credential(
        &ca,
        &bg_id,
        "custodian",
        "person-custodian",
        &emergency.public_key(),
    )
    .unwrap();
    let a_key = Authenticator::new().public_key();
    let a_new = credential(11);
    let content = CredentialContent {
        ca_id: &ca,
        credential_id: &a_new,
        officer: &ADMIN_A,
        person_id: "person-admin-a",
        public_key_sec1: &a_key,
    };
    let challenge = lab
        .admin
        .issue_breakglass_challenge(&bg_id, &content, 120)
        .unwrap();
    owner
        .execute("SELECT remove_breakglass_credential($1)", &[&bg_id])
        .unwrap();
    let count = frozen(&mut owner, "ca_breakglass_credential", &bg_id);
    assert!(matches!(
        breakglass_submit(&mut lab.admin, &mut emergency, &bg_id, &challenge, &content)
            .unwrap_err(),
        RevocationStoreError::SignedApprovalRefused
    ));
    let refused = lab
        .admin
        .issue_breakglass_challenge(&bg_id, &content, 120)
        .unwrap_err();
    assert_eq!(sqlstate(&refused).as_deref(), Some("42501"));
    assert_eq!(
        frozen(&mut owner, "ca_breakglass_credential", &bg_id),
        count
    );
}

/// A CA-admin proposal older than the CA's `admin_proposal_max_age_hours`
/// (default 168, migration 0052) can no longer be approved; a younger one
/// can. Rejection stays possible, so stale proposals are closed, not lost.
#[test]
fn stale_admin_proposals_cannot_be_approved() {
    let Some(url) = database_url() else { return };
    let mut lab = lab(&url);
    let ca = lab.ca_id.clone();
    let mut owner = Client::connect(&lab.url, NoTls).unwrap();
    let age = |owner: &mut Client, change: &str, days: i32| {
        owner
            .batch_execute(&format!(
                "ALTER TABLE ca_admin_change DISABLE TRIGGER ca_admin_change_guard;
                 UPDATE ca_admin_change SET proposed_at = proposed_at - interval '{days} days'
                 WHERE change_id = '{change}';
                 ALTER TABLE ca_admin_change ENABLE TRIGGER ca_admin_change_guard"
            ))
            .unwrap();
    };
    let stale = lab
        .admin
        .propose_officer_grant(&ca, OfficerGrantAction::Grant, &THIRD, &ADMIN_A)
        .unwrap();
    age(&mut owner, &stale, 8);
    let refused = lab
        .admin
        .approve_officer_grant(&stale, OfficerGrantAction::Grant, &THIRD, &ADMIN_B)
        .unwrap_err();
    assert_eq!(sqlstate(&refused).as_deref(), Some("23514"));
    let status: String = owner
        .query_one(
            "SELECT status FROM ca_admin_change WHERE change_id = $1::text::uuid",
            &[&stale],
        )
        .unwrap()
        .get(0);
    assert_eq!(status, "PROPOSED");
    // Within the limit it is approved as before.
    let recent = lab
        .admin
        .propose_officer_grant(&ca, OfficerGrantAction::Revoke, &MAKER, &ADMIN_A)
        .unwrap();
    age(&mut owner, &recent, 2);
    lab.admin
        .approve_officer_grant(&recent, OfficerGrantAction::Revoke, &MAKER, &ADMIN_B)
        .unwrap();
    for bad in [0_i16, 2161] {
        let refused = owner
            .execute(
                "UPDATE ca_revocation_policy SET admin_proposal_max_age_hours = $2
                 WHERE ca_id = $1::text::uuid",
                &[&ca, &bad],
            )
            .unwrap_err();
        assert_eq!(refused.code().map(|c| c.code()), Some("23514"));
    }
}

/// Challenges that expired unused more than the retention ago are not
/// evidence of anything and are purged by housekeeping (migration 0053);
/// consumed challenges (evidence) and recent ones stay, and nobody else
/// may delete a challenge.
#[test]
fn expired_unused_challenges_are_purged() {
    let Some(url) = database_url() else { return };
    let mut lab = lab(&url);
    let ca = lab.ca_id.clone();
    let mut owner = Client::connect(&lab.url, NoTls).unwrap();
    let old_unused = lab.propose_challenge();
    let recent_unused = lab.propose_challenge();
    let change = lab.signed_proposal();
    let consumed: String = owner
        .query_one(
            "SELECT challenge_id::text FROM status_change_signature
             WHERE change_id = $1::text::uuid AND role = 'MAKER'",
            &[&change],
        )
        .unwrap()
        .get(0);
    // Age two of them (a superuser, with the guard disabled).
    owner
        .batch_execute(&format!(
            "ALTER TABLE status_change_challenge DISABLE TRIGGER status_change_challenge_guard;
             UPDATE status_change_challenge
                SET issued_at = issued_at - interval '40 days',
                    expires_at = expires_at - interval '40 days'
              WHERE challenge_id IN ('{old_unused}', '{consumed}');
             ALTER TABLE status_change_challenge ENABLE TRIGGER status_change_challenge_guard"
        ))
        .unwrap();
    // Recent or consumed challenges cannot be deleted, even by a superuser.
    for id in [&recent_unused, &consumed] {
        let refused = owner
            .execute(
                "DELETE FROM status_change_challenge WHERE challenge_id = $1::text::uuid",
                &[id],
            )
            .unwrap_err();
        assert_eq!(refused.code().map(|c| c.code()), Some("23514"));
    }
    let mut operator = Client::connect(&url_as(&url, "trust_crl_operator"), NoTls).unwrap();
    // An admin challenge expired unused long ago is purged by housekeeping.
    let grant = AdminChange::Officer(OfficerGrantAction::Grant, &THIRD);
    let admin_unused = lab
        .admin
        .issue_admin_proposal_challenge(&ca, &grant, &ADMIN_A, 120)
        .unwrap();
    owner
        .batch_execute(&format!(
            "ALTER TABLE ca_admin_challenge DISABLE TRIGGER ca_admin_challenge_guard;
             UPDATE ca_admin_challenge
                SET issued_at = issued_at - interval '40 days',
                    expires_at = expires_at - interval '40 days'
              WHERE challenge_id = '{admin_unused}';
             ALTER TABLE ca_admin_challenge ENABLE TRIGGER ca_admin_challenge_guard"
        ))
        .unwrap();
    let report = PgRevocationStore::connect_lab(&url_as(&url, "trust_crl_operator"))
        .unwrap()
        .crl_housekeeping(&ca, 3600, 3600)
        .unwrap();
    // Both old unused challenges (status change and CA admin) go.
    assert_eq!(report.purged_challenges, 2);
    let too_short = operator
        .query_one("SELECT purge_expired_challenges($1::text::uuid, 6)", &[&ca])
        .unwrap_err();
    assert_eq!(too_short.code().map(|c| c.code()), Some("22023"));
    let purged: i64 = operator
        .query_one(
            "SELECT purge_expired_challenges($1::text::uuid, 30)",
            &[&ca],
        )
        .unwrap()
        .get(0);
    // Nothing is left to purge.
    assert_eq!(purged, 0);
    let left: Vec<String> = owner
        .query(
            "SELECT challenge_id::text FROM status_change_challenge
             WHERE ca_id = $1::text::uuid ORDER BY challenge_id",
            &[&ca],
        )
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect();
    assert!(!left.contains(&old_unused));
    assert!(left.contains(&recent_unused) && left.contains(&consumed));
    let audited: i64 = owner
        .query_one(
            "SELECT count(*) FROM audit_event
             WHERE ca_id = $1::text::uuid AND event_type = 'challenge.purged'",
            &[&ca],
        )
        .unwrap()
        .get(0);
    assert_eq!(audited, 1);
}

/// Housekeeping reports CA-admin proposals past the CA's
/// `admin_proposal_max_age_hours` (migration 0054) and needs attention
/// until an admin rejects them; younger proposals do not count.
#[test]
fn housekeeping_reports_stale_admin_proposals() {
    let Some(url) = database_url() else { return };
    let mut lab = lab(&url);
    let ca = lab.ca_id.clone();
    let mut owner = Client::connect(&lab.url, NoTls).unwrap();
    let stale = lab
        .admin
        .propose_officer_grant(&ca, OfficerGrantAction::Grant, &THIRD, &ADMIN_A)
        .unwrap();
    lab.admin
        .propose_officer_grant(&ca, OfficerGrantAction::Revoke, &MAKER, &ADMIN_A)
        .unwrap();
    owner
        .batch_execute(&format!(
            "ALTER TABLE ca_admin_change DISABLE TRIGGER ca_admin_change_guard;
             UPDATE ca_admin_change SET proposed_at = proposed_at - interval '8 days'
             WHERE change_id = '{stale}';
             ALTER TABLE ca_admin_change ENABLE TRIGGER ca_admin_change_guard"
        ))
        .unwrap();
    let mut operator = Client::connect(&url_as(&url, "trust_crl_operator"), NoTls).unwrap();
    let listed: Vec<(String, String)> = operator
        .query(
            "SELECT family, change_id::text FROM stale_admin_proposals($1::text::uuid)",
            &[&ca],
        )
        .unwrap()
        .iter()
        .map(|row| (row.get(0), row.get(1)))
        .collect();
    assert_eq!(listed, [("CA_ADMIN".to_owned(), stale.clone())]);
    let mut housekeeping =
        PgRevocationStore::connect_lab(&url_as(&url, "trust_crl_operator")).unwrap();
    let report = housekeeping.crl_housekeeping(&ca, 3600, 3600).unwrap();
    assert_eq!(report.stale_admin_proposals, 1);
    assert!(report.needs_attention());
    // Rejected, it no longer counts.
    Client::connect(&url_as(&url, "trust_ca_admin"), NoTls)
        .unwrap()
        .execute(
            "SELECT reject_ca_admin_change($1::text::uuid, $2, $3)",
            &[&stale, &ADMIN_B.issuer, &ADMIN_B.subject],
        )
        .unwrap();
    let report = housekeeping.crl_housekeeping(&ca, 3600, 3600).unwrap();
    assert_eq!(report.stale_admin_proposals, 0);
}

/// Certificates stored before migration 0031 have no `not_after`, so they
/// are never pruned. Housekeeping backfills it (migration 0055): the Rust
/// core reads notAfter from the stored DER after checking its serial; the
/// value is then set once. A DER that does not parse or names another
/// serial is reported (and needs attention), never guessed.
#[test]
fn housekeeping_backfills_not_after_from_the_stored_der() {
    let Some(url) = database_url() else { return };
    let mut owner = Client::connect(&url, NoTls).unwrap();
    let ca: String = owner
        .query_one(
            "INSERT INTO ca(ca_id, display_name, policy_version)
             VALUES (gen_random_uuid(), 'Backfill CA', 'v1') RETURNING ca_id::text",
            &[],
        )
        .unwrap()
        .get(0);
    owner
        .execute(
            "INSERT INTO ca_revocation_policy(ca_id) VALUES ($1::text::uuid)",
            &[&ca],
        )
        .unwrap();
    let other = EphemeralLabCa::new("Sovereign Trust Lab Root").unwrap();
    let root = other.root_certificate();
    let der = x509_cert::der::Encode::to_der(root).unwrap();
    let serial = root.tbs_certificate.serial_number.as_bytes().to_vec();
    let expected = i64::try_from(
        root.tbs_certificate
            .validity
            .not_after
            .to_unix_duration()
            .as_secs(),
    )
    .unwrap();
    owner
        .execute(
            "WITH r AS (
                 INSERT INTO certificate_request(request_id, ca_id, idempotency_key, csr_sha256,
                     requester_id, policy_version, state)
                 VALUES (gen_random_uuid(), $1::text::uuid, 'backfill', sha256('csr-b'::bytea),
                         'requester', 'v1', 'PUBLISHED') RETURNING request_id),
             s AS (
                 INSERT INTO serial_reservation(ca_id, serial_der_content, request_id)
                 SELECT $1::text::uuid, $2, request_id FROM r RETURNING request_id)
             INSERT INTO certificate(ca_id, serial_der_content, request_id, fingerprint_sha256,
                 certificate_der, signed_at)
             SELECT $1::text::uuid, $2, request_id, sha256($3), $3,
                    to_timestamp($4::bigint) - interval '1 day'
             FROM s",
            &[&ca, &serial, &der, &expected],
        )
        .unwrap();
    // A certificate whose stored DER is not a certificate.
    owner
        .batch_execute(&format!(
            "INSERT INTO certificate_request(request_id, ca_id, idempotency_key, csr_sha256,
                 requester_id, policy_version, state)
                 VALUES (gen_random_uuid(), '{ca}', 'backfill-junk', sha256('csr-j'::bytea),
                         'requester', 'v1', 'PUBLISHED');
             INSERT INTO serial_reservation(ca_id, serial_der_content, request_id)
                 SELECT '{ca}', '\\x7f01', request_id FROM certificate_request
                 WHERE ca_id = '{ca}' AND idempotency_key = 'backfill-junk';
             INSERT INTO certificate(ca_id, serial_der_content, request_id, fingerprint_sha256,
                 certificate_der, signed_at)
                 SELECT ca_id, serial_der_content, request_id, sha256('junk'::bytea),
                        '\\x3003020101', now()
                 FROM serial_reservation
                 WHERE ca_id = '{ca}' AND serial_der_content = '\\x7f01';"
        ))
        .unwrap();
    let mut operator = PgRevocationStore::connect_lab(&url_as(&url, "trust_crl_operator")).unwrap();
    let report = operator.crl_housekeeping(&ca, 3600, 3600).unwrap();
    // The real certificate is backfilled; the placeholder DER is reported
    // as unreadable.
    assert_eq!(
        (report.backfilled_not_after, report.unreadable_certificates),
        (1, 1)
    );
    assert!(report.needs_attention());
    let stored: i64 = owner
        .query_one(
            "SELECT extract(epoch FROM not_after)::bigint FROM certificate
             WHERE ca_id = $1::text::uuid AND serial_der_content = $2",
            &[&ca, &serial],
        )
        .unwrap()
        .get(0);
    assert_eq!(stored, expected);
    let report = operator.crl_housekeeping(&ca, 3600, 3600).unwrap();
    assert_eq!(
        (report.backfilled_not_after, report.unreadable_certificates),
        (0, 1)
    );
    // Once set, not_after never changes, even for a superuser.
    let refused = owner
        .execute(
            "UPDATE certificate SET not_after = not_after + interval '1 day'
             WHERE ca_id = $1::text::uuid AND serial_der_content = $2",
            &[&ca, &serial],
        )
        .unwrap_err();
    assert_eq!(refused.code().map(|c| c.code()), Some("23514"));
    // A value that disagrees with nothing in the DER cannot be recorded for
    // another serial by a direct call either: the function only fills NULLs.
    let mut sql_operator = Client::connect(&url_as(&url, "trust_crl_operator"), NoTls).unwrap();
    let changed: bool = sql_operator
        .query_one(
            "SELECT record_certificate_not_after($1::text::uuid, $2, to_timestamp($3::bigint))",
            &[&ca, &serial, &(expected - 10)],
        )
        .unwrap()
        .get(0);
    assert!(!changed);
}

/// An admin key enrolled by a break-glass use whose evidence does not
/// re-verify (a forged emergency signature) signs nothing through the Rust
/// core; once the evidence is intact the same key signs normally.
#[test]
fn keys_from_unverifiable_breakglass_uses_cannot_sign() {
    let Some(url) = database_url() else { return };
    let mut lab = lab(&url);
    let ca = lab.ca_id.clone();
    let mut owner = Client::connect(&lab.url, NoTls).unwrap();
    let mut boot = PgRevocationStore::connect_lab(&lab.url).unwrap();
    let credential = |tag: u8| {
        let mut id = ca.replace('-', "").into_bytes();
        id.push(tag);
        id
    };
    let (b_id, bg_id, a_id) = (credential(4), credential(20), credential(11));
    let mut admin_b = Authenticator::new();
    boot.enroll_admin_credential(
        &ca,
        &b_id,
        &ADMIN_B,
        "person-admin-b",
        &admin_b.public_key(),
    )
    .unwrap();
    owner
        .execute(
            "UPDATE ca_revocation_policy SET signed_admin_required = true
             WHERE ca_id = $1::text::uuid",
            &[&ca],
        )
        .unwrap();
    let mut emergency = Authenticator::new();
    boot.enroll_breakglass_credential(
        &ca,
        &bg_id,
        "custodian",
        "person-custodian",
        &emergency.public_key(),
    )
    .unwrap();
    let mut admin_a = Authenticator::new();
    let a_key = admin_a.public_key();
    let content = CredentialContent {
        ca_id: &ca,
        credential_id: &a_id,
        officer: &ADMIN_A,
        person_id: "person-admin-a",
        public_key_sec1: &a_key,
    };
    let challenge = lab
        .admin
        .issue_breakglass_challenge(&bg_id, &content, 120)
        .unwrap();
    let use_id =
        breakglass_submit(&mut lab.admin, &mut emergency, &bg_id, &challenge, &content).unwrap();
    let flip = |owner: &mut Client| {
        owner
            .batch_execute(&format!(
                "ALTER TABLE breakglass_use DISABLE TRIGGER breakglass_use_guard;
                 UPDATE breakglass_use
                    SET signature_der = set_byte(signature_der, octet_length(signature_der) - 1,
                            get_byte(signature_der, octet_length(signature_der) - 1) # 1)
                  WHERE use_id = '{use_id}';
                 ALTER TABLE breakglass_use ENABLE TRIGGER breakglass_use_guard"
            ))
            .unwrap();
    };
    let grant = AdminChange::Officer(OfficerGrantAction::Grant, &THIRD);
    // Forged evidence: A's key is refused before anything is written.
    flip(&mut owner);
    let challenge = lab
        .admin
        .issue_admin_proposal_challenge(&ca, &grant, &ADMIN_A, 120)
        .unwrap();
    assert!(matches!(
        admin_submit(
            &mut lab.admin,
            &mut admin_a,
            &a_id,
            &challenge,
            Some(&grant)
        )
        .unwrap_err(),
        RevocationStoreError::SignedApprovalRefused
    ));
    // Restored evidence (flip the byte back): A signs; B approves as usual.
    flip(&mut owner);
    let change = admin_submit(
        &mut lab.admin,
        &mut admin_a,
        &a_id,
        &challenge,
        Some(&grant),
    )
    .unwrap();
    let approval = lab
        .admin
        .issue_admin_approval_challenge(AdminFamily::CaAdmin, &change, &ADMIN_B, 120)
        .unwrap();
    admin_submit(&mut lab.admin, &mut admin_b, &b_id, &approval, None).unwrap();
}

/// A proposal stored with a forged maker signature (sent straight to the
/// database, which cannot verify ECDSA) cannot be completed by an honest
/// checker: the Rust core re-verifies the maker's stored evidence before
/// the approval is written, and the change stays PROPOSED.
#[test]
fn approvals_reverify_the_makers_stored_signature() {
    let Some(url) = database_url() else { return };
    let mut lab = lab(&url);
    let challenge = lab.propose_challenge();
    let digest = lab
        .officer
        .signed_challenge(&challenge)
        .unwrap()
        .digest()
        .unwrap();
    let (data, client, _) = lab.maker.sign(&digest);
    let (_, _, forged) = Authenticator::new().sign(&digest);
    let mut direct = Client::connect(&url_as(&url, "trust_revocation_officer_api"), NoTls).unwrap();
    let change: String = direct
        .query_one(
            "SELECT propose_signed_status_change($1::text::uuid, $2, $3, $4, $5)::text",
            &[&challenge, &lab.maker_credential, &data, &client, &forged],
        )
        .unwrap()
        .get(0);
    let approval = challenge_for(&mut lab, &change);
    let refused = lab.submit(&approval, false, None).unwrap_err();
    assert!(
        matches!(refused, RevocationStoreError::InvalidAssertion(_)),
        "{refused:?}"
    );
    assert!(lab
        .officer
        .pending_status_changes(&lab.ca_id)
        .unwrap()
        .iter()
        .any(|pending| pending.change_id == change));
    assert_eq!(
        lab.officer.status(&lab.ca_id, &lab.serial).unwrap(),
        CertificateStatus::Valid
    );
}

/// The same for CA administration: a proposal stored with a forged maker
/// signature (straight to the database) is not approved through the Rust
/// core, which re-verifies the maker's stored evidence first.
#[test]
fn admin_approvals_reverify_the_makers_stored_signature() {
    let Some(url) = database_url() else { return };
    let mut lab = lab(&url);
    let ca = lab.ca_id.clone();
    let mut owner = Client::connect(&lab.url, NoTls).unwrap();
    let mut boot = PgRevocationStore::connect_lab(&lab.url).unwrap();
    let (mut admin_a, mut admin_b) = (Authenticator::new(), Authenticator::new());
    let credential = |tag: u8| {
        let mut id = ca.replace('-', "").into_bytes();
        id.push(tag);
        id
    };
    let (a_id, b_id) = (credential(3), credential(4));
    boot.enroll_admin_credential(
        &ca,
        &a_id,
        &ADMIN_A,
        "person-admin-a",
        &admin_a.public_key(),
    )
    .unwrap();
    boot.enroll_admin_credential(
        &ca,
        &b_id,
        &ADMIN_B,
        "person-admin-b",
        &admin_b.public_key(),
    )
    .unwrap();
    owner
        .execute(
            "UPDATE ca_revocation_policy SET signed_admin_required = true
             WHERE ca_id = $1::text::uuid",
            &[&ca],
        )
        .unwrap();
    let grant = AdminChange::Officer(OfficerGrantAction::Grant, &THIRD);
    let challenge = lab
        .admin
        .issue_admin_proposal_challenge(&ca, &grant, &ADMIN_A, 120)
        .unwrap();
    let digest = lab
        .admin
        .admin_challenge(&challenge)
        .unwrap()
        .claim
        .digest();
    let (data, client, _) = admin_a.sign(&digest);
    let (_, _, forged) = Authenticator::new().sign(&digest);
    let mut direct = Client::connect(&url_as(&url, "trust_ca_admin"), NoTls).unwrap();
    let change: String = direct
        .query_one(
            "SELECT propose_signed_admin_change($1::text::uuid, $2, $3, $4, $5,
                                                NULL, NULL, $6, $7, NULL, NULL)::text",
            &[
                &challenge,
                &a_id,
                &data,
                &client,
                &forged,
                &THIRD.issuer,
                &THIRD.subject,
            ],
        )
        .unwrap()
        .get(0);
    let approval = lab
        .admin
        .issue_admin_approval_challenge(AdminFamily::CaAdmin, &change, &ADMIN_B, 120)
        .unwrap();
    let refused = admin_submit(&mut lab.admin, &mut admin_b, &b_id, &approval, None).unwrap_err();
    assert!(
        matches!(refused, RevocationStoreError::InvalidAssertion(_)),
        "{refused:?}"
    );
    let granted: i64 = owner
        .query_one(
            "SELECT count(*) FROM revocation_officer_grant
             WHERE ca_id = $1::text::uuid AND subject = 'third'",
            &[&ca],
        )
        .unwrap()
        .get(0);
    assert_eq!(granted, 0);
}

/// A break-glass use whose stored evidence includes a forged first review
/// (sent straight to the database) is not closed by an honest second
/// review: the Rust core re-verifies the use's evidence before writing.
#[test]
fn breakglass_reviews_reverify_the_stored_evidence() {
    let Some(url) = database_url() else { return };
    let mut lab = lab(&url);
    let ca = lab.ca_id.clone();
    let mut owner = Client::connect(&lab.url, NoTls).unwrap();
    let mut boot = PgRevocationStore::connect_lab(&lab.url).unwrap();
    let credential = |tag: u8| {
        let mut id = ca.replace('-', "").into_bytes();
        id.push(tag);
        id
    };
    let (b_id, bg_id, a_id, c_id) = (
        credential(4),
        credential(20),
        credential(11),
        credential(13),
    );
    let (mut admin_a, mut admin_b, mut admin_c) = (
        Authenticator::new(),
        Authenticator::new(),
        Authenticator::new(),
    );
    boot.enroll_admin_credential(
        &ca,
        &b_id,
        &ADMIN_B,
        "person-admin-b",
        &admin_b.public_key(),
    )
    .unwrap();
    owner
        .batch_execute(&format!(
            "INSERT INTO ca_admin_grant(issuer, subject, ca_id) VALUES ('{ISSUER}', 'admin-c', '{ca}');
             UPDATE ca_revocation_policy SET signed_admin_required = true WHERE ca_id = '{ca}'"
        ))
        .unwrap();
    let mut emergency = Authenticator::new();
    boot.enroll_breakglass_credential(
        &ca,
        &bg_id,
        "custodian",
        "person-custodian",
        &emergency.public_key(),
    )
    .unwrap();
    let a_key = admin_a.public_key();
    let a_content = CredentialContent {
        ca_id: &ca,
        credential_id: &a_id,
        officer: &ADMIN_A,
        person_id: "person-admin-a",
        public_key_sec1: &a_key,
    };
    let challenge = lab
        .admin
        .issue_breakglass_challenge(&bg_id, &a_content, 120)
        .unwrap();
    let use_id = breakglass_submit(
        &mut lab.admin,
        &mut emergency,
        &bg_id,
        &challenge,
        &a_content,
    )
    .unwrap();
    // A proposes C's key, B approves: three admins with keys.
    let c_key = admin_c.public_key();
    let c_content = CredentialContent {
        ca_id: &ca,
        credential_id: &c_id,
        officer: &ADMIN_C,
        person_id: "person-admin-c",
        public_key_sec1: &c_key,
    };
    let enroll = AdminChange::AdminCredential(CredentialChangeKind::Enroll, &c_content);
    let proposal = lab
        .admin
        .issue_admin_proposal_challenge(&ca, &enroll, &ADMIN_A, 120)
        .unwrap();
    let change = admin_submit(
        &mut lab.admin,
        &mut admin_a,
        &a_id,
        &proposal,
        Some(&enroll),
    )
    .unwrap();
    let approval = lab
        .admin
        .issue_admin_approval_challenge(AdminFamily::AdminCredential, &change, &ADMIN_B, 120)
        .unwrap();
    admin_submit(&mut lab.admin, &mut admin_b, &b_id, &approval, None).unwrap();

    // B's review is forged straight in the database (another key signs).
    let review = lab
        .admin
        .issue_breakglass_review_challenge(&use_id, &ADMIN_B, 120)
        .unwrap();
    let digest = lab.admin.admin_challenge(&review).unwrap().claim.digest();
    let (data, client, _) = admin_b.sign(&digest);
    let (_, _, forged) = Authenticator::new().sign(&digest);
    let mut direct = Client::connect(&url_as(&url, "trust_ca_admin"), NoTls).unwrap();
    let first: String = direct
        .query_one(
            "SELECT review_breakglass_use($1::text::uuid, $2, $3, $4, $5)",
            &[&review, &b_id, &data, &client, &forged],
        )
        .unwrap()
        .get(0);
    assert_eq!(first, "PENDING_SECOND_REVIEW");
    // C's honest review does not close the use.
    let refused =
        breakglass_review(&mut lab.admin, &mut admin_c, &c_id, &use_id, &ADMIN_C).unwrap_err();
    assert!(
        matches!(refused, RevocationStoreError::InvalidAssertion(_)),
        "{refused:?}"
    );
    let uses = lab.admin.breakglass_uses(&ca).unwrap();
    assert!(!uses[0].reviewed);
}

/// The audit role lists every CA carrying signed evidence (migration
/// 0056), so one scheduled `signed_evidence_audit --all` covers them; a CA
/// without signatures is not listed.
#[test]
fn auditor_lists_the_cas_with_signed_evidence() {
    let Some(url) = database_url() else { return };
    let quiet = lab(&url);
    let mut signed = lab(&url);
    signed.signed_proposal();
    let mut auditor =
        PgRevocationStore::connect_lab(&url_as(&url, "trust_audit_verifier")).unwrap();
    let cas = auditor.evidence_cas().unwrap();
    assert!(cas.contains(&signed.ca_id));
    assert!(!cas.contains(&quiet.ca_id));
}

/// Signed submissions fail closed on an untrusted clock (ADR-0006
/// condition 6): when the database clock and the Rust core's disagree
/// beyond the bound, nothing is signed into the database (challenge
/// expiry, hold deadlines and review deadlines use the database clock).
#[test]
fn signed_submissions_refuse_a_skewed_database_clock() {
    let Some(url) = database_url() else { return };
    let mut lab = lab(&url);
    fn a_minute_ahead() -> i64 {
        trust_pki_core::clock::system_clock_us() + 60_000_000
    }
    let challenge = lab.propose_challenge();
    lab.officer.set_clock_source(a_minute_ahead);
    let refused = lab.submit(&challenge, true, None).unwrap_err();
    assert!(
        matches!(refused, RevocationStoreError::ClockSkew),
        "{refused:?}"
    );
    assert!(lab
        .officer
        .pending_status_changes(&lab.ca_id)
        .unwrap()
        .is_empty());
    // With the clocks agreeing again, the same challenge is still usable.
    lab.officer
        .set_clock_source(trust_pki_core::clock::system_clock_us);
    lab.submit(&challenge, true, None).unwrap();

    let grant = AdminChange::Officer(OfficerGrantAction::Grant, &THIRD);
    let ca = lab.ca_id.clone();
    let mut admin_a = Authenticator::new();
    let credential = |tag: u8| {
        let mut id = ca.replace('-', "").into_bytes();
        id.push(tag);
        id
    };
    let a_id = credential(3);
    PgRevocationStore::connect_lab(&lab.url)
        .unwrap()
        .enroll_admin_credential(
            &ca,
            &a_id,
            &ADMIN_A,
            "person-admin-a",
            &admin_a.public_key(),
        )
        .unwrap();
    let challenge = lab
        .admin
        .issue_admin_proposal_challenge(&ca, &grant, &ADMIN_A, 120)
        .unwrap();
    lab.admin.set_clock_source(a_minute_ahead);
    let refused = admin_submit(
        &mut lab.admin,
        &mut admin_a,
        &a_id,
        &challenge,
        Some(&grant),
    )
    .unwrap_err();
    assert!(
        matches!(refused, RevocationStoreError::ClockSkew),
        "{refused:?}"
    );
}
