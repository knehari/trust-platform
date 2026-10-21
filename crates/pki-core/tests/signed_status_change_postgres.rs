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
    officer_credential::CredentialChangeKind,
    revocation::{CertificateStatus, OfficerIdentity, RevocationReason, StatusAction},
    revocation_store::{CredentialContent, PgRevocationStore, RevocationStoreError},
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
            .claim
            .digest();
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
