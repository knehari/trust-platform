//! Officer credentials and the canonical status-change claim (ADR-0007,
//! proposed; lab only). Step 1 registers who may sign: a P-256 key bound to
//! an officer identity and a person (migration 0028). The claim below is
//! what officers will sign in step 2; nothing verifies signed approvals yet.

use sha2::{Digest, Sha256};
use trust_pki_crypto::canonical_p256_public_key_sec1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialError {
    /// Not a valid P-256 point in SEC1 form (compressed or uncompressed).
    InvalidPublicKey,
    /// A field is empty or out of the database's bounds.
    InvalidInput,
}

/// The one form an officer key is stored and compared in: compressed SEC1,
/// after checking the point is on the curve. Compressed and uncompressed
/// encodings of one key give the same bytes, so the database's uniqueness on
/// the key's SHA-256 holds whatever encoding an authenticator reports.
pub fn canonical_officer_key(public_key_sec1: &[u8]) -> Result<[u8; 33], CredentialError> {
    canonical_p256_public_key_sec1(public_key_sec1)
        .ok()
        .and_then(|key| key.try_into().ok())
        .ok_or(CredentialError::InvalidPublicKey)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialChangeKind {
    Enroll,
    Remove,
}

impl CredentialChangeKind {
    pub fn as_sql(self) -> &'static str {
        match self {
            Self::Enroll => "ENROLL_CREDENTIAL",
            Self::Remove => "REMOVE_CREDENTIAL",
        }
    }
}

/// The content a CA admin reviews and approves (migration 0028
/// `credential_change_digest`): SHA-256 of each field as a 4-byte
/// big-endian length and its bytes.
pub struct CredentialChange<'a> {
    pub kind: CredentialChangeKind,
    pub ca_id: [u8; 16],
    pub credential_id: &'a [u8],
    pub officer_issuer: &'a str,
    pub officer_subject: &'a str,
    pub person_id: &'a str,
    pub public_key: &'a [u8; 33],
}

impl CredentialChange<'_> {
    pub fn validate(&self) -> Result<(), CredentialError> {
        let ok = (16..=1023).contains(&self.credential_id.len())
            && (1..=1024).contains(&self.officer_issuer.chars().count())
            && (1..=512).contains(&self.officer_subject.chars().count())
            && (1..=256).contains(&self.person_id.chars().count());
        ok.then_some(()).ok_or(CredentialError::InvalidInput)
    }

    pub fn digest(&self) -> [u8; 32] {
        self.digest_with_kind(self.kind.as_sql())
    }

    /// The same digest under another change kind: CA-admin credential
    /// changes (migration 0040) use ENROLL_ / REMOVE_ADMIN_CREDENTIAL.
    pub fn digest_with_kind(&self, kind_sql: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for part in [
            kind_sql.as_bytes(),
            &self.ca_id,
            self.credential_id,
            self.officer_issuer.as_bytes(),
            self.officer_subject.as_bytes(),
            self.person_id.as_bytes(),
            self.public_key,
        ] {
            // Bounded by `validate` and the database (< 4 KiB).
            hasher.update((part.len() as u32).to_be_bytes());
            hasher.update(part);
        }
        hasher.finalize().into()
    }
}

/// The canonical claim an officer signs for a status change (ADR-0007 §2).
/// Its SHA-256 is the WebAuthn challenge; maker and checker sign the same
/// claim, so it names the change, the CA, the CA's registered issuer
/// certificate, the exact action and a single-use challenge with expiry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusChangeClaim {
    pub change_id: [u8; 16],
    pub ca_id: [u8; 16],
    pub issuer_certificate_sha256: [u8; 32],
    pub serial_der_content: Vec<u8>,
    /// SUSPEND, RELEASE, REVOKE or PRECAUTIONARY_SUSPEND.
    pub action: &'static str,
    /// CRL reason code, None for RELEASE.
    pub reason: Option<u8>,
    /// Microseconds since the Unix epoch.
    pub invalidity_date_us: Option<i64>,
    pub policy_edition: String,
    /// SHA-256 of the single-use challenge nonce (never the nonce itself).
    pub challenge_sha256: [u8; 32],
    /// Microseconds since the Unix epoch.
    pub expires_at_us: i64,
}

const STATUS_CHANGE_TAG: &[u8] = b"trust-platform/status-change/v1\0";

fn claim_field(out: &mut Vec<u8>, value: Option<&[u8]>) {
    match value {
        None => out.push(0),
        Some(bytes) => {
            out.push(1);
            // Fields are bounded (serial <= 20 bytes, edition <= 128 characters).
            out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            out.extend_from_slice(bytes);
        }
    }
}

impl StatusChangeClaim {
    /// Fail closed on anything the database would not accept either.
    pub fn validate(&self) -> Result<(), CredentialError> {
        let action_ok = match self.action {
            "RELEASE" => self.reason.is_none() && self.invalidity_date_us.is_none(),
            "SUSPEND" => self.reason == Some(6),
            // A single-officer precautionary hold (ADR-0007 §6, migration
            // 0036): its own action, so it is never an ordinary maker claim.
            "PRECAUTIONARY_SUSPEND" => self.reason == Some(6) && self.invalidity_date_us.is_none(),
            "REVOKE" => matches!(self.reason, Some(0..=5 | 9 | 10)),
            _ => false,
        };
        let ok = action_ok
            && (1..=20).contains(&self.serial_der_content.len())
            && (1..=128).contains(&self.policy_edition.chars().count());
        ok.then_some(()).ok_or(CredentialError::InvalidInput)
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = STATUS_CHANGE_TAG.to_vec();
        claim_field(&mut out, Some(&self.change_id));
        claim_field(&mut out, Some(&self.ca_id));
        claim_field(&mut out, Some(&self.issuer_certificate_sha256));
        claim_field(&mut out, Some(&self.serial_der_content));
        claim_field(&mut out, Some(self.action.as_bytes()));
        claim_field(&mut out, self.reason.as_ref().map(std::slice::from_ref));
        claim_field(
            &mut out,
            self.invalidity_date_us
                .map(i64::to_be_bytes)
                .as_ref()
                .map(|b| &b[..]),
        );
        claim_field(&mut out, Some(self.policy_edition.as_bytes()));
        claim_field(&mut out, Some(&self.challenge_sha256));
        claim_field(&mut out, Some(&self.expires_at_us.to_be_bytes()));
        out
    }

    /// The WebAuthn challenge for this claim.
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.canonical_bytes()).into()
    }

    /// The WebAuthn challenge for closing this change without applying it
    /// (`step` REJECT by a checker, WITHDRAW by the maker; migration 0039):
    /// its own tag and the step, so it never verifies as a maker or
    /// checker claim.
    pub fn closing_digest(&self, step: &str) -> Result<[u8; 32], CredentialError> {
        if !matches!(step, "REJECT" | "WITHDRAW") {
            return Err(CredentialError::InvalidInput);
        }
        let mut out = STATUS_CHANGE_CLOSE_TAG.to_vec();
        claim_field(&mut out, Some(step.as_bytes()));
        out.extend_from_slice(&self.canonical_bytes()[STATUS_CHANGE_TAG.len()..]);
        Ok(Sha256::digest(out).into())
    }
}

const STATUS_CHANGE_CLOSE_TAG: &[u8] = b"trust-platform/status-change-close/v1\0";

/// The canonical claim a CA admin signs for a CA-administration change
/// (ADR-0007 §2, `trust-platform/ca-admin/v1`, migration 0037): issuer
/// registration and officer grants (0024), officer credential enrolment and
/// removal (0028). Its SHA-256 is the WebAuthn challenge. A proposal claim
/// has no change id (the database allocates it; the signed content digest
/// and kind are checked against the created change), an approval claim
/// names the change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaAdminClaim {
    /// PROPOSE or APPROVE.
    pub step: &'static str,
    pub ca_id: [u8; 16],
    /// None before the CA's first issuer registration.
    pub issuer_certificate_sha256: Option<[u8; 32]>,
    /// CA_ADMIN, CREDENTIAL or ADMIN_CREDENTIAL (0040).
    pub family: &'static str,
    pub kind: &'static str,
    pub change_id: Option<[u8; 16]>,
    /// The digest the checker approves (0024 / 0028 content digests).
    pub content_sha256: [u8; 32],
    pub policy_edition: String,
    /// SHA-256 of the single-use challenge nonce.
    pub challenge_sha256: [u8; 32],
    /// Microseconds since the Unix epoch.
    pub expires_at_us: i64,
}

const CA_ADMIN_TAG: &[u8] = b"trust-platform/ca-admin/v1\0";

impl CaAdminClaim {
    /// Fail closed on anything the database would not accept either.
    pub fn validate(&self) -> Result<(), CredentialError> {
        let step_ok = match self.step {
            "PROPOSE" => self.change_id.is_none(),
            "APPROVE" => self.change_id.is_some(),
            _ => false,
        };
        let kind_ok = match self.family {
            "CA_ADMIN" => matches!(
                self.kind,
                "REGISTER_ISSUER" | "GRANT_OFFICER" | "REVOKE_OFFICER"
            ),
            "CREDENTIAL" => matches!(self.kind, "ENROLL_CREDENTIAL" | "REMOVE_CREDENTIAL"),
            "ADMIN_CREDENTIAL" => matches!(
                self.kind,
                "ENROLL_ADMIN_CREDENTIAL" | "REMOVE_ADMIN_CREDENTIAL"
            ),
            _ => false,
        };
        let ok = step_ok && kind_ok && (1..=128).contains(&self.policy_edition.chars().count());
        ok.then_some(()).ok_or(CredentialError::InvalidInput)
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = CA_ADMIN_TAG.to_vec();
        claim_field(&mut out, Some(self.step.as_bytes()));
        claim_field(&mut out, Some(&self.ca_id));
        claim_field(
            &mut out,
            self.issuer_certificate_sha256.as_ref().map(|d| &d[..]),
        );
        claim_field(&mut out, Some(self.family.as_bytes()));
        claim_field(&mut out, Some(self.kind.as_bytes()));
        claim_field(&mut out, self.change_id.as_ref().map(|c| &c[..]));
        claim_field(&mut out, Some(&self.content_sha256));
        claim_field(&mut out, Some(self.policy_edition.as_bytes()));
        claim_field(&mut out, Some(&self.challenge_sha256));
        claim_field(&mut out, Some(&self.expires_at_us.to_be_bytes()));
        out
    }

    /// The WebAuthn challenge for this claim.
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.canonical_bytes()).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // SEC1 encodings of the P-256 generator point.
    const G_UNCOMPRESSED: &str =
        "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296\
4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
    const G_COMPRESSED: &str = "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn one_key_has_one_canonical_form() {
        let a = canonical_officer_key(&hex(G_UNCOMPRESSED)).unwrap();
        let b = canonical_officer_key(&hex(G_COMPRESSED)).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.to_vec(), hex(G_COMPRESSED));
        let mut off_curve = hex(G_UNCOMPRESSED);
        off_curve[64] ^= 1;
        assert_eq!(
            canonical_officer_key(&off_curve),
            Err(CredentialError::InvalidPublicKey)
        );
        assert_eq!(
            canonical_officer_key(&[]),
            Err(CredentialError::InvalidPublicKey)
        );
    }

    #[test]
    fn credential_digest_is_length_prefixed() {
        let key = canonical_officer_key(&hex(G_COMPRESSED)).unwrap();
        let change = |subject, person| CredentialChange {
            kind: CredentialChangeKind::Enroll,
            ca_id: [7; 16],
            credential_id: &[1; 16],
            officer_issuer: "https://idp.lab.invalid",
            officer_subject: subject,
            person_id: person,
            public_key: &key,
        };
        assert!(change("maker", "person-1").validate().is_ok());
        assert!(change("", "person-1").validate().is_err());
        // Moving a character between adjacent fields changes the digest.
        assert_ne!(
            change("maker", "person-1").digest(),
            change("makerp", "erson-1").digest()
        );
    }

    fn claim() -> StatusChangeClaim {
        StatusChangeClaim {
            change_id: [1; 16],
            ca_id: [2; 16],
            issuer_certificate_sha256: [3; 32],
            serial_der_content: vec![0x01, 0x02],
            action: "REVOKE",
            reason: Some(1),
            invalidity_date_us: None,
            policy_edition: "v1".into(),
            challenge_sha256: [4; 32],
            expires_at_us: 1_792_533_719_000_000,
        }
    }

    #[test]
    fn claim_binds_every_field_and_validates() {
        let base = claim();
        assert!(base.validate().is_ok());
        assert!(base.canonical_bytes().starts_with(STATUS_CHANGE_TAG));
        let variants = [
            StatusChangeClaim {
                change_id: [9; 16],
                ..claim()
            },
            StatusChangeClaim {
                ca_id: [9; 16],
                ..claim()
            },
            StatusChangeClaim {
                issuer_certificate_sha256: [9; 32],
                ..claim()
            },
            StatusChangeClaim {
                serial_der_content: vec![0x01, 0x03],
                ..claim()
            },
            StatusChangeClaim {
                reason: Some(4),
                ..claim()
            },
            StatusChangeClaim {
                invalidity_date_us: Some(0),
                ..claim()
            },
            StatusChangeClaim {
                challenge_sha256: [9; 32],
                ..claim()
            },
            StatusChangeClaim {
                expires_at_us: 1,
                ..claim()
            },
        ];
        for variant in variants {
            assert_ne!(variant.digest(), base.digest(), "{variant:?}");
        }
        for invalid in [
            StatusChangeClaim {
                reason: Some(7),
                ..claim()
            },
            StatusChangeClaim {
                reason: None,
                ..claim()
            },
            StatusChangeClaim {
                action: "RELEASE",
                ..claim()
            },
            StatusChangeClaim {
                action: "SUSPEND",
                ..claim()
            },
            StatusChangeClaim {
                serial_der_content: vec![],
                ..claim()
            },
        ] {
            assert_eq!(invalid.validate(), Err(CredentialError::InvalidInput));
        }
    }

    /// A single-officer precautionary hold (ADR-0007 §6) signs a claim that
    /// cannot be mistaken for the maker half of an ordinary suspension.
    #[test]
    fn precautionary_suspension_is_a_distinct_claim() {
        let precaution = StatusChangeClaim {
            action: "PRECAUTIONARY_SUSPEND",
            reason: Some(6),
            ..claim()
        };
        assert_eq!(precaution.validate(), Ok(()));
        let ordinary = StatusChangeClaim {
            action: "SUSPEND",
            ..precaution.clone()
        };
        assert_ne!(precaution.digest(), ordinary.digest());
        for invalid in [
            StatusChangeClaim {
                reason: Some(1),
                ..precaution.clone()
            },
            StatusChangeClaim {
                invalidity_date_us: Some(1),
                ..precaution.clone()
            },
        ] {
            assert_eq!(invalid.validate(), Err(CredentialError::InvalidInput));
        }
    }

    fn admin_claim() -> CaAdminClaim {
        CaAdminClaim {
            step: "APPROVE",
            ca_id: [2; 16],
            issuer_certificate_sha256: Some([3; 32]),
            family: "CREDENTIAL",
            kind: "ENROLL_CREDENTIAL",
            change_id: Some([1; 16]),
            content_sha256: [5; 32],
            policy_edition: "v1".into(),
            challenge_sha256: [4; 32],
            expires_at_us: 1_792_533_719_000_000,
        }
    }

    /// Admin claims are domain-separated from status-change claims, bind
    /// every field, and only valid step/family/kind combinations pass.
    #[test]
    fn ca_admin_claims_bind_their_fields() {
        let claim = admin_claim();
        assert_eq!(claim.validate(), Ok(()));
        assert!(claim
            .canonical_bytes()
            .starts_with(b"trust-platform/ca-admin/v1\0"));
        let variants = [
            CaAdminClaim {
                issuer_certificate_sha256: None,
                ..claim.clone()
            },
            CaAdminClaim {
                kind: "REMOVE_CREDENTIAL",
                ..claim.clone()
            },
            CaAdminClaim {
                content_sha256: [6; 32],
                ..claim.clone()
            },
            CaAdminClaim {
                step: "PROPOSE",
                change_id: None,
                ..claim.clone()
            },
        ];
        for variant in &variants {
            assert_eq!(variant.validate(), Ok(()));
            assert_ne!(variant.digest(), claim.digest());
        }
        for invalid in [
            CaAdminClaim {
                change_id: None,
                ..claim.clone()
            },
            CaAdminClaim {
                step: "PROPOSE",
                ..claim.clone()
            },
            CaAdminClaim {
                family: "CA_ADMIN",
                ..claim.clone()
            },
            CaAdminClaim {
                policy_edition: String::new(),
                ..claim.clone()
            },
        ] {
            assert_eq!(invalid.validate(), Err(CredentialError::InvalidInput));
        }
    }

    /// Rejection and withdrawal claims differ from each other and from the
    /// maker/checker claim of the same change; other steps are refused.
    #[test]
    fn closing_claims_are_domain_separated() {
        let claim = claim();
        let reject = claim.closing_digest("REJECT").unwrap();
        let withdraw = claim.closing_digest("WITHDRAW").unwrap();
        assert_ne!(reject, withdraw);
        assert_ne!(reject, claim.digest());
        assert_ne!(withdraw, claim.digest());
        assert_eq!(
            claim.closing_digest("APPROVE"),
            Err(CredentialError::InvalidInput)
        );
    }
}
