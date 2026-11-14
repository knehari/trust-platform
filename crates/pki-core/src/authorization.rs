//! Signed registration decisions the laboratory signer verifies before it
//! signs (ADR-0028).
//!
//! An issuance is authorized by one of:
//! - a registered RA system's signed request
//!   (`ra_request::ra_issuance_message`, or its version 2);
//! - a registration officer's signed decision, over the claim below.
//!
//! The officer claim is text, so an officer can sign it with OpenSSL, as for
//! profile and CA decisions (ADR-0011, ADR-0014). The database builds it from
//! the stored application (`certificate_decision_claim`, migration 0041). The
//! signer and the audit tool rebuild it here from the same facts, so neither
//! the API nor the database can approve an issuance without the officer's key.
//!
//! The same holds for what a CRL lists (ADR-0029): an officer's approval of a
//! revocation request, and the officer's confirmation of a void (ADR-0020),
//! are signed claims too. RA-signed revocations are covered by
//! `ra_request::ra_revocation_message`.

/// A field that would break the claim's `key=value;` layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidClaimField;

/// What a registration officer signs to approve or reject an application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfficerDecision<'a> {
    /// `approve` or `reject`.
    pub decision: &'a str,
    /// Lowercase hyphenated UUIDs.
    pub ca_id: &'a str,
    pub application_id: &'a str,
    pub profile_id: &'a str,
    pub revision: i32,
    pub csr_sha256: &'a [u8; 32],
    /// The certificate's subject CN and names, as the application records them.
    pub subject_cn: &'a str,
    pub dns_names: &'a [String],
    pub validity_days: i32,
    /// Optional extensions, in catalogue order (`application_leaf`).
    pub extensions: &'a [String],
    /// The officer's registered key.
    pub key_id: &'a str,
    /// Exactly as the database formatted it: `YYYY-MM-DDTHH:MM:SS.mmmZ`.
    pub issued_at: &'a str,
}

fn plain(value: &str) -> Result<&str, InvalidClaimField> {
    if value.is_empty() || value.contains([';', '=', ',']) || value.chars().any(char::is_control) {
        return Err(InvalidClaimField);
    }
    Ok(value)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The claim text (version 1), byte for byte what the officer signs.
pub fn officer_decision_claim(decision: &OfficerDecision<'_>) -> Result<String, InvalidClaimField> {
    if !matches!(decision.decision, "approve" | "reject") {
        return Err(InvalidClaimField);
    }
    let names = decision
        .dns_names
        .iter()
        .map(|name| plain(name))
        .collect::<Result<Vec<_>, _>>()?
        .join(",");
    let extensions = decision
        .extensions
        .iter()
        .map(|extension| plain(extension))
        .collect::<Result<Vec<_>, _>>()?
        .join(",");
    Ok(format!(
        "trust-platform/issuance-authorization/v1;decision={};ca={};application={};profile={};\
         revision={};csr_sha256={};subject_cn={};dns_names={};validity_days={};extensions={};\
         key={};issued_at={}",
        decision.decision,
        plain(decision.ca_id)?,
        plain(decision.application_id)?,
        plain(decision.profile_id)?,
        decision.revision,
        hex(decision.csr_sha256),
        plain(decision.subject_cn)?,
        names,
        decision.validity_days,
        extensions,
        plain(decision.key_id)?,
        plain(decision.issued_at)?,
    ))
}

/// What a registration officer signs to approve or reject a revocation
/// request. The free-text reason is not part of it; the reason code is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationDecision<'a> {
    /// `approve` or `reject`.
    pub decision: &'a str,
    pub ca_id: &'a str,
    pub application_id: &'a str,
    pub revocation_id: &'a str,
    /// The serial's DER content octets.
    pub serial: &'a [u8],
    /// RFC 5280 reason code.
    pub reason_code: i16,
    pub key_id: &'a str,
    pub issued_at: &'a str,
}

/// The revocation claim text (version 1).
pub fn revocation_decision_claim(
    decision: &RevocationDecision<'_>,
) -> Result<String, InvalidClaimField> {
    if !matches!(decision.decision, "approve" | "reject") || decision.serial.is_empty() {
        return Err(InvalidClaimField);
    }
    Ok(format!(
        "trust-platform/revocation-authorization/v1;decision={};ca={};application={};\
         revocation={};serial={};reason_code={};key={};issued_at={}",
        decision.decision,
        plain(decision.ca_id)?,
        plain(decision.application_id)?,
        plain(decision.revocation_id)?,
        hex(decision.serial),
        decision.reason_code,
        plain(decision.key_id)?,
        plain(decision.issued_at)?,
    ))
}

/// What the second registration officer signs to confirm a proposed void:
/// the serial is listed on every later CRL (ADR-0020).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoidConfirmation<'a> {
    pub ca_id: &'a str,
    pub application_id: &'a str,
    pub serial: &'a [u8],
    /// Whether the signer had claimed the ambiguous intent.
    pub signer_claimed: bool,
    pub key_id: &'a str,
    pub issued_at: &'a str,
}

/// The void confirmation claim text (version 1).
pub fn void_confirmation_claim(void: &VoidConfirmation<'_>) -> Result<String, InvalidClaimField> {
    if void.serial.is_empty() {
        return Err(InvalidClaimField);
    }
    Ok(format!(
        "trust-platform/void-authorization/v1;ca={};application={};serial={};signer_claimed={};\
         key={};issued_at={}",
        plain(void.ca_id)?,
        plain(void.application_id)?,
        hex(void.serial),
        void.signer_claimed,
        plain(void.key_id)?,
        plain(void.issued_at)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names() -> Vec<String> {
        vec!["www.lab.invalid".into(), "api.lab.invalid".into()]
    }

    fn decision<'a>(names: &'a [String], extensions: &'a [String]) -> OfficerDecision<'a> {
        OfficerDecision {
            decision: "approve",
            ca_id: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
            application_id: "11111111-1111-4111-8111-111111111111",
            profile_id: "server",
            revision: 1,
            csr_sha256: &[0xab; 32],
            subject_cn: "www.lab.invalid",
            dns_names: names,
            validity_days: 30,
            extensions,
            key_id: "lab-ra-officer",
            issued_at: "2026-11-11T09:00:00.000Z",
        }
    }

    // tests/management_authorization_proofs.sql asserts the same text.
    #[test]
    fn claim_matches_the_database() {
        let names = names();
        let extensions = vec!["client-auth".to_owned()];
        assert_eq!(
            officer_decision_claim(&decision(&names, &extensions)).unwrap(),
            "trust-platform/issuance-authorization/v1;decision=approve;\
             ca=dddddddd-dddd-4ddd-8ddd-dddddddddddd;application=11111111-1111-4111-8111-111111111111;\
             profile=server;revision=1;\
             csr_sha256=abababababababababababababababababababababababababababababababab;\
             subject_cn=www.lab.invalid;dns_names=www.lab.invalid,api.lab.invalid;validity_days=30;\
             extensions=client-auth;key=lab-ra-officer;issued_at=2026-11-11T09:00:00.000Z"
        );
        let none: Vec<String> = Vec::new();
        assert!(officer_decision_claim(&decision(&names, &none))
            .unwrap()
            .contains(";extensions=;key="));
    }

    #[test]
    fn fields_cannot_forge_the_layout() {
        let names = names();
        let none: Vec<String> = Vec::new();
        let base = decision(&names, &none);
        let injected = vec!["www.lab.invalid;decision=approve".to_owned()];
        for bad in [
            OfficerDecision {
                decision: "maybe",
                ..base.clone()
            },
            OfficerDecision {
                subject_cn: "a=b",
                ..base.clone()
            },
            OfficerDecision {
                key_id: "k;x",
                ..base.clone()
            },
            OfficerDecision {
                profile_id: "",
                ..base.clone()
            },
            OfficerDecision {
                dns_names: &injected,
                ..base.clone()
            },
        ] {
            assert_eq!(
                officer_decision_claim(&bad),
                Err(InvalidClaimField),
                "{bad:?}"
            );
        }
    }

    // tests/management_revocation_proofs.sql asserts the same texts.
    #[test]
    fn revocation_and_void_claims_match_the_database() {
        let revocation = RevocationDecision {
            decision: "approve",
            ca_id: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
            application_id: "11111111-1111-4111-8111-111111111111",
            revocation_id: "22222222-2222-4222-8222-222222222222",
            serial: &[0x0a, 0xff],
            reason_code: 1,
            key_id: "lab-ra-officer-p256",
            issued_at: "2026-11-11T09:00:00.000Z",
        };
        assert_eq!(
            revocation_decision_claim(&revocation).unwrap(),
            "trust-platform/revocation-authorization/v1;decision=approve;\
             ca=dddddddd-dddd-4ddd-8ddd-dddddddddddd;application=11111111-1111-4111-8111-111111111111;\
             revocation=22222222-2222-4222-8222-222222222222;serial=0aff;reason_code=1;\
             key=lab-ra-officer-p256;issued_at=2026-11-11T09:00:00.000Z"
        );
        let void = VoidConfirmation {
            ca_id: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
            application_id: "11111111-1111-4111-8111-111111111111",
            serial: &[0x0a, 0xff],
            signer_claimed: false,
            key_id: "lab-ra-officer-2-p256",
            issued_at: "2026-11-11T09:00:00.000Z",
        };
        assert_eq!(
            void_confirmation_claim(&void).unwrap(),
            "trust-platform/void-authorization/v1;ca=dddddddd-dddd-4ddd-8ddd-dddddddddddd;\
             application=11111111-1111-4111-8111-111111111111;serial=0aff;signer_claimed=false;\
             key=lab-ra-officer-2-p256;issued_at=2026-11-11T09:00:00.000Z"
        );
        for bad in [
            RevocationDecision {
                decision: "revoke",
                ..revocation.clone()
            },
            RevocationDecision {
                serial: &[],
                ..revocation.clone()
            },
            RevocationDecision {
                key_id: "a;b",
                ..revocation.clone()
            },
        ] {
            assert_eq!(revocation_decision_claim(&bad), Err(InvalidClaimField));
        }
        assert_eq!(
            void_confirmation_claim(&VoidConfirmation {
                issued_at: "x=y",
                ..void
            }),
            Err(InvalidClaimField)
        );
    }
}
