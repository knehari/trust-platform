//! Typed certificate status vocabulary for the lab revocation slice.
//!
//! Lab rules only: the database (migration 0014) re-checks every one of them.
//! Accepted reason codes are 0-6, 9 and 10; 7 does not exist and 8
//! (`removeFromCRL`) is always rejected.

use crate::revocation_policy::StatusChangeError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationReason {
    Unspecified,
    KeyCompromise,
    CaCompromise,
    AffiliationChanged,
    Superseded,
    CessationOfOperation,
    CertificateHold,
    PrivilegeWithdrawn,
    AaCompromise,
}

impl RevocationReason {
    pub fn code(self) -> i16 {
        match self {
            Self::Unspecified => 0,
            Self::KeyCompromise => 1,
            Self::CaCompromise => 2,
            Self::AffiliationChanged => 3,
            Self::Superseded => 4,
            Self::CessationOfOperation => 5,
            Self::CertificateHold => 6,
            Self::PrivilegeWithdrawn => 9,
            Self::AaCompromise => 10,
        }
    }

    pub fn from_code(code: i16) -> Result<Self, StatusChangeError> {
        match code {
            0 => Ok(Self::Unspecified),
            1 => Ok(Self::KeyCompromise),
            2 => Ok(Self::CaCompromise),
            3 => Ok(Self::AffiliationChanged),
            4 => Ok(Self::Superseded),
            5 => Ok(Self::CessationOfOperation),
            6 => Ok(Self::CertificateHold),
            9 => Ok(Self::PrivilegeWithdrawn),
            10 => Ok(Self::AaCompromise),
            _ => Err(StatusChangeError::UnknownReason),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusAction {
    Suspend,
    Release,
    Revoke,
}

impl StatusAction {
    pub fn as_sql(self) -> &'static str {
        match self {
            Self::Suspend => "SUSPEND",
            Self::Release => "RELEASE",
            Self::Revoke => "REVOKE",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateStatus {
    Valid,
    Suspended,
    Revoked,
}

impl CertificateStatus {
    pub fn from_sql(value: &str) -> Option<Self> {
        match value {
            "VALID" => Some(Self::Valid),
            "SUSPENDED" => Some(Self::Suspended),
            "REVOKED" => Some(Self::Revoked),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConformanceTarget {
    Rfc5280,
    EtsiEn319411_1,
    EtsiEn319411_2,
}

impl ConformanceTarget {
    pub fn as_sql(self) -> &'static str {
        match self {
            Self::Rfc5280 => "RFC5280",
            Self::EtsiEn319411_1 => "ETSI_EN_319_411_1",
            Self::EtsiEn319411_2 => "ETSI_EN_319_411_2",
        }
    }
}

/// An authenticated officer, identified by the `(issuer, subject)` pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OfficerIdentity<'a> {
    pub issuer: &'a str,
    pub subject: &'a str,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::revocation_policy::StatusChangeError;

    pub(crate) const ALL: [RevocationReason; 9] = [
        RevocationReason::Unspecified,
        RevocationReason::KeyCompromise,
        RevocationReason::CaCompromise,
        RevocationReason::AffiliationChanged,
        RevocationReason::Superseded,
        RevocationReason::CessationOfOperation,
        RevocationReason::CertificateHold,
        RevocationReason::PrivilegeWithdrawn,
        RevocationReason::AaCompromise,
    ];

    #[test]
    fn reason_codes_round_trip_and_reject_7_8_and_out_of_range() {
        for r in ALL {
            assert_eq!(RevocationReason::from_code(r.code()), Ok(r));
        }
        for bad in [7, 8, -1, 11] {
            assert_eq!(
                RevocationReason::from_code(bad),
                Err(StatusChangeError::UnknownReason)
            );
        }
    }

    #[test]
    fn sql_names() {
        assert_eq!(StatusAction::Suspend.as_sql(), "SUSPEND");
        assert_eq!(StatusAction::Release.as_sql(), "RELEASE");
        assert_eq!(StatusAction::Revoke.as_sql(), "REVOKE");
        assert_eq!(
            CertificateStatus::from_sql("VALID"),
            Some(CertificateStatus::Valid)
        );
        assert_eq!(
            CertificateStatus::from_sql("SUSPENDED"),
            Some(CertificateStatus::Suspended)
        );
        assert_eq!(
            CertificateStatus::from_sql("REVOKED"),
            Some(CertificateStatus::Revoked)
        );
        assert_eq!(CertificateStatus::from_sql("valid"), None);
        assert_eq!(ConformanceTarget::Rfc5280.as_sql(), "RFC5280");
        assert_eq!(
            ConformanceTarget::EtsiEn319411_1.as_sql(),
            "ETSI_EN_319_411_1"
        );
        assert_eq!(
            ConformanceTarget::EtsiEn319411_2.as_sql(),
            "ETSI_EN_319_411_2"
        );
        let o = OfficerIdentity {
            issuer: "i",
            subject: "s",
        };
        assert_eq!((o.issuer, o.subject), ("i", "s"));
    }
}
