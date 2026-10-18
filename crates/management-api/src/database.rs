//! PostgreSQL connection target for the management API.
//!
//! TLS is required by default (SEC-03/D-03): the server certificate must chain
//! to an operator-supplied CA bundle and match the configured host name. System
//! trust roots are deliberately not used for a private PKI database. Plaintext
//! is available only through an explicit, logged laboratory opt-out.

use postgres::{config::SslMode, Client, NoTls};
use rustls::{
    crypto::ring,
    pki_types::{pem::PemObject, CertificateDer},
    ClientConfig, RootCertStore,
};
use std::{path::Path, sync::Arc, time::Duration};
use tokio_postgres_rustls::MakeRustlsConnect;

pub const TLS_MODE_ENV: &str = "TRUST_DATABASE_TLS";
pub const CA_FILE_ENV: &str = "TRUST_DATABASE_CA_FILE";
const VERIFY_FULL: &str = "verify-full";
const DISABLE_LAB: &str = "disable-lab";

#[derive(Clone)]
pub enum DatabaseTls {
    /// TLS 1.3 with certificate chain and host name verification.
    VerifyFull(Arc<ClientConfig>),
    /// Plaintext; only for disposable laboratory databases.
    DisabledForLab,
}

#[derive(Clone)]
pub struct Database {
    pub url: String,
    pub tls: DatabaseTls,
}

impl Database {
    #[cfg(test)]
    pub fn lab_plaintext(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            tls: DatabaseTls::DisabledForLab,
        }
    }

    pub fn connect(&self, statement_timeout_ms: u64) -> Result<Client, ()> {
        let mut config: postgres::Config = self.url.parse().map_err(|_| ())?;
        config.connect_timeout(Duration::from_secs(3));
        // Apply the limit at session startup so every management read, including
        // startup checks, is bounded even after the connection succeeds.
        config.options(&format!("-c statement_timeout={statement_timeout_ms}"));
        match &self.tls {
            DatabaseTls::VerifyFull(tls) => {
                // Override any sslmode in the URL: "prefer" would silently fall
                // back to plaintext when the server does not offer TLS.
                config.ssl_mode(SslMode::Require);
                config
                    .connect(MakeRustlsConnect::new(ClientConfig::clone(tls)))
                    .map_err(|_| ())
            }
            DatabaseTls::DisabledForLab => {
                config.ssl_mode(SslMode::Disable);
                config.connect(NoTls).map_err(|_| ())
            }
        }
    }
}

/// Reads the TLS policy from `TRUST_DATABASE_TLS` (default `verify-full`) and
/// `TRUST_DATABASE_CA_FILE`. Unknown modes and missing CA bundles fail closed.
pub fn tls_from_settings(mode: Option<&str>, ca_file: Option<&str>) -> Result<DatabaseTls, String> {
    match mode.unwrap_or(VERIFY_FULL) {
        VERIFY_FULL => {
            let path = ca_file
                .filter(|path| !path.is_empty())
                .ok_or_else(|| format!("{TLS_MODE_ENV}={VERIFY_FULL} requires {CA_FILE_ENV}"))?;
            Ok(DatabaseTls::VerifyFull(Arc::new(verify_full_config(
                Path::new(path),
            )?)))
        }
        DISABLE_LAB => Ok(DatabaseTls::DisabledForLab),
        _ => Err(format!(
            "{TLS_MODE_ENV} must be {VERIFY_FULL} or {DISABLE_LAB}"
        )),
    }
}

fn verify_full_config(ca_file: &Path) -> Result<ClientConfig, String> {
    let mut roots = RootCertStore::empty();
    for certificate in
        CertificateDer::pem_file_iter(ca_file).map_err(|_| format!("cannot read {CA_FILE_ENV}"))?
    {
        let certificate = certificate.map_err(|_| format!("invalid PEM in {CA_FILE_ENV}"))?;
        roots
            .add(certificate)
            .map_err(|_| format!("invalid CA certificate in {CA_FILE_ENV}"))?;
    }
    if roots.is_empty() {
        return Err(format!("{CA_FILE_ENV} contains no CA certificate"));
    }
    Ok(
        ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| "TLS 1.3 unavailable".to_string())?
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{env, fs};

    fn temp_file(name: &str, contents: &str) -> std::path::PathBuf {
        let path = env::temp_dir().join(format!("trust-db-tls-{}-{name}", std::process::id()));
        fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn tls_is_required_by_default_and_needs_a_ca_bundle() {
        let error = tls_from_settings(None, None).err().unwrap();
        assert!(error.contains(CA_FILE_ENV), "{error}");
        assert!(tls_from_settings(Some("verify-full"), Some("")).is_err());
    }

    #[test]
    fn only_the_explicit_lab_opt_out_disables_tls() {
        assert!(matches!(
            tls_from_settings(Some("disable-lab"), None),
            Ok(DatabaseTls::DisabledForLab)
        ));
        for mode in ["disable", "prefer", "require", "", "VERIFY-FULL"] {
            assert!(tls_from_settings(Some(mode), None).is_err(), "{mode}");
        }
    }

    #[test]
    fn unreadable_empty_or_invalid_ca_bundles_fail_closed() {
        assert!(tls_from_settings(None, Some("/nonexistent/trust-ca.pem")).is_err());
        let empty = temp_file("empty.pem", "");
        assert!(tls_from_settings(None, empty.to_str()).is_err());
        let garbage = temp_file(
            "garbage.pem",
            "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
        );
        assert!(tls_from_settings(None, garbage.to_str()).is_err());
        let _ = fs::remove_file(empty);
        let _ = fs::remove_file(garbage);
    }

    /// Requires a TLS-enabled PostgreSQL whose certificate names `localhost`
    /// only. CI supplies the variables; locally the test is skipped without them.
    #[test]
    fn verify_full_connects_only_to_a_trusted_matching_server() {
        let (Ok(url), Ok(ca_file), Ok(untrusted_ca)) = (
            env::var("TRUST_API_TLS_TEST_DATABASE_URL"),
            env::var("TRUST_API_TLS_TEST_CA_FILE"),
            env::var("TRUST_API_TLS_TEST_UNTRUSTED_CA_FILE"),
        ) else {
            assert_ne!(
                env::var("TRUST_REQUIRE_DATABASE").as_deref(),
                Ok("1"),
                "TRUST_API_TLS_TEST_* variables are required for the TLS integration test"
            );
            return;
        };
        let tls = tls_from_settings(None, Some(&ca_file)).unwrap();
        // sslmode=disable in the URL must not downgrade verify-full.
        let trusted = Database {
            url: format!("{url}?sslmode=disable"),
            tls: tls.clone(),
        };
        let mut client = trusted.connect(3_000).expect("verified TLS connection");
        let encrypted: bool = client
            .query_one(
                "SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()",
                &[],
            )
            .unwrap()
            .get(0);
        assert!(encrypted);

        // A root unrelated to the server certificate must be rejected.
        let untrusted = Database {
            url: url.clone(),
            tls: tls_from_settings(None, Some(&untrusted_ca)).unwrap(),
        };
        assert!(untrusted.connect(3_000).is_err());

        // The trusted chain presented for another host name must be rejected.
        let wrong_host = Database {
            url: url.replacen("@localhost:", "@127.0.0.1:", 1),
            tls,
        };
        assert_ne!(wrong_host.url, url, "test URL must use host localhost");
        assert!(wrong_host.connect(3_000).is_err());
    }
}
