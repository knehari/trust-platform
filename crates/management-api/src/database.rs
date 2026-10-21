//! PostgreSQL connection target for the management API.
//!
//! TLS is required by default (SEC-03/D-03): the server certificate must chain
//! to an operator-supplied CA bundle and match the configured host name. System
//! trust roots are deliberately not used for a private PKI database. Plaintext
//! is available only through an explicit, logged laboratory opt-out.
//!
//! Connections are reused through a small idle cache. Concurrency stays bounded
//! by the caller's semaphores; the cache only avoids a TCP + TLS + SCRAM
//! handshake per request. The management API issues read-only SELECTs without
//! session state, so reusing a session cannot leak state between requests.

use postgres::{config::SslMode, Client, NoTls};
use rustls::{
    crypto::ring,
    pki_types::{pem::PemObject, CertificateDer},
    ClientConfig, RootCertStore,
};
use std::{
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio_postgres_rustls::MakeRustlsConnect;

pub const TLS_MODE_ENV: &str = "TRUST_DATABASE_TLS";
pub const CA_FILE_ENV: &str = "TRUST_DATABASE_CA_FILE";
const VERIFY_FULL: &str = "verify-full";
const DISABLE_LAB: &str = "disable-lab";
/// Idle sessions older than this are closed instead of reused, which bounds how
/// long a credential rotation or server-side change can take to apply.
const MAX_IDLE_AGE: Duration = Duration::from_secs(30);

#[derive(Clone)]
pub enum DatabaseTls {
    /// TLS 1.3 with certificate chain and host name verification.
    VerifyFull(Arc<ClientConfig>),
    /// Plaintext; only for disposable laboratory databases.
    DisabledForLab,
}

struct IdleClient {
    client: Client,
    since: Instant,
}

#[derive(Default)]
struct IdleCache(Vec<IdleClient>);

impl Drop for IdleCache {
    fn drop(&mut self) {
        let sessions = std::mem::take(&mut self.0);
        // Dropping a postgres::Client blocks on its internal runtime, which
        // panics on an async worker thread (e.g. when the last AppState clone
        // goes away). Close cached sessions on a plain thread in that case.
        if !sessions.is_empty() && tokio::runtime::Handle::try_current().is_ok() {
            let _ = std::thread::Builder::new()
                .name("trust-db-idle-close".into())
                .spawn(move || drop(sessions));
        }
    }
}

/// Clones share one idle cache.
#[derive(Clone)]
pub struct Database {
    pub url: String,
    pub tls: DatabaseTls,
    max_idle: usize,
    idle: Arc<Mutex<IdleCache>>,
}

impl Database {
    pub fn new(url: impl Into<String>, tls: DatabaseTls, max_idle: usize) -> Self {
        Self {
            url: url.into(),
            tls,
            max_idle,
            idle: Arc::default(),
        }
    }

    #[cfg(test)]
    pub fn lab_plaintext(url: impl Into<String>) -> Self {
        Self::new(url, DatabaseTls::DisabledForLab, 2)
    }

    /// Runs `query` on a reused idle session or a new one. A session is put
    /// back only after success; any error discards it. A reused session found
    /// closed by the server (restart, idle timeout) is retried once on a new
    /// connection; that is safe because callers only run read-only queries.
    pub fn run<T>(
        &self,
        statement_timeout_ms: u64,
        mut query: impl FnMut(&mut Client) -> Result<T, postgres::Error>,
    ) -> Result<T, ()> {
        if let Some(mut client) = self.take_idle() {
            match query(&mut client) {
                Ok(value) => {
                    self.put_idle(client);
                    return Ok(value);
                }
                Err(_) if client.is_closed() => {}
                Err(_) => return Err(()),
            }
        }
        let mut client = self.connect(statement_timeout_ms)?;
        let value = query(&mut client).map_err(|_| ())?;
        self.put_idle(client);
        Ok(value)
    }

    fn take_idle(&self) -> Option<Client> {
        let mut idle = self
            .idle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        while let Some(entry) = idle.0.pop() {
            if entry.since.elapsed() < MAX_IDLE_AGE && !entry.client.is_closed() {
                return Some(entry.client);
            }
        }
        None
    }

    fn put_idle(&self, client: Client) {
        let mut idle = self
            .idle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if idle.0.len() < self.max_idle && !client.is_closed() {
            idle.0.push(IdleClient {
                client,
                since: Instant::now(),
            });
        }
    }

    #[cfg(test)]
    fn idle_count(&self) -> usize {
        self.idle.lock().unwrap().0.len()
    }

    fn connect(&self, statement_timeout_ms: u64) -> Result<Client, ()> {
        connect_client(&self.url, &self.tls, statement_timeout_ms)
    }
}

/// One session under `tls`, with a connect timeout and a session statement
/// timeout. Shared by the management API and the lab service binaries
/// (CRL distribution, revocation API) so they all apply the same policy.
pub fn connect_client(
    url: &str,
    tls: &DatabaseTls,
    statement_timeout_ms: u64,
) -> Result<Client, ()> {
    let mut config: postgres::Config = url.parse().map_err(|_| ())?;
    config.connect_timeout(Duration::from_secs(3));
    // Apply the limit at session startup so every read, including startup
    // checks, is bounded even after the connection succeeds.
    config.options(&format!("-c statement_timeout={statement_timeout_ms}"));
    match tls {
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

    fn backend_pid(db: &Database) -> Result<i32, ()> {
        db.run(3_000, |client| {
            client
                .query_one("SELECT pg_backend_pid()", &[])
                .map(|row| row.get::<_, i32>(0))
        })
    }

    /// Uses the restricted CI login (TRUST_API_TEST_DATABASE_URL).
    #[test]
    fn idle_sessions_are_reused_discarded_on_error_and_bounded() {
        let Ok(url) = env::var("TRUST_API_TEST_DATABASE_URL") else {
            assert_ne!(
                env::var("TRUST_REQUIRE_DATABASE").as_deref(),
                Ok("1"),
                "TRUST_API_TEST_DATABASE_URL is required when TRUST_REQUIRE_DATABASE=1"
            );
            return;
        };
        let db = Database::lab_plaintext(url.clone());

        // Success returns the session to the cache and the next call reuses it.
        let first = backend_pid(&db).unwrap();
        assert_eq!(db.idle_count(), 1);
        assert_eq!(backend_pid(&db).unwrap(), first);

        // A failed query discards the session instead of caching it.
        assert!(db
            .run(3_000, |client| client
                .query_one("SELECT 1/0", &[])
                .map(|_| ()))
            .is_err());
        assert_eq!(db.idle_count(), 0);
        let second = backend_pid(&db).unwrap();
        assert_ne!(second, first);

        // A cached session closed by the server is retried once on a new one.
        let mut admin = Database::lab_plaintext(url).connect(3_000).unwrap();
        admin
            .execute("SELECT pg_terminate_backend($1)", &[&second])
            .unwrap();
        let third = backend_pid(&db).unwrap();
        assert_ne!(third, second);

        // Concurrent callers each get a session, but at most max_idle stay cached.
        std::thread::scope(|scope| {
            for _ in 0..4 {
                scope.spawn(|| {
                    db.run(3_000, |client| client.execute("SELECT pg_sleep(0.2)", &[]))
                        .unwrap();
                });
            }
        });
        assert_eq!(db.idle_count(), 2);
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
        let trusted = Database::new(format!("{url}?sslmode=disable"), tls.clone(), 1);
        let encrypted = trusted
            .run(3_000, |db| {
                db.query_one(
                    "SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()",
                    &[],
                )
                .map(|row| row.get::<_, bool>(0))
            })
            .expect("verified TLS connection");
        assert!(encrypted);

        // A root unrelated to the server certificate must be rejected.
        let untrusted = Database::new(
            url.clone(),
            tls_from_settings(None, Some(&untrusted_ca)).unwrap(),
            1,
        );
        assert!(untrusted.connect(3_000).is_err());

        // The trusted chain presented for another host name must be rejected.
        let wrong_host = Database::new(url.replacen("@localhost:", "@127.0.0.1:", 1), tls, 1);
        assert_ne!(wrong_host.url, url, "test URL must use host localhost");
        assert!(wrong_host.connect(3_000).is_err());
    }
}
