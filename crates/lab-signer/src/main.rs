//! `trust-lab-signer`: the laboratory signer process (ADR-0017, Proposed).
//!
//! Configuration (environment):
//! - `TRUST_SIGNER_SOCKET`: Unix socket path to listen on. The socket is
//!   created with mode 0600; with `TRUST_SIGNER_SOCKET_OWNER=<uid>:<gid>` it
//!   is handed to the API's user. Nothing listens on the network.
//! - `TRUST_SIGNER_DATABASE_URL`: a login holding only `trust_lab_signer`.
//! - `TRUST_SIGNER_CA_ID`: the one CA this signer serves.
//! - `TRUST_SIGNER_KEY_FILE`: that CA's P-256 key (PEM). Read for each
//!   request and checked against the CA's attested key; never logged.
//!
//! Protocol: one JSON line per connection,
//! `{"intent_id": "...", "tbs_der_base64": "..."}`, answered by
//! `{"signature_der_base64": "..."}` or `{"error": "<code>"}`.
use std::{
    env,
    error::Error,
    fs,
    os::unix::{
        fs::{chown, PermissionsExt},
        net::UnixListener,
    },
    path::PathBuf,
};

use trust_lab_signer::service::{log, restricted_login, serve, Config};

fn main() -> Result<(), Box<dyn Error>> {
    let socket = PathBuf::from(env::var("TRUST_SIGNER_SOCKET")?);
    let config = Config {
        database_url: env::var("TRUST_SIGNER_DATABASE_URL")?,
        ca_id: uuid_text(&env::var("TRUST_SIGNER_CA_ID")?)?,
        key_file: PathBuf::from(env::var("TRUST_SIGNER_KEY_FILE")?),
    };
    if !restricted_login(&config.database_url)? {
        return Err("the signer login is not limited to trust_lab_signer".into());
    }
    if socket.exists() {
        fs::remove_file(&socket)?;
    }
    let listener = UnixListener::bind(&socket)?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
    if let Ok(owner) = env::var("TRUST_SIGNER_SOCKET_OWNER") {
        let (uid, gid) = owner
            .split_once(':')
            .ok_or("TRUST_SIGNER_SOCKET_OWNER is uid:gid")?;
        chown(&socket, Some(uid.parse()?), Some(gid.parse()?))?;
    }
    log(serde_json::json!({"event": "lab_signer_started", "ca_id": config.ca_id}));
    // One request at a time: the laboratory needs no concurrency, and the
    // database claim serializes signing anyway.
    serve(&config, &listener);
    Ok(())
}

fn uuid_text(raw: &str) -> Result<String, Box<dyn Error>> {
    let lower = raw.trim().to_ascii_lowercase();
    let valid = lower.len() == 36
        && lower.char_indices().all(|(index, c)| {
            if [8, 13, 18, 23].contains(&index) {
                c == '-'
            } else {
                c.is_ascii_hexdigit()
            }
        });
    if valid {
        Ok(lower)
    } else {
        Err("TRUST_SIGNER_CA_ID is not a UUID".into())
    }
}
