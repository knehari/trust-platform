//! Lab-only audit chain sealing and external anchoring (migration 0027,
//! ADR-0006 condition 5, proposed).
//!
//! `seal`: seals every unsealed audit record (login holding
//! trust_audit_sealer).
//! `verify <checkpoint-file>`: loads the whole chain (login holding
//! trust_audit_verifier), re-encodes every record, checks it against every
//! checkpoint already in the file, then appends the new head. The file is
//! the external anchor: keep it on another system or append-only storage,
//! and publish its last line out of band. A superuser who rewrites the
//! database cannot rewrite it.
//!
//! Signed anchors: with `--anchor-key <pkcs8.der>` (the anchoring host's
//! P-256 key, a plaintext file in the lab; an HSM in production) every
//! appended line is signed (`audit-chain-checkpoint v2`) and every existing
//! line must carry a valid signature by that key. A verifier holding only
//! `--anchor-public-key <spki.der>` checks the signatures and appends
//! nothing. A line that is unsigned, malformed or signed by another key
//! then counts as tampering. Without either option the file holds unsigned
//! lines (v1).
//!
//! Exit status: 0 verified; 2 records older than `--unsealed-older-than`
//! seconds (default 3600) are not sealed yet; 3 the chain or a signed
//! anchor does not verify (tampering or loss: investigate, do not append);
//! 1 error.
//! The database URL is read from TRUST_DATABASE_URL; the connection is the
//! lab NoTls adapter, for a loopback or private lab database only.
//! Usage:
//!   TRUST_DATABASE_URL=postgresql://... cargo run -p trust-pki-core \
//!     --features postgres-store --example audit_chain_anchor -- seal
//!   TRUST_DATABASE_URL=postgresql://... cargo run -p trust-pki-core \
//!     --features postgres-store --example audit_chain_anchor -- \
//!     verify <checkpoint-file> [--unsealed-older-than SECONDS] \
//!     [--anchor-key PKCS8.der | --anchor-public-key SPKI.der]

use postgres::{Client, NoTls};
use std::{
    env, fs,
    io::{ErrorKind, Write},
    process::ExitCode,
};
use trust_pki_core::{
    audit_chain::{checkpoint_signing_message, verify_sealed_chain, Checkpoint, SignedCheckpoint},
    audit_chain_store::{load_entries, seal, unsealed},
};
use trust_pki_crypto::{canonical_p256_public_key_sec1, lab::LabP256KeyFile};
use x509_cert::{der::Decode, spki::SubjectPublicKeyInfoOwned};

enum Outcome {
    Verified,
    Unsealed,
    Tampered,
}

/// How the anchor file is protected.
enum Anchor {
    Unsigned,
    Signed {
        public_key: Vec<u8>,
        signer: Option<LabP256KeyFile>,
    },
}

fn option(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1).cloned())
}

fn anchor(args: &[String]) -> Result<Anchor, String> {
    let signer = option(args, "--anchor-key")
        .map(|path| {
            let der = fs::read(&path).map_err(|e| format!("cannot read {path}: {e}"))?;
            LabP256KeyFile::from_pkcs8_der(&der)
                .map_err(|_| format!("{path}: not a P-256 PKCS#8 key"))
        })
        .transpose()?;
    let given = option(args, "--anchor-public-key")
        .map(|path| {
            let der = fs::read(&path).map_err(|e| format!("cannot read {path}: {e}"))?;
            SubjectPublicKeyInfoOwned::from_der(&der)
                .ok()
                .and_then(|spki| {
                    canonical_p256_public_key_sec1(spki.subject_public_key.raw_bytes()).ok()
                })
                .ok_or_else(|| format!("{path}: not a P-256 public key"))
        })
        .transpose()?;
    Ok(match (signer, given) {
        (None, None) => Anchor::Unsigned,
        (Some(signer), given) => {
            let public_key = signer.public_key_sec1();
            if given.is_some_and(|given| given != public_key) {
                return Err("--anchor-key and --anchor-public-key do not match".into());
            }
            Anchor::Signed {
                public_key,
                signer: Some(signer),
            }
        }
        (None, Some(public_key)) => Anchor::Signed {
            public_key,
            signer: None,
        },
    })
}

/// The exported checkpoints, or the reason the anchor itself is tampered.
fn read_checkpoints(
    path: &str,
    anchor: &Anchor,
) -> Result<Result<Vec<Checkpoint>, String>, String> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == ErrorKind::NotFound => String::new(),
        Err(e) => return Err(format!("cannot read {path}: {e}")),
    };
    let mut checkpoints = Vec::new();
    for (i, line) in text.lines().enumerate() {
        match anchor {
            // Fail closed: an unreadable anchor is not an empty one.
            Anchor::Unsigned => checkpoints.push(
                Checkpoint::parse_line(line)
                    .ok_or_else(|| format!("{path}:{}: not a checkpoint line", i + 1))?,
            ),
            Anchor::Signed { public_key, .. } => {
                match SignedCheckpoint::parse_line(line).filter(|signed| signed.verify(public_key))
                {
                    Some(signed) => checkpoints.push(signed.checkpoint),
                    None => {
                        return Ok(Err(format!(
                            "{path}:{}: not a checkpoint signed by the anchor key",
                            i + 1
                        )))
                    }
                }
            }
        }
    }
    Ok(Ok(checkpoints))
}

fn run() -> Result<Outcome, String> {
    let args: Vec<String> = env::args().skip(1).collect();
    let url = env::var("TRUST_DATABASE_URL").map_err(|_| "TRUST_DATABASE_URL is not set")?;
    let mut client =
        Client::connect(&url, NoTls).map_err(|e| format!("database connection failed: {e}"))?;
    match args.first().map(String::as_str) {
        Some("seal") => {
            let mut total = 0;
            loop {
                let sealed =
                    seal(&mut client, 10_000).map_err(|e| format!("seal failed: {e:?}"))?;
                total += sealed;
                if sealed == 0 {
                    break;
                }
            }
            println!("sealed={total}");
            Ok(Outcome::Verified)
        }
        Some("verify") => {
            let path = args.get(1).ok_or("verify needs a checkpoint file")?;
            let older_than = match args.iter().position(|a| a == "--unsealed-older-than") {
                None => 3600,
                Some(i) => args
                    .get(i + 1)
                    .and_then(|v| v.parse::<i64>().ok())
                    .filter(|v| *v >= 0)
                    .ok_or("--unsealed-older-than needs a non-negative number of seconds")?,
            };
            let anchor = anchor(&args)?;
            let checkpoints = match read_checkpoints(path, &anchor)? {
                Ok(checkpoints) => checkpoints,
                Err(reason) => {
                    println!("tampered_anchor={reason}");
                    return Ok(Outcome::Tampered);
                }
            };
            let entries = load_entries(&mut client).map_err(|e| format!("load failed: {e:?}"))?;
            let chain = match verify_sealed_chain(entries, &checkpoints) {
                Ok(chain) => chain,
                Err(error) => {
                    println!("tampered={error:?}");
                    return Ok(Outcome::Tampered);
                }
            };
            let last = checkpoints.last().map_or(0, |c| c.sequence);
            let checkpoint = Checkpoint {
                sequence: chain.sequence(),
                head: chain.head(),
            };
            let line = match &anchor {
                Anchor::Unsigned => Some(checkpoint.to_line()),
                Anchor::Signed {
                    signer: Some(signer),
                    ..
                } => Some(
                    SignedCheckpoint {
                        checkpoint,
                        signature_der: signer.sign(&checkpoint_signing_message(&checkpoint)),
                    }
                    .to_line(),
                ),
                // A verifier without the anchor key checks but never writes.
                Anchor::Signed { signer: None, .. } => None,
            };
            if let Some(line) = line.filter(|_| chain.sequence() > last) {
                let mut file = fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .map_err(|e| format!("cannot open {path}: {e}"))?;
                writeln!(file, "{line}")
                    .and_then(|()| file.sync_all())
                    .map_err(|e| format!("cannot append to {path}: {e}"))?;
                println!("{line}");
            }
            let pending =
                unsealed(&mut client, older_than).map_err(|e| format!("count failed: {e:?}"))?;
            println!("verified={} unsealed={pending}", chain.sequence());
            Ok(if pending > 0 {
                Outcome::Unsealed
            } else {
                Outcome::Verified
            })
        }
        _ => Err("usage: audit_chain_anchor seal | verify <checkpoint-file> \
                  [--unsealed-older-than S]"
            .into()),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(Outcome::Verified) => ExitCode::SUCCESS,
        Ok(Outcome::Unsealed) => ExitCode::from(2),
        Ok(Outcome::Tampered) => ExitCode::from(3),
        Err(message) => {
            eprintln!("audit_chain_anchor: {message}");
            ExitCode::FAILURE
        }
    }
}
