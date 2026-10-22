use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use jsonwebtoken::jwk::{AlgorithmParameters, JwkSet, KeyAlgorithm, PublicKeyUse};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use tokio::sync::{Mutex, RwLock};

const MAX_JWKS_AGE: Duration = Duration::from_secs(60);
const MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub struct OidcVerifier {
    inner: Arc<VerifierInner>,
}

struct VerifierInner {
    keys: RwLock<KeyCache>,
    refresh_lock: Mutex<()>,
    source: Option<JwksSource>,
    validation: Validation,
}

struct KeyCache {
    keys: HashMap<String, DecodingKey>,
    fetched_at: Instant,
    last_attempt: Instant,
}

struct JwksSource {
    client: reqwest::Client,
    uri: String,
}

#[derive(Debug, Deserialize)]
struct Discovery {
    issuer: String,
    jwks_uri: String,
}

#[derive(Debug, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    pub roles: Vec<String>,
    pub ca_ids: Vec<String>,
}

impl OidcVerifier {
    pub async fn discover(issuer: &str, audience: &str) -> Result<Self, String> {
        if audience.is_empty() || !safe_issuer_url(issuer) {
            return Err("invalid OIDC issuer or audience".into());
        }
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| "cannot configure OIDC client")?;
        let document: Discovery = client
            .get(format!(
                "{}/.well-known/openid-configuration",
                issuer.trim_end_matches('/')
            ))
            .send()
            .await
            .map_err(|_| "OIDC discovery unavailable")?
            .error_for_status()
            .map_err(|_| "OIDC discovery rejected")?
            .json()
            .await
            .map_err(|_| "invalid OIDC discovery document")?;
        if document.issuer != issuer || !safe_issuer_url(&document.jwks_uri) {
            return Err("OIDC discovery issuer or JWKS URL mismatch".into());
        }
        let issuer_origin = reqwest::Url::parse(issuer)
            .map_err(|_| "invalid issuer URL")?
            .origin();
        let jwks_origin = reqwest::Url::parse(&document.jwks_uri)
            .map_err(|_| "invalid JWKS URL")?
            .origin();
        if issuer_origin != jwks_origin {
            return Err("JWKS origin differs from issuer".into());
        }
        let source = JwksSource {
            client,
            uri: document.jwks_uri,
        };
        let jwks = source.fetch().await?;
        Self::new(issuer, audience, jwks, Some(source))
    }

    #[cfg(test)]
    pub fn from_jwks(issuer: &str, audience: &str, jwks: JwkSet) -> Result<Self, String> {
        Self::new(issuer, audience, jwks, None)
    }

    fn new(
        issuer: &str,
        audience: &str,
        jwks: JwkSet,
        source: Option<JwksSource>,
    ) -> Result<Self, String> {
        if issuer.is_empty() || audience.is_empty() {
            return Err("missing OIDC issuer or audience".into());
        }
        let keys = permitted_keys(jwks)?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[issuer]);
        validation.set_audience(&[audience]);
        validation.set_required_spec_claims(&["exp", "nbf", "iss", "aud", "sub"]);
        validation.validate_nbf = true;
        validation.leeway = 0;
        let now = Instant::now();
        Ok(Self {
            inner: Arc::new(VerifierInner {
                keys: RwLock::new(KeyCache {
                    keys,
                    fetched_at: now,
                    last_attempt: now - MIN_REFRESH_INTERVAL,
                }),
                refresh_lock: Mutex::new(()),
                source,
                validation,
            }),
        })
    }

    pub async fn verify(&self, token: &str) -> Result<Claims, ()> {
        if token.len() > 8192 {
            return Err(());
        }
        let header = decode_header(token).map_err(|_| ())?;
        if header.alg != Algorithm::RS256 || header.typ.as_deref() != Some("at+jwt") {
            return Err(());
        }
        let kid = header.kid.as_deref().ok_or(())?;
        self.refresh_if_needed(kid).await?;
        let cache = self.inner.keys.read().await;
        let key = cache.keys.get(kid).ok_or(())?;
        let claims = decode::<Claims>(token, key, &self.inner.validation)
            .map_err(|_| ())?
            .claims;
        if claims.iss.len() > 1024
            || claims.sub.is_empty()
            || claims.sub.len() > 512
            || claims.ca_ids.len() > 1024
            || claims.roles.len() > 32
        {
            return Err(());
        }
        Ok(claims)
    }

    async fn refresh_if_needed(&self, kid: &str) -> Result<(), ()> {
        let Some(source) = &self.inner.source else {
            return Ok(());
        };
        let cache = self.inner.keys.read().await;
        if cache.fetched_at.elapsed() < MAX_JWKS_AGE && cache.keys.contains_key(kid) {
            return Ok(());
        }
        drop(cache);
        // One refresh at a time. A forged unknown kid cannot trigger unbounded
        // network requests or make a stale key usable while the issuer is down.
        let _guard = self.inner.refresh_lock.try_lock().map_err(|_| ())?;
        let mut cache = self.inner.keys.write().await;
        if cache.fetched_at.elapsed() < MAX_JWKS_AGE && cache.keys.contains_key(kid) {
            return Ok(());
        }
        if cache.last_attempt.elapsed() < MIN_REFRESH_INTERVAL {
            return Err(());
        }
        cache.last_attempt = Instant::now();
        drop(cache);
        let fresh = source.fetch().await.map_err(|_| ())?;
        let keys = permitted_keys(fresh).map_err(|_| ())?;
        let mut cache = self.inner.keys.write().await;
        cache.keys = keys;
        cache.fetched_at = Instant::now();
        Ok(())
    }
}

impl JwksSource {
    async fn fetch(&self) -> Result<JwkSet, String> {
        self.client
            .get(&self.uri)
            .send()
            .await
            .map_err(|_| "OIDC JWKS unavailable")?
            .error_for_status()
            .map_err(|_| "OIDC JWKS rejected")?
            .json()
            .await
            .map_err(|_| "invalid OIDC JWKS".into())
    }
}

fn permitted_keys(jwks: JwkSet) -> Result<HashMap<String, DecodingKey>, String> {
    let mut keys = HashMap::new();
    for jwk in jwks.keys {
        let Some(kid) = jwk.common.key_id.as_deref() else {
            continue;
        };
        if kid.is_empty()
            || jwk.common.key_algorithm != Some(KeyAlgorithm::RS256)
            || !matches!(jwk.algorithm, AlgorithmParameters::RSA(_))
            || jwk.common.public_key_use.as_ref() != Some(&PublicKeyUse::Signature)
        {
            continue;
        }
        let key = DecodingKey::from_jwk(&jwk).map_err(|_| "invalid RSA JWK")?;
        if keys.insert(kid.to_owned(), key).is_some() {
            return Err("duplicate OIDC key id".into());
        }
    }
    if keys.is_empty() {
        return Err("no permitted OIDC signing key".into());
    }
    Ok(keys)
}

fn safe_issuer_url(raw: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(raw) else {
        return false;
    };
    if !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.query().is_some()
    {
        return false;
    }
    matches!(
        (url.scheme(), url.host_str()),
        ("https", Some(_)) | ("http", Some("localhost" | "127.0.0.1" | "::1"))
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{extract::State, routing::get, Json, Router};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use jsonwebtoken::{encode, EncodingKey, Header};
    use rsa::{
        pkcs8::{EncodePrivateKey, LineEnding},
        traits::PublicKeyParts,
        RsaPrivateKey,
    };
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Clone)]
    struct TestIssuer {
        issuer: String,
        jwks: Arc<RwLock<serde_json::Value>>,
        jwks_reads: Arc<AtomicUsize>,
    }

    async fn discovery(State(state): State<TestIssuer>) -> Json<serde_json::Value> {
        Json(json!({"issuer":state.issuer,"jwks_uri":format!("{}/jwks",state.issuer)}))
    }

    async fn jwks(State(state): State<TestIssuer>) -> Json<serde_json::Value> {
        state.jwks_reads.fetch_add(1, Ordering::SeqCst);
        Json(state.jwks.read().await.clone())
    }

    fn test_jwk(private: &RsaPrivateKey, kid: &str) -> serde_json::Value {
        let public = private.to_public_key();
        json!({"kty":"RSA", "use":"sig", "alg":"RS256", "kid":kid,
            "n":URL_SAFE_NO_PAD.encode(public.n().to_bytes_be()),
            "e":URL_SAFE_NO_PAD.encode(public.e().to_bytes_be())})
    }

    fn test_token(private: &RsaPrivateKey, issuer: &str, kid: &str) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.typ = Some("at+jwt".into());
        header.kid = Some(kid.into());
        let now = jsonwebtoken::get_current_timestamp();
        let claims = json!({"iss":issuer,"aud":"trust-api","sub":"operator",
            "nbf":now-1,"exp":now+60,"roles":["trust-ca-reader"],"ca_ids":[]});
        let pem = private.to_pkcs8_pem(LineEnding::LF).unwrap();
        encode(
            &header,
            &claims,
            &EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn oidc_urls_fail_closed() {
        assert!(safe_issuer_url("https://issuer.example.test/realms/lab"));
        assert!(safe_issuer_url("http://127.0.0.1:8080/realms/lab"));
        assert!(!safe_issuer_url("http://issuer.example.test/realms/lab"));
        assert!(!safe_issuer_url("https://user:pass@issuer.example.test"));
    }

    #[test]
    fn empty_jwks_is_rejected() {
        let set = JwkSet { keys: Vec::new() };
        assert!(OidcVerifier::from_jwks("https://issuer.example.test", "trust-api", set).is_err());
    }

    #[tokio::test]
    async fn signed_access_token_checks_audience_expiry_type_and_signature() {
        let private = RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
        let public = private.to_public_key();
        let jwks: JwkSet = serde_json::from_value(json!({"keys":[{
            "kty":"RSA", "use":"sig", "alg":"RS256", "kid":"lab-key",
            "n":URL_SAFE_NO_PAD.encode(public.n().to_bytes_be()),
            "e":URL_SAFE_NO_PAD.encode(public.e().to_bytes_be())
        }]}))
        .unwrap();
        let verifier =
            OidcVerifier::from_jwks("https://issuer.example.test", "trust-api", jwks).unwrap();
        let pem = private.to_pkcs8_pem(LineEnding::LF).unwrap();
        let signer = EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap();
        let now = jsonwebtoken::get_current_timestamp();
        let claims = json!({
            "iss":"https://issuer.example.test", "aud":"trust-api", "sub":"operator-1",
            "nbf":now-1, "exp":now+60, "roles":["trust-ca-reader"],
            "ca_ids":["eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"]
        });
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("lab-key".into());
        header.typ = Some("at+jwt".into());
        let token = encode(&header, &claims, &signer).unwrap();
        assert_eq!(verifier.verify(&token).await.unwrap().sub, "operator-1");
        let mut wrong_audience = claims.clone();
        wrong_audience["aud"] = json!("another-service");
        assert!(verifier
            .verify(&encode(&header, &wrong_audience, &signer).unwrap())
            .await
            .is_err());
        let mut expired = claims.clone();
        expired["exp"] = json!(now - 1);
        assert!(verifier
            .verify(&encode(&header, &expired, &signer).unwrap())
            .await
            .is_err());
        header.typ = Some("JWT".into());
        assert!(verifier
            .verify(&encode(&header, &claims, &signer).unwrap())
            .await
            .is_err());
        let mut tampered = token.into_bytes();
        let middle_index = tampered.len() / 2;
        let middle = &mut tampered[middle_index];
        *middle = if *middle == b'A' { b'B' } else { b'A' };
        assert!(verifier
            .verify(std::str::from_utf8(&tampered).unwrap())
            .await
            .is_err());
    }

    #[tokio::test]
    async fn rotated_jwks_replaces_removed_keys_and_limits_refresh_attempts() {
        let first = RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
        let second = RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://{}", listener.local_addr().unwrap());
        let state = TestIssuer {
            issuer: issuer.clone(),
            jwks: Arc::new(RwLock::new(json!({"keys":[test_jwk(&first,"first")]}))),
            jwks_reads: Arc::new(AtomicUsize::new(0)),
        };
        let app = Router::new()
            .route("/.well-known/openid-configuration", get(discovery))
            .route("/jwks", get(jwks))
            .with_state(state.clone());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let verifier = OidcVerifier::discover(&issuer, "trust-api").await.unwrap();
        let first_token = test_token(&first, &issuer, "first");
        assert!(verifier.verify(&first_token).await.is_ok());
        *state.jwks.write().await = json!({"keys":[test_jwk(&second,"second")]});
        let second_token = test_token(&second, &issuer, "second");
        let (first_read, second_read, third_read) = tokio::join!(
            verifier.verify(&second_token),
            verifier.verify(&second_token),
            verifier.verify(&second_token),
        );
        assert!(first_read.is_ok() || second_read.is_ok() || third_read.is_ok());
        assert!(verifier.verify(&second_token).await.is_ok());
        assert!(verifier.verify(&first_token).await.is_err());
        assert_eq!(state.jwks_reads.load(Ordering::SeqCst), 2);

        for index in 0..3 {
            let unknown = test_token(&second, &issuer, &format!("unknown-{index}"));
            assert!(verifier.verify(&unknown).await.is_err());
        }
        assert_eq!(state.jwks_reads.load(Ordering::SeqCst), 2);

        // Once the cache is too old, even a previously accepted key fails
        // closed when the issuer serves an invalid set.
        *state.jwks.write().await = json!({"keys":[]});
        {
            let mut cache = verifier.inner.keys.write().await;
            cache.fetched_at = Instant::now() - MAX_JWKS_AGE;
            cache.last_attempt = Instant::now() - MIN_REFRESH_INTERVAL;
        }
        assert!(verifier.verify(&second_token).await.is_err());
        assert_eq!(state.jwks_reads.load(Ordering::SeqCst), 3);
        assert!(verifier.verify(&second_token).await.is_err());
        assert_eq!(state.jwks_reads.load(Ordering::SeqCst), 3);
        server.abort();
        let _ = server.await;
        {
            let mut cache = verifier.inner.keys.write().await;
            cache.last_attempt = Instant::now() - MIN_REFRESH_INTERVAL;
        }
        assert!(verifier.verify(&second_token).await.is_err());
    }
}
