use std::collections::HashMap;

use jsonwebtoken::jwk::{AlgorithmParameters, JwkSet, KeyAlgorithm, PublicKeyUse};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;

#[derive(Clone)]
pub struct OidcVerifier {
    keys: HashMap<String, DecodingKey>,
    validation: Validation,
}

#[derive(Debug, Deserialize)]
struct Discovery {
    issuer: String,
    jwks_uri: String,
}

#[derive(Debug, Deserialize)]
pub struct Claims {
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
        let jwks: JwkSet = client
            .get(&document.jwks_uri)
            .send()
            .await
            .map_err(|_| "OIDC JWKS unavailable")?
            .error_for_status()
            .map_err(|_| "OIDC JWKS rejected")?
            .json()
            .await
            .map_err(|_| "invalid OIDC JWKS")?;
        Self::from_jwks(issuer, audience, jwks)
    }

    pub fn from_jwks(issuer: &str, audience: &str, jwks: JwkSet) -> Result<Self, String> {
        if issuer.is_empty() || audience.is_empty() {
            return Err("missing OIDC issuer or audience".into());
        }
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
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[issuer]);
        validation.set_audience(&[audience]);
        validation.set_required_spec_claims(&["exp", "nbf", "iss", "aud", "sub"]);
        validation.validate_nbf = true;
        validation.leeway = 0;
        Ok(Self { keys, validation })
    }

    pub fn verify(&self, token: &str) -> Result<Claims, ()> {
        if token.len() > 8192 {
            return Err(());
        }
        let header = decode_header(token).map_err(|_| ())?;
        if header.alg != Algorithm::RS256 || header.typ.as_deref() != Some("at+jwt") {
            return Err(());
        }
        let key = self.keys.get(header.kid.as_deref().ok_or(())?).ok_or(())?;
        let claims = decode::<Claims>(token, key, &self.validation)
            .map_err(|_| ())?
            .claims;
        if claims.sub.is_empty() || claims.ca_ids.len() > 1024 || claims.roles.len() > 32 {
            return Err(());
        }
        Ok(claims)
    }
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
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use jsonwebtoken::{encode, EncodingKey, Header};
    use rsa::{
        pkcs8::{EncodePrivateKey, LineEnding},
        traits::PublicKeyParts,
        RsaPrivateKey,
    };
    use serde_json::json;

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

    #[test]
    fn signed_access_token_checks_audience_expiry_type_and_signature() {
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
        assert_eq!(verifier.verify(&token).unwrap().sub, "operator-1");
        let mut wrong_audience = claims.clone();
        wrong_audience["aud"] = json!("another-service");
        assert!(verifier
            .verify(&encode(&header, &wrong_audience, &signer).unwrap())
            .is_err());
        let mut expired = claims.clone();
        expired["exp"] = json!(now - 1);
        assert!(verifier
            .verify(&encode(&header, &expired, &signer).unwrap())
            .is_err());
        header.typ = Some("JWT".into());
        assert!(verifier
            .verify(&encode(&header, &claims, &signer).unwrap())
            .is_err());
        let mut tampered = token.into_bytes();
        let middle_index = tampered.len() / 2;
        let middle = &mut tampered[middle_index];
        *middle = if *middle == b'A' { b'B' } else { b'A' };
        assert!(verifier
            .verify(std::str::from_utf8(&tampered).unwrap())
            .is_err());
    }
}
