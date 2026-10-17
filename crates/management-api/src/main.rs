mod auth;

use auth::{Claims, OidcVerifier};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::get,
    Json, Router,
};
use postgres::{Client, NoTls};
use serde::Serialize;
use std::env;

#[derive(Clone)]
struct AppState {
    verifier: OidcVerifier,
    database_url: String,
}

#[derive(Serialize)]
struct Ca {
    ca_id: String,
    parent_ca_id: Option<String>,
    display_name: String,
    policy_version: String,
    created_at: String,
}
#[derive(Serialize)]
struct Certificate {
    ca_id: String,
    serial_hex: String,
    fingerprint_sha256: String,
    request_id: String,
    state: String,
    signed_at: String,
    published_at: Option<String>,
}
#[derive(Serialize)]
struct Audit {
    event_id: String,
    ca_id: String,
    event_type: String,
    decision: String,
    policy_version: Option<String>,
    recorded_at: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let issuer = env::var("TRUST_OIDC_ISSUER")?;
    let audience = env::var("TRUST_OIDC_AUDIENCE")?;
    let database_url = env::var("TRUST_DATABASE_URL")?;
    let verifier = OidcVerifier::discover(&issuer, &audience).await?;
    let safe_db_role = query_db(database_url.clone(), |db| {
        db.query_one(
            "SELECT pg_has_role(current_user,'trust_api_reader','member') \
             AND NOT EXISTS (SELECT 1 FROM pg_roles r WHERE r.rolname=current_user \
                 AND (r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb)) \
             AND NOT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace \
                 WHERE n.nspname='public' AND c.relkind IN ('r','p','m','f') \
                 AND has_table_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'))",
            &[],
        )
        .map(|row| row.get::<_, bool>(0))
    })
    .await
    .map_err(|_| "management database unavailable")?;
    if !safe_db_role {
        return Err("management database login lacks read-only role isolation".into());
    }
    let app = router(AppState {
        verifier,
        database_url,
    });
    let bind = env::var("TRUST_API_BIND").unwrap_or_else(|_| "127.0.0.1:8081".into());
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/health", get(health))
        .route("/v1/cas", get(list_cas))
        .route("/v1/cas/{ca_id}", get(get_ca))
        .route("/v1/cas/{ca_id}/certificates", get(list_certificates))
        .route("/v1/cas/{ca_id}/audit", get(list_audit))
        .with_state(state)
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({"status":"up"}))
}

fn authorize(headers: &HeaderMap, verifier: &OidcVerifier) -> Result<Claims, StatusCode> {
    let raw = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let token = raw
        .strip_prefix("Bearer ")
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let claims = verifier
        .verify(token)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    if !claims.roles.iter().any(|role| role == "trust-ca-reader") {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(claims)
}

fn scoped_ca_id(raw: &str, claims: &Claims) -> Result<String, StatusCode> {
    let canonical = uuid::Uuid::parse_str(raw)
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .to_string();
    if !claims.ca_ids.iter().any(|scope| scope == &canonical) {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(canonical)
}

async fn query_db<T: Send + 'static>(
    url: String,
    query: impl FnOnce(&mut Client) -> Result<T, postgres::Error> + Send + 'static,
) -> Result<T, StatusCode> {
    tokio::task::spawn_blocking(move || {
        let mut db = Client::connect(&url, NoTls).map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        query(&mut db).map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
    })
    .await
    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
}

async fn list_cas(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<Ca>>, StatusCode> {
    let claims = authorize(&headers, &state.verifier)?;
    let ids: Vec<String> = claims
        .ca_ids
        .iter()
        .filter_map(|id| uuid::Uuid::parse_str(id).ok().map(|u| u.to_string()))
        .take(1024)
        .collect();
    let rows = query_db(state.database_url, move |db| db.query(
        "SELECT ca_id,parent_ca_id,display_name,policy_version,created_at FROM management_ca WHERE ca_id=ANY($1::text[]) ORDER BY display_name LIMIT 100", &[&ids]
    )).await?;
    Ok(Json(
        rows.into_iter()
            .map(|r| Ca {
                ca_id: r.get(0),
                parent_ca_id: r.get(1),
                display_name: r.get(2),
                policy_version: r.get(3),
                created_at: r.get(4),
            })
            .collect(),
    ))
}

async fn get_ca(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(ca_id): Path<String>,
) -> Result<Json<Ca>, StatusCode> {
    let claims = authorize(&headers, &state.verifier)?;
    let ca_id = scoped_ca_id(&ca_id, &claims)?;
    let row = query_db(state.database_url, move |db| db.query_opt(
        "SELECT ca_id,parent_ca_id,display_name,policy_version,created_at FROM management_ca WHERE ca_id=$1", &[&ca_id]
    )).await?.ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(Ca {
        ca_id: row.get(0),
        parent_ca_id: row.get(1),
        display_name: row.get(2),
        policy_version: row.get(3),
        created_at: row.get(4),
    }))
}

async fn list_certificates(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(ca_id): Path<String>,
) -> Result<Json<Vec<Certificate>>, StatusCode> {
    let claims = authorize(&headers, &state.verifier)?;
    let ca_id = scoped_ca_id(&ca_id, &claims)?;
    let rows = query_db(state.database_url, move |db| db.query(
        "SELECT ca_id,serial_hex,fingerprint_sha256,request_id,state,signed_at,published_at FROM management_certificate WHERE ca_id=$1 ORDER BY signed_at DESC LIMIT 100", &[&ca_id]
    )).await?;
    Ok(Json(
        rows.into_iter()
            .map(|r| Certificate {
                ca_id: r.get(0),
                serial_hex: r.get(1),
                fingerprint_sha256: r.get(2),
                request_id: r.get(3),
                state: r.get(4),
                signed_at: r.get(5),
                published_at: r.get(6),
            })
            .collect(),
    ))
}

async fn list_audit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(ca_id): Path<String>,
) -> Result<Json<Vec<Audit>>, StatusCode> {
    let claims = authorize(&headers, &state.verifier)?;
    let ca_id = scoped_ca_id(&ca_id, &claims)?;
    let rows = query_db(state.database_url, move |db| db.query(
        "SELECT event_id,ca_id,event_type,decision,policy_version,recorded_at FROM management_audit WHERE ca_id=$1 ORDER BY recorded_at DESC LIMIT 100", &[&ca_id]
    )).await?;
    Ok(Json(
        rows.into_iter()
            .map(|r| Audit {
                event_id: r.get(0),
                ca_id: r.get(1),
                event_type: r.get(2),
                decision: r.get(3),
                policy_version: r.get(4),
                recorded_at: r.get(5),
            })
            .collect(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use http_body_util::BodyExt;
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use rsa::{
        pkcs8::{EncodePrivateKey, LineEnding},
        traits::PublicKeyParts,
        RsaPrivateKey,
    };
    use serde_json::json;
    use tower::ServiceExt;
    #[test]
    fn scope_rejects_other_and_invalid_ca() {
        let claims = Claims {
            sub: "operator".into(),
            roles: vec!["trust-ca-reader".into()],
            ca_ids: vec!["eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee".into()],
        };
        assert_eq!(
            scoped_ca_id("ffffffff-ffff-4fff-8fff-ffffffffffff", &claims),
            Err(StatusCode::FORBIDDEN)
        );
        assert_eq!(
            scoped_ca_id("../../ca", &claims),
            Err(StatusCode::BAD_REQUEST)
        );
    }

    #[tokio::test]
    async fn http_contract_rejects_missing_role_and_wrong_scope() {
        let private = RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
        let public = private.to_public_key();
        let jwks = serde_json::from_value(json!({"keys":[{
            "kty":"RSA", "use":"sig", "alg":"RS256", "kid":"http-test",
            "n":URL_SAFE_NO_PAD.encode(public.n().to_bytes_be()),
            "e":URL_SAFE_NO_PAD.encode(public.e().to_bytes_be())
        }]}))
        .unwrap();
        let verifier =
            OidcVerifier::from_jwks("https://issuer.example.test", "trust-api", jwks).unwrap();
        let signer =
            EncodingKey::from_rsa_pem(private.to_pkcs8_pem(LineEnding::LF).unwrap().as_bytes())
                .unwrap();
        let mut header = Header::new(Algorithm::RS256);
        header.typ = Some("at+jwt".into());
        header.kid = Some("http-test".into());
        let now = jsonwebtoken::get_current_timestamp();
        let mut claims = json!({
            "iss":"https://issuer.example.test", "aud":"trust-api", "sub":"operator",
            "nbf":now-1, "exp":now+60, "roles":[],
            "ca_ids":["eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"]
        });
        let database_url = env::var("TRUST_API_TEST_DATABASE_URL").unwrap_or_default();
        let app = router(AppState {
            verifier,
            database_url: database_url.clone(),
        });
        let no_token = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/cas")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(no_token.status(), StatusCode::UNAUTHORIZED);
        let no_role_token = encode(&header, &claims, &signer).unwrap();
        let no_role = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/cas")
                    .header("authorization", format!("Bearer {no_role_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(no_role.status(), StatusCode::FORBIDDEN);
        claims["roles"] = json!(["trust-ca-reader"]);
        let token = encode(&header, &claims, &signer).unwrap();
        let other_ca = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/cas/ffffffff-ffff-4fff-8fff-ffffffffffff")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(other_ca.status(), StatusCode::FORBIDDEN);
        if !database_url.is_empty() {
            let scoped = app
                .oneshot(
                    Request::builder()
                        .uri("/v1/cas")
                        .header("authorization", format!("Bearer {token}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(scoped.status(), StatusCode::OK);
            let body = scoped.into_body().collect().await.unwrap().to_bytes();
            let listed: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(listed.as_array().unwrap().len(), 1);
            assert!(listed
                .as_array()
                .unwrap()
                .iter()
                .all(|ca| ca["ca_id"] == "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"));
        }
    }
}
