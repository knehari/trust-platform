//! Read-only views of the RA channel's policies (migration 0049, ADR-0044,
//! Proposed). Readers of a CA see:
//! - `GET /v1/cas/{ca_id}/ra-systems`: each RA granted a profile of the CA,
//!   whether it is enabled, its profiles, its effective hourly quotas
//!   (ADR-0039) and their use in the last hour, its DNS zones, and its keys
//!   (ADR-0040) as SHA-256 fingerprints with their activation and
//!   retirement times;
//! - `GET /v1/cas/{ca_id}/short-lived-profiles`: the CA's short-lived
//!   profiles and their bound (ADR-0042).
//!
//! The database owner still sets all of it; nothing here writes.

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

use crate::{
    authorize, profile_lifecycle::with_replay_header, query_db_as, scoped_ca_id, AppState,
};

#[derive(Serialize, serde::Deserialize, Debug, PartialEq)]
struct RaKey {
    key_id: i32,
    sha256: String,
    activated_at: String,
    retired_at: Option<String>,
}

#[derive(Serialize)]
struct RaSystem {
    ra_id: String,
    display_name: String,
    enabled: bool,
    profile_ids: Vec<String>,
    max_issuance_per_hour: i32,
    max_revocation_per_hour: i32,
    /// None: the profiles' zones apply.
    allowed_dns_zones: Option<Vec<String>>,
    issuance_last_hour: i64,
    revocation_last_hour: i64,
    keys: Vec<RaKey>,
}

#[derive(Serialize)]
struct ShortLivedProfile {
    profile_id: String,
    max_validity_days: i32,
    updated_at: String,
}

/// `GET /v1/cas/{ca_id}/ra-systems`.
pub(crate) async fn list_ra_systems(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw_ca): Path<String>,
) -> Result<Response, StatusCode> {
    let claims = authorize(&headers, &state.verifier).await?;
    let ca_id = scoped_ca_id(&raw_ca, &claims)?;
    let rows = query_db_as(
        state.database_url,
        state.database_slots,
        (claims.iss, claims.sub),
        move |db| {
            db.query(
                "SELECT ra_id, display_name, enabled, profile_ids, max_issuance_per_hour, \
                 max_revocation_per_hour, allowed_dns_zones, issuance_last_hour, \
                 revocation_last_hour, keys_json \
                 FROM management_ra_system WHERE ca_id = $1 ORDER BY ra_id LIMIT 500",
                &[&ca_id],
            )
        },
    )
    .await?;
    let items = rows
        .into_iter()
        .map(|row| {
            let keys: Vec<RaKey> = serde_json::from_str(&row.get::<_, String>(9))
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
            Ok(RaSystem {
                ra_id: row.get(0),
                display_name: row.get(1),
                enabled: row.get(2),
                profile_ids: row.get(3),
                max_issuance_per_hour: row.get(4),
                max_revocation_per_hour: row.get(5),
                allowed_dns_zones: row.get(6),
                issuance_last_hour: row.get(7),
                revocation_last_hour: row.get(8),
                keys,
            })
        })
        .collect::<Result<Vec<_>, StatusCode>>()?;
    Ok(with_replay_header(Json(items).into_response(), false))
}

/// `GET /v1/cas/{ca_id}/short-lived-profiles`.
pub(crate) async fn list_short_lived_profiles(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw_ca): Path<String>,
) -> Result<Response, StatusCode> {
    let claims = authorize(&headers, &state.verifier).await?;
    let ca_id = scoped_ca_id(&raw_ca, &claims)?;
    let rows = query_db_as(
        state.database_url,
        state.database_slots,
        (claims.iss, claims.sub),
        move |db| {
            db.query(
                "SELECT profile_id, max_validity_days, updated_at \
                 FROM management_short_lived_profile WHERE ca_id = $1 ORDER BY profile_id LIMIT 500",
                &[&ca_id],
            )
        },
    )
    .await?;
    let items: Vec<ShortLivedProfile> = rows
        .into_iter()
        .map(|row| ShortLivedProfile {
            profile_id: row.get(0),
            max_validity_days: row.get(1),
            updated_at: row.get(2),
        })
        .collect();
    Ok(with_replay_header(Json(items).into_response(), false))
}
