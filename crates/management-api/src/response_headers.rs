//! Response headers shared by the lab HTTP APIs (management read API,
//! revocation API, CA-admin API). LAB ONLY.
//!
//! Their responses carry signing challenges, signed evidence and CA data:
//! `Cache-Control: no-store` keeps browsers and intermediaries from storing
//! them, and `X-Content-Type-Options: nosniff` keeps JSON from being
//! interpreted as anything else. Applied to every response, errors
//! included. Not used by the public CRL distribution point, which sets its
//! own cache headers.
use axum::{
    body::Body,
    http::{header, HeaderValue, Request},
    middleware::Next,
    response::Response,
};

pub async fn security_headers(request: Request<Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}
