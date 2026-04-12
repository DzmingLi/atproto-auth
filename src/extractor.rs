use std::sync::Arc;

use axum::extract::{FromRef, FromRequestParts};
use axum_extra::extract::CookieJar;
use http::request::Parts;

use crate::session::SessionStore;

/// The session cookie name.
pub const SESSION_COOKIE: &str = "pad_session";

/// Authenticated user extracted from session cookie.
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub did: String,
    pub handle: Option<String>,
    pub token: String,
}

/// Rejection type for auth failures.
#[derive(Debug)]
pub struct AuthRejection;

impl axum::response::IntoResponse for AuthRejection {
    fn into_response(self) -> axum::response::Response {
        (
            http::StatusCode::UNAUTHORIZED,
            axum::Json(serde_json::json!({ "error": "unauthorized" })),
        )
            .into_response()
    }
}

/// Implement extraction from any state that provides a SessionStore.
/// The consuming app must implement `FromRef<AppState> for Arc<dyn SessionStore>`.
impl<S> FromRequestParts<S> for AuthUser
where
    Arc<dyn SessionStore>: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AuthRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let store = <Arc<dyn SessionStore> as FromRef<S>>::from_ref(state);

        // Try cookie first
        let jar = CookieJar::from_headers(&parts.headers);
        let token = jar
            .get(SESSION_COOKIE)
            .map(|c| c.value().to_string())
            // Fallback: Bearer token header (for API clients)
            .or_else(|| {
                parts
                    .headers
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.strip_prefix("Bearer "))
                    .map(|s| s.to_string())
            });

        let token = token.ok_or(AuthRejection)?;

        let session: crate::session::OAuthSession = store
            .get_session(&token)
            .await
            .map_err(|_| AuthRejection)?
            .ok_or(AuthRejection)?;

        Ok(AuthUser {
            did: session.did,
            handle: session.handle,
            token: session.token,
        })
    }
}
