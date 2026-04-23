use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    Router,
    extract::{Query, State},
    response::{IntoResponse, Redirect, Response},
    routing::get,
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use chrono::Utc;
use rand::distr::{Alphanumeric, SampleString};
use tokio::sync::RwLock;

use atproto_identity::key::{to_public, identify_key, generate_key, KeyType};
use atproto_oauth::{
    pkce,
    resources::pds_resources,
    workflow::{OAuthClient, OAuthRequest, OAuthRequestState, oauth_init},
};
use atproto_oauth::storage::OAuthRequestStorage;
use atproto_oauth_axum::handler_metadata::handle_oauth_metadata;

use crate::config::OAuthConfig;
use crate::extractor::SESSION_COOKIE;
use crate::session::{OAuthSession, SessionStore};

/// Shared state for OAuth handlers.
#[derive(Clone)]
pub struct OAuthState {
    pub config: OAuthConfig,
    pub request_store: Arc<dyn OAuthRequestStorage>,
    pub session_store: Arc<dyn SessionStore>,
    pub http_client: reqwest::Client,
    /// Maps oauth_state → cli_redirect URL for CLI login flows. Initialized
    /// empty; populated per-login when the client asks for a CLI redirect.
    pub cli_redirects: Arc<RwLock<HashMap<String, String>>>,
}

impl OAuthState {
    /// Construct with the required collaborators; auxiliary state
    /// (`http_client`, `cli_redirects`) is initialized to sensible defaults.
    /// Callers that need to override either can do so after construction.
    pub fn new(
        config: OAuthConfig,
        request_store: Arc<dyn OAuthRequestStorage>,
        session_store: Arc<dyn SessionStore>,
    ) -> Self {
        Self {
            config,
            request_store,
            session_store,
            http_client: reqwest::Client::new(),
            cli_redirects: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl axum::extract::FromRef<OAuthState> for Arc<dyn SessionStore> {
    fn from_ref(state: &OAuthState) -> Self {
        state.session_store.clone()
    }
}

/// Create the OAuth router with all necessary endpoints.
/// Mount this at `/oauth` or `/api/auth` in your app.
///
/// Provides:
/// - `GET /login?handle=xxx` — start OAuth flow
/// - `GET /callback` — OAuth callback
/// - `POST /logout` — destroy session
/// - `GET /me` — current user info
/// - `GET /client-metadata.json` — OAuth client metadata
/// - `GET /jwks.json` — public keys
pub fn oauth_router(state: OAuthState) -> Router {
    Router::new()
        .route("/login", get(login_start))
        .route("/callback", get(oauth_callback))
        .route("/logout", axum::routing::post(logout))
        .route("/me", get(me))
        .route("/client-metadata.json", get(metadata))
        .route("/jwks.json", get(jwks))
        .with_state(state)
}

#[derive(serde::Deserialize)]
struct LoginQuery {
    handle: String,
    /// Optional: redirect URL for CLI login (e.g. http://localhost:19284/callback)
    cli_redirect: Option<String>,
}

/// Step 1: User provides handle → we resolve their PDS, do PAR, redirect to authorization page.
async fn login_start(
    State(state): State<OAuthState>,
    Query(q): Query<LoginQuery>,
) -> Result<Response, OAuthError> {
    let handle = q.handle.trim();

    // Resolve handle to PDS
    let pds_url = resolve_handle_to_pds(&state.http_client, handle).await?;

    // Discover OAuth endpoints from PDS
    let (_, auth_server) = pds_resources(&state.http_client, &pds_url).await
        .map_err(|e| OAuthError::Internal(format!("PDS OAuth discovery failed: {e}")))?;

    // Generate PKCE
    let (pkce_verifier, code_challenge) = pkce::generate();

    // Generate DPoP key
    let dpop_key = generate_key(KeyType::P256Private)
        .map_err(|e| OAuthError::Internal(format!("key gen failed: {e}")))?;

    // Generate state & nonce
    let oauth_state_value = Alphanumeric.sample_string(&mut rand::rng(), 32);
    let nonce = Alphanumeric.sample_string(&mut rand::rng(), 32);

    let oauth_client_config = state.config.to_client_config();
    let oauth_client = OAuthClient {
        redirect_uri: oauth_client_config.redirect_uris.clone(),
        client_id: oauth_client_config.client_id.clone(),
        private_signing_key_data: state.config.signing_key.clone(),
    };

    let oauth_request_state = OAuthRequestState {
        state: oauth_state_value.clone(),
        nonce: nonce.clone(),
        code_challenge,
        scope: "atproto transition:generic".into(),
    };

    // Push Authorization Request
    let par_response = oauth_init(
        &state.http_client,
        &oauth_client,
        &dpop_key,
        Some(handle),
        &auth_server,
        &oauth_request_state,
    )
    .await
    .map_err(|e| OAuthError::Internal(format!("PAR failed: {e}")))?;

    // Store the request for callback verification
    let signing_public_key = to_public(&state.config.signing_key)
        .map_err(|e| OAuthError::Internal(format!("public key derivation: {e}")))?;

    let oauth_request = OAuthRequest {
        oauth_state: oauth_state_value.clone(),
        issuer: auth_server.issuer.clone(),
        authorization_server: pds_url.clone(),
        nonce,
        pkce_verifier,
        signing_public_key: format!("{}", signing_public_key),
        dpop_private_key: format!("{}", dpop_key),
        created_at: Utc::now(),
        expires_at: Utc::now() + chrono::Duration::minutes(10),
    };

    state.request_store.insert_oauth_request(oauth_request).await
        .map_err(|e| OAuthError::Internal(format!("store request: {e}")))?;

    // Store CLI redirect if present
    if let Some(ref cli_redirect) = q.cli_redirect {
        state.cli_redirects.write().await
            .insert(oauth_state_value.clone(), cli_redirect.clone());
    }

    // Build authorization URL
    let auth_url = format!(
        "{}?client_id={}&request_uri={}",
        auth_server.authorization_endpoint,
        urlencoding::encode(&oauth_client.client_id),
        urlencoding::encode(&par_response.request_uri),
    );

    Ok(Redirect::temporary(&auth_url).into_response())
}

#[derive(serde::Deserialize)]
struct CallbackQuery {
    state: String,
    iss: String,
    code: String,
}

/// Step 2: PDS redirects back with code → exchange for tokens → create session → redirect to app.
async fn oauth_callback(
    State(state): State<OAuthState>,
    Query(q): Query<CallbackQuery>,
) -> Result<Response, OAuthError> {
    // Look up the pending request
    let oauth_request = state.request_store
        .get_oauth_request_by_state(&q.state).await
        .map_err(|e| OAuthError::Internal(format!("lookup request: {e}")))?
        .ok_or(OAuthError::BadRequest("invalid or expired OAuth state".into()))?;

    // Verify issuer matches
    if oauth_request.issuer != q.iss {
        return Err(OAuthError::BadRequest(format!(
            "issuer mismatch: expected {}, got {}",
            oauth_request.issuer, q.iss
        )));
    }

    // Recover keys
    let dpop_key = identify_key(&oauth_request.dpop_private_key)
        .map_err(|e| OAuthError::Internal(format!("dpop key: {e}")))?;

    let oauth_client_config = state.config.to_client_config();
    let oauth_client = OAuthClient {
        redirect_uri: oauth_client_config.redirect_uris.clone(),
        client_id: oauth_client_config.client_id.clone(),
        private_signing_key_data: state.config.signing_key.clone(),
    };

    // Get authorization server metadata
    let (_, auth_server) = pds_resources(&state.http_client, &oauth_request.authorization_server).await
        .map_err(|e| OAuthError::Internal(format!("PDS discovery: {e}")))?;

    // Exchange code for tokens
    let token_response = atproto_oauth::workflow::oauth_complete(
        &state.http_client,
        &oauth_client,
        &dpop_key,
        &q.code,
        &oauth_request,
        &auth_server,
    )
    .await
    .map_err(|e| OAuthError::Internal(format!("token exchange: {e}")))?;

    // Clean up the pending request
    let _ = state.request_store.delete_oauth_request_by_state(&q.state).await;

    // Extract DID from token response
    let did = token_response.sub
        .ok_or(OAuthError::Internal("no DID in token response".into()))?;

    // Resolve handle from DID
    let handle = resolve_did_to_handle(&state.http_client, &did).await.ok();

    // Generate session token
    let session_token = Alphanumeric.sample_string(&mut rand::rng(), 64);

    let session = OAuthSession {
        token: session_token.clone(),
        did,
        handle,
        pds_url: Some(oauth_request.authorization_server.clone()),
        access_token: Some(token_response.access_token),
        refresh_token: token_response.refresh_token,
        dpop_key: Some(oauth_request.dpop_private_key.clone()),
        created_at: Utc::now(),
        expires_at: Utc::now() + chrono::Duration::days(30),
    };

    state.session_store.create_session(&session).await
        .map_err(|e| OAuthError::Internal(format!("create session: {e}")))?;

    // Check if this was a CLI login flow
    let cli_redirect = state.cli_redirects.write().await.remove(&q.state);

    if let Some(redirect_url) = cli_redirect {
        // CLI flow: redirect to local server with token
        let url = format!(
            "{}?token={}&did={}&handle={}",
            redirect_url,
            urlencoding::encode(&session_token),
            urlencoding::encode(&session.did),
            urlencoding::encode(session.handle.as_deref().unwrap_or("")),
        );
        Ok(Redirect::temporary(&url).into_response())
    } else {
        // Web flow: set cookie and redirect to app root
        let cookie = Cookie::build((SESSION_COOKIE, session_token))
            .path("/")
            .http_only(true)
            .same_site(SameSite::Lax)
            .max_age(time::Duration::days(30))
            .build();

        let jar = CookieJar::new().add(cookie);

        Ok((jar, Redirect::temporary("/")).into_response())
    }
}

/// Logout: clear session and cookie.
async fn logout(
    State(state): State<OAuthState>,
    jar: CookieJar,
) -> Result<impl IntoResponse, OAuthError> {
    if let Some(cookie) = jar.get(SESSION_COOKIE) {
        let _ = state.session_store.delete_session(cookie.value()).await;
    }

    let removal = Cookie::build((SESSION_COOKIE, ""))
        .path("/")
        .max_age(time::Duration::ZERO)
        .build();

    Ok((jar.remove(removal), axum::http::StatusCode::NO_CONTENT))
}

/// Get current user info.
async fn me(
    user: crate::extractor::AuthUser,
) -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "did": user.did,
        "handle": user.handle,
    }))
}

/// Serve OAuth client metadata.
async fn metadata(State(state): State<OAuthState>) -> impl IntoResponse {
    let config = state.config.to_client_config();
    handle_oauth_metadata(config).await
}

/// Serve JWKS (public keys only — the upstream handle_oauth_jwks leaks private keys).
async fn jwks(State(state): State<OAuthState>) -> impl IntoResponse {
    let keys: Vec<_> = state.config.to_client_config().signing_keys
        .iter()
        .filter_map(|key_data| to_public(key_data).ok())
        .filter_map(|pk| atproto_oauth::jwk::generate(&pk).ok())
        .collect();
    axum::Json(serde_json::json!({ "keys": keys }))
}

// ---- Helpers ----

/// Resolve an AT Protocol handle to a PDS URL.
/// Thin wrapper over the shared `crate::resolve` helpers so the OAuth flow
/// gets OAuth-typed errors.
async fn resolve_handle_to_pds(client: &reqwest::Client, handle: &str) -> Result<String, OAuthError> {
    let (_did, pds) = crate::resolve::resolve_handle(client, handle).await
        .map_err(|e| OAuthError::BadRequest(e.to_string()))?;
    Ok(pds)
}

/// Resolve a DID to a handle (best effort).
async fn resolve_did_to_handle(client: &reqwest::Client, did: &str) -> Result<String, OAuthError> {
    let doc_url = if did.starts_with("did:plc:") {
        format!("https://plc.directory/{}", did)
    } else if did.starts_with("did:web:") {
        let domain = did.strip_prefix("did:web:").unwrap_or("");
        format!("https://{}/.well-known/did.json", domain)
    } else {
        return Err(OAuthError::Internal("unsupported DID method".into()));
    };

    let doc: serde_json::Value = client.get(&doc_url).send().await
        .map_err(|e| OAuthError::Internal(e.to_string()))?
        .json().await
        .map_err(|e| OAuthError::Internal(e.to_string()))?;

    doc["alsoKnownAs"].as_array()
        .and_then(|aliases| {
            aliases.iter()
                .filter_map(|a| a.as_str())
                .find(|a| a.starts_with("at://"))
                .map(|a| a.strip_prefix("at://").unwrap_or(a).to_string())
        })
        .ok_or(OAuthError::Internal("no handle in DID doc".into()))
}

// ---- Error type ----

#[derive(Debug)]
pub enum OAuthError {
    BadRequest(String),
    Internal(String),
}

impl IntoResponse for OAuthError {
    fn into_response(self) -> Response {
        let (status, msg) = match self {
            OAuthError::BadRequest(m) => (axum::http::StatusCode::BAD_REQUEST, m),
            OAuthError::Internal(m) => {
                tracing::error!("OAuth error: {m}");
                (axum::http::StatusCode::INTERNAL_SERVER_ERROR, m)
            }
        };
        (status, axum::Json(serde_json::json!({ "error": msg }))).into_response()
    }
}
