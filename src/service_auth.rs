use atproto_identity::key::identify_key;
use atproto_oauth::dpop::request_dpop;
use reqwest_chain::ChainMiddleware;
use reqwest_middleware::ClientBuilder;
use atproto_oauth::dpop::DpopRetry;

use crate::session::OAuthSession;

/// Call PDS `com.atproto.server.getServiceAuth` using the user's OAuth session,
/// then return a service auth token that can authenticate XRPC calls to a third-party service.
///
/// - `session`: the user's OAuth session (must have access_token, dpop_key, pds_url)
/// - `audience_did`: the DID of the service to authenticate to (e.g. `did:web:knot.example.com`)
/// - `lxm`: the XRPC method being authorized (e.g. `sh.tangled.repo.delete`)
pub async fn get_service_auth_token(
    http_client: &reqwest::Client,
    session: &OAuthSession,
    audience_did: &str,
    lxm: &str,
) -> Result<String, String> {
    let access_token = session.access_token.as_deref()
        .ok_or("no access_token in session")?;
    let dpop_key_str = session.dpop_key.as_deref()
        .ok_or("no dpop_key in session")?;
    let pds_url = session.pds_url.as_deref()
        .ok_or("no pds_url in session")?;

    let dpop_key = identify_key(dpop_key_str)
        .map_err(|e| format!("invalid dpop key: {e}"))?;

    let exp = chrono::Utc::now().timestamp() + 60;
    let svc_url = format!(
        "{}/xrpc/com.atproto.server.getServiceAuth?aud={}&lxm={}&exp={}",
        pds_url,
        urlencoding::encode(audience_did),
        urlencoding::encode(lxm),
        exp,
    );

    // Build DPoP proof for this request
    let (dpop_token, dpop_header, dpop_claims) = request_dpop(&dpop_key, "GET", &svc_url, access_token)
        .map_err(|e| format!("dpop proof: {e}"))?;

    let dpop_retry = DpopRetry::new(dpop_header, dpop_claims, dpop_key.clone(), true);

    let dpop_client = ClientBuilder::new(http_client.clone())
        .with(ChainMiddleware::new(dpop_retry))
        .build();

    let resp = dpop_client
        .get(&svc_url)
        .header("DPoP", &dpop_token)
        .header("Authorization", format!("DPoP {}", access_token))
        .send()
        .await
        .map_err(|e| format!("getServiceAuth request: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("getServiceAuth returned {status}: {body}"));
    }

    let body: serde_json::Value = resp.json().await
        .map_err(|e| format!("getServiceAuth parse: {e}"))?;

    body["token"].as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| "no token in getServiceAuth response".into())
}
