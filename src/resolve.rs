//! AT Protocol identity resolution: handle → DID → PDS.
//!
//! Shared helpers used by both the OAuth flow and downstream apps that need
//! to resolve handles outside the OAuth path (e.g. adding a collaborator by
//! handle, or looking up a PDS URL for `getRecord`).

use anyhow::{Context, Result, anyhow, bail};

/// Resolve a handle (e.g. `alice.bsky.social`) to its DID.
///
/// Tries `https://{handle}/.well-known/atproto-did` first so self-hosted
/// handles work without depending on bsky.social, then falls back to the
/// public Bluesky resolver. `did:` inputs are returned unchanged.
pub async fn resolve_handle_to_did(client: &reqwest::Client, handle: &str) -> Result<String> {
    if handle.starts_with("did:") {
        return Ok(handle.to_string());
    }

    if handle.contains('.') {
        let url = format!("https://{handle}/.well-known/atproto-did");
        if let Ok(resp) = client.get(&url).send().await
            && resp.status().is_success()
        {
            let text = resp.text().await.unwrap_or_default().trim().to_string();
            if text.starts_with("did:") {
                return Ok(text);
            }
        }
    }

    let url = format!(
        "https://bsky.social/xrpc/com.atproto.identity.resolveHandle?handle={}",
        urlencoding::encode(handle)
    );
    let resp = client.get(&url).send().await
        .with_context(|| format!("resolve handle {handle}"))?;
    if !resp.status().is_success() {
        bail!("cannot resolve handle: {handle}");
    }
    let body: serde_json::Value = resp.json().await
        .with_context(|| format!("parse resolveHandle response for {handle}"))?;
    body["did"].as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("handle {handle} did not resolve to a DID"))
}

/// Fetch a DID's DID document URL. Only supports did:plc and did:web.
fn did_doc_url(did: &str) -> Result<String> {
    if let Some(_plc) = did.strip_prefix("did:plc:") {
        Ok(format!("https://plc.directory/{did}"))
    } else if let Some(host) = did.strip_prefix("did:web:") {
        Ok(format!("https://{host}/.well-known/did.json"))
    } else {
        bail!("unsupported DID method: {did}")
    }
}

/// Resolve a DID to the PDS service endpoint from its DID document.
///
/// Matches on either `#atproto_pds` service id or `AtprotoPersonalDataServer`
/// service type so both styles of DID docs (current and legacy) work.
pub async fn resolve_did_to_pds(client: &reqwest::Client, did: &str) -> Result<String> {
    let url = did_doc_url(did)?;
    let doc: serde_json::Value = client.get(&url).send().await
        .with_context(|| format!("fetch DID doc for {did}"))?
        .json().await
        .with_context(|| format!("parse DID doc for {did}"))?;

    let services = doc.get("service").and_then(|s| s.as_array())
        .ok_or_else(|| anyhow!("no services in DID doc for {did}"))?;

    for svc in services {
        let id = svc.get("id").and_then(|v| v.as_str()).unwrap_or("");
        let ty = svc.get("type").and_then(|v| v.as_str()).unwrap_or("");
        let is_pds = id == "#atproto_pds" || ty == "AtprotoPersonalDataServer";
        if is_pds && let Some(endpoint) = svc.get("serviceEndpoint").and_then(|v| v.as_str()) {
            return Ok(endpoint.to_string());
        }
    }
    bail!("no PDS service endpoint for {did}")
}

/// One-shot: handle → (DID, PDS URL).
pub async fn resolve_handle(client: &reqwest::Client, handle: &str) -> Result<(String, String)> {
    let did = resolve_handle_to_did(client, handle).await?;
    let pds = resolve_did_to_pds(client, &did).await?;
    Ok((did, pds))
}
