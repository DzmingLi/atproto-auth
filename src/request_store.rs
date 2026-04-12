use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use atproto_oauth::storage::OAuthRequestStorage;
use atproto_oauth::workflow::OAuthRequest;
use tokio::sync::RwLock;

/// In-memory storage for pending OAuth authorization requests.
/// Sufficient for single-instance deployments. Requests are lost on restart,
/// which only affects in-flight OAuth flows (not established sessions).
#[derive(Clone)]
pub struct MemoryRequestStore {
    inner: Arc<RwLock<HashMap<String, OAuthRequest>>>,
}

impl MemoryRequestStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl OAuthRequestStorage for MemoryRequestStore {
    async fn get_oauth_request_by_state(&self, state: &str) -> anyhow::Result<Option<OAuthRequest>> {
        let map = self.inner.read().await;
        Ok(map.get(state).cloned())
    }

    async fn insert_oauth_request(&self, request: OAuthRequest) -> anyhow::Result<()> {
        let mut map = self.inner.write().await;
        map.insert(request.oauth_state.clone(), request);
        Ok(())
    }

    async fn delete_oauth_request_by_state(&self, state: &str) -> anyhow::Result<()> {
        let mut map = self.inner.write().await;
        map.remove(state);
        Ok(())
    }

    async fn clear_expired_oauth_requests(&self) -> anyhow::Result<u64> {
        let mut map = self.inner.write().await;
        let now = chrono::Utc::now();
        let before = map.len();
        map.retain(|_, req| req.expires_at > now);
        Ok((before - map.len()) as u64)
    }
}
