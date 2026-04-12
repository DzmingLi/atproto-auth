use atproto_identity::key::{KeyData, KeyType, generate_key, to_public};
use atproto_oauth_axum::state::OAuthClientConfig;

/// Configuration for the AT Protocol OAuth client.
#[derive(Clone)]
pub struct OAuthConfig {
    /// Public URL of this application (e.g. "https://pad.example.com").
    /// Used to construct client_id, redirect_uri, jwks_uri.
    pub public_url: String,
    /// Human-readable application name.
    pub client_name: String,
    /// The P-256 signing key (private). Generated if not provided.
    pub signing_key: KeyData,
}

impl OAuthConfig {
    /// Create config with an auto-generated P-256 signing key (dev mode).
    pub fn new_dev(public_url: impl Into<String>, client_name: impl Into<String>) -> anyhow::Result<Self> {
        let signing_key = generate_key(KeyType::P256Private)?;
        Ok(Self {
            public_url: public_url.into(),
            client_name: client_name.into(),
            signing_key,
        })
    }

    /// Create config with a provided signing key.
    pub fn new(
        public_url: impl Into<String>,
        client_name: impl Into<String>,
        signing_key: KeyData,
    ) -> Self {
        Self {
            public_url: public_url.into(),
            client_name: client_name.into(),
            signing_key,
        }
    }

    /// The OAuth client_id URL (points to client-metadata.json).
    pub fn client_id(&self) -> String {
        format!("{}/oauth/client-metadata.json", self.public_url)
    }

    /// The OAuth callback URL.
    pub fn redirect_uri(&self) -> String {
        format!("{}/oauth/callback", self.public_url)
    }

    /// The JWKS URL.
    pub fn jwks_uri(&self) -> String {
        format!("{}/oauth/jwks.json", self.public_url)
    }

    /// Build the OAuthClientConfig used by atproto-oauth-axum handlers.
    pub fn to_client_config(&self) -> OAuthClientConfig {
        OAuthClientConfig {
            client_id: self.client_id(),
            redirect_uris: self.redirect_uri(),
            jwks_uri: Some(self.jwks_uri()),
            signing_keys: vec![self.signing_key.clone()],
            scope: Some("atproto transition:generic".into()),
            client_name: Some(self.client_name.clone()),
            client_uri: Some(self.public_url.clone()),
            ..Default::default()
        }
    }

    /// Get the public key string for this signing key (multibase-encoded).
    pub fn signing_public_key(&self) -> anyhow::Result<String> {
        let public = to_public(&self.signing_key)?;
        Ok(format!("{}", public))
    }
}
