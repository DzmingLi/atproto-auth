use async_trait::async_trait;
use chrono::{DateTime, Utc};

/// An authenticated OAuth session.
#[derive(Debug, Clone)]
pub struct OAuthSession {
    pub token: String,
    pub did: String,
    pub handle: Option<String>,
    /// The user's PDS endpoint (e.g. "https://pds.example.com")
    pub pds_url: Option<String>,
    /// DPoP-bound access token for XRPC calls
    pub access_token: Option<String>,
    /// Refresh token for obtaining new access tokens
    pub refresh_token: Option<String>,
    /// DPoP private key (serialized) for making authenticated requests
    pub dpop_key: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Trait for session persistence. Implement for your storage backend.
#[async_trait]
pub trait SessionStore: Send + Sync {
    async fn create_session(&self, session: &OAuthSession) -> anyhow::Result<()>;
    async fn get_session(&self, token: &str) -> anyhow::Result<Option<OAuthSession>>;
    async fn delete_session(&self, token: &str) -> anyhow::Result<()>;
    async fn delete_sessions_for_did(&self, did: &str) -> anyhow::Result<()>;
}

/// PostgreSQL session store.
pub struct PgSessionStore {
    pool: sqlx::PgPool,
}

impl PgSessionStore {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }

    /// SQL to create the oauth_sessions table. Run this as a migration.
    pub const MIGRATION: &str = r#"
CREATE TABLE IF NOT EXISTS oauth_sessions (
    token VARCHAR(128) PRIMARY KEY,
    did VARCHAR(255) NOT NULL,
    handle VARCHAR(255),
    pds_url VARCHAR(512),
    access_token TEXT,
    refresh_token TEXT,
    dpop_key TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_oauth_sessions_did ON oauth_sessions(did);
"#;
}

#[async_trait]
impl SessionStore for PgSessionStore {
    async fn create_session(&self, s: &OAuthSession) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO oauth_sessions (token, did, handle, pds_url, access_token, refresh_token, dpop_key, created_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
             ON CONFLICT (token) DO UPDATE SET \
             did = $2, handle = $3, pds_url = $4, access_token = $5, refresh_token = $6, dpop_key = $7, expires_at = $9"
        )
        .bind(&s.token)
        .bind(&s.did)
        .bind(&s.handle)
        .bind(&s.pds_url)
        .bind(&s.access_token)
        .bind(&s.refresh_token)
        .bind(&s.dpop_key)
        .bind(s.created_at)
        .bind(s.expires_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_session(&self, token: &str) -> anyhow::Result<Option<OAuthSession>> {
        let row: Option<(
            String, String, Option<String>, Option<String>,
            Option<String>, Option<String>, Option<String>,
            DateTime<Utc>, DateTime<Utc>,
        )> = sqlx::query_as(
            "SELECT token, did, handle, pds_url, access_token, refresh_token, dpop_key, created_at, expires_at \
             FROM oauth_sessions WHERE token = $1 AND expires_at > NOW()"
        )
        .bind(token)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|(token, did, handle, pds_url, access_token, refresh_token, dpop_key, created_at, expires_at)| {
            OAuthSession { token, did, handle, pds_url, access_token, refresh_token, dpop_key, created_at, expires_at }
        }))
    }

    async fn delete_session(&self, token: &str) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM oauth_sessions WHERE token = $1")
            .bind(token)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn delete_sessions_for_did(&self, did: &str) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM oauth_sessions WHERE did = $1")
            .bind(did)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
