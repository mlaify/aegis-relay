use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    Open,
    Token,
}

/// Mutable runtime configuration — overlays env-var defaults and is
/// persisted to `aegis-relay-runtime.json` on every admin write.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeConfig {
    /// Relay user tokens (distinct from the admin token).
    pub tokens: Vec<String>,
    pub require_token_for_push: bool,
    pub require_token_for_identity_put: bool,
    pub purge_acknowledged_on_cleanup: bool,
    pub max_message_age_days: Option<i64>,
}

impl RuntimeConfig {
    pub fn auth_mode(&self) -> AuthMode {
        if self.tokens.is_empty() {
            AuthMode::Open
        } else {
            AuthMode::Token
        }
    }

    /// Build a `RetentionPolicy` snapshot from the current runtime config.
    pub fn retention_policy(&self) -> RetentionPolicy {
        RetentionPolicy {
            purge_acknowledged_on_cleanup: self.purge_acknowledged_on_cleanup,
            max_message_age_days: self.max_message_age_days,
        }
    }

    /// Persist the config to a JSON file, ignoring I/O errors (best-effort).
    pub fn save(&self, path: &PathBuf) {
        if let Ok(json) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write(path, json);
        }
    }

    /// Load a previously-persisted override file, returning `None` on any error.
    pub fn load_from_file(path: &PathBuf) -> Option<Self> {
        let data = std::fs::read_to_string(path).ok()?;
        serde_json::from_str(&data).ok()
    }
}

#[derive(Debug, Clone)]
pub struct RetentionPolicy {
    pub purge_acknowledged_on_cleanup: bool,
    pub max_message_age_days: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct RelayConfig {
    pub bind: String,
    pub db_path: String,
    pub admin_token: Option<String>,
    pub runtime_config_path: PathBuf,
    pub audit_log_path: Option<PathBuf>,
    /// Externally reachable base URL of this relay (e.g. `https://relay.company.com`).
    /// Advertised in `/.well-known/aegis-config` so clients can discover where
    /// to reach the relay independent of bind address.
    pub public_url: Option<String>,
    /// Initial runtime config (env-var defaults, optionally overlaid from file).
    pub runtime: RuntimeConfig,
}

impl RelayConfig {
    pub fn from_env() -> Self {
        let bind = std::env::var("AEGIS_RELAY_BIND").unwrap_or_else(|_| "0.0.0.0:8787".to_string());
        let db_path =
            std::env::var("AEGIS_DB_PATH").unwrap_or_else(|_| "aegis-relay.db".to_string());
        let audit_log_path = std::env::var("AEGIS_RELAY_AUDIT_LOG_PATH")
            .ok()
            .map(PathBuf::from);
        let admin_token = std::env::var("AEGIS_RELAY_ADMIN_TOKEN")
            .ok()
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty());
        let runtime_config_path = std::env::var("AEGIS_RELAY_RUNTIME_CONFIG_PATH")
            .ok()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("aegis-relay-runtime.json"));

        let mut tokens = std::env::var("AEGIS_RELAY_AUTH_TOKENS")
            .ok()
            .map(|v| {
                v.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        if tokens.is_empty() {
            if let Ok(single) = std::env::var("AEGIS_RELAY_CAPABILITY_TOKEN") {
                let single = single.trim().to_string();
                if !single.is_empty() {
                    tokens.push(single);
                }
            }
        }

        let mut runtime = RuntimeConfig {
            tokens,
            require_token_for_push: bool_env("AEGIS_RELAY_REQUIRE_TOKEN_FOR_PUSH", false),
            require_token_for_identity_put: bool_env(
                "AEGIS_RELAY_REQUIRE_TOKEN_FOR_IDENTITY_PUT",
                true,
            ),
            purge_acknowledged_on_cleanup: bool_env("AEGIS_RELAY_PURGE_ACKED_ON_CLEANUP", true),
            max_message_age_days: std::env::var("AEGIS_RELAY_MAX_MESSAGE_AGE_DAYS")
                .ok()
                .and_then(|v| v.parse::<i64>().ok())
                .filter(|v| *v > 0),
        };

        // Overlay with persisted runtime config if the file exists.
        if let Some(overlay) = RuntimeConfig::load_from_file(&runtime_config_path) {
            runtime = overlay;
        }

        let public_url = std::env::var("AEGIS_RELAY_PUBLIC_URL")
            .ok()
            .map(|v| v.trim().trim_end_matches('/').to_string())
            .filter(|v| !v.is_empty());

        Self {
            bind,
            db_path,
            admin_token,
            runtime_config_path,
            audit_log_path,
            public_url,
            runtime,
        }
    }

    pub fn into_shared_runtime(self) -> Arc<RwLock<RuntimeConfig>> {
        Arc::new(RwLock::new(self.runtime))
    }
}

fn bool_env(name: &str, default: bool) -> bool {
    match std::env::var(name) {
        Ok(v) => matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"),
        Err(_) => default,
    }
}
