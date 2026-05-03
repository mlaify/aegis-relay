use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    Open,
    Token,
}

#[derive(Debug, Clone)]
pub struct RelayAuthConfig {
    pub mode: AuthMode,
    pub tokens: Vec<String>,
    pub require_token_for_push: bool,
    pub require_token_for_identity_put: bool,
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
    pub auth: RelayAuthConfig,
    pub retention: RetentionPolicy,
    pub audit_log_path: Option<PathBuf>,
}

impl RelayConfig {
    pub fn from_env() -> Self {
        let bind = std::env::var("AEGIS_RELAY_BIND").unwrap_or_else(|_| "0.0.0.0:8787".to_string());
        let db_path =
            std::env::var("AEGIS_DB_PATH").unwrap_or_else(|_| "aegis-relay.db".to_string());
        let audit_log_path = std::env::var("AEGIS_RELAY_AUDIT_LOG_PATH")
            .ok()
            .map(PathBuf::from);

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

        let mode = if tokens.is_empty() {
            AuthMode::Open
        } else {
            AuthMode::Token
        };

        let auth = RelayAuthConfig {
            mode,
            tokens,
            require_token_for_push: bool_env("AEGIS_RELAY_REQUIRE_TOKEN_FOR_PUSH", false),
            require_token_for_identity_put: bool_env(
                "AEGIS_RELAY_REQUIRE_TOKEN_FOR_IDENTITY_PUT",
                true,
            ),
        };

        let retention = RetentionPolicy {
            purge_acknowledged_on_cleanup: bool_env("AEGIS_RELAY_PURGE_ACKED_ON_CLEANUP", true),
            max_message_age_days: std::env::var("AEGIS_RELAY_MAX_MESSAGE_AGE_DAYS")
                .ok()
                .and_then(|v| v.parse::<i64>().ok())
                .filter(|v| *v > 0),
        };

        Self {
            bind,
            db_path,
            auth,
            retention,
            audit_log_path,
        }
    }
}

fn bool_env(name: &str, default: bool) -> bool {
    match std::env::var(name) {
        Ok(v) => matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"),
        Err(_) => default,
    }
}
