use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};

use crate::{
    audit::AuditEvent,
    config::RuntimeConfig,
    AppState,
};

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct AdminStatusResponse {
    pub version: &'static str,
    pub envelopes_total: usize,
    pub envelopes_acknowledged: usize,
    pub envelopes_active: usize,
    pub identities_total: usize,
    pub auth_mode: String,
    pub token_count: usize,
    pub require_token_for_push: bool,
    pub require_token_for_identity_put: bool,
    pub purge_acknowledged_on_cleanup: bool,
    pub max_message_age_days: Option<i64>,
    pub audit_log_configured: bool,
}

#[derive(Debug, Serialize)]
pub struct AdminConfigResponse {
    pub tokens: Vec<TokenEntry>,
    pub require_token_for_push: bool,
    pub require_token_for_identity_put: bool,
    pub purge_acknowledged_on_cleanup: bool,
    pub max_message_age_days: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct TokenEntry {
    pub index: usize,
    pub hint: String,
}

#[derive(Debug, Deserialize)]
pub struct AdminConfigPut {
    pub require_token_for_push: Option<bool>,
    pub require_token_for_identity_put: Option<bool>,
    pub purge_acknowledged_on_cleanup: Option<bool>,
    pub max_message_age_days: Option<Option<i64>>,
}

#[derive(Debug, Serialize)]
pub struct AddTokenResponse {
    pub index: usize,
    pub token: String,
}

#[derive(Debug, Deserialize)]
pub struct PaginationParams {
    #[serde(default)]
    pub offset: usize,
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_limit() -> usize {
    50
}

#[derive(Debug, Serialize)]
pub struct IdentityListResponse {
    pub offset: usize,
    pub limit: usize,
    pub items: Vec<IdentityListItem>,
}

#[derive(Debug, Serialize)]
pub struct IdentityListItem {
    pub identity_id: String,
    pub aliases: Vec<String>,
    pub updated_at: String,
}

#[derive(Debug, Serialize)]
pub struct AuditLogResponse {
    pub offset: usize,
    pub limit: usize,
    pub lines: Vec<serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Auth helper
// ---------------------------------------------------------------------------

fn require_admin_auth(state: &AppState, headers: &HeaderMap) -> Result<(), Response> {
    let admin_token = match &state.admin_token {
        Some(t) => t,
        None => {
            return Err((
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": { "code": "admin_disabled", "message": "no admin token configured" }
                })),
            )
                .into_response())
        }
    };

    let provided = token_from_headers(headers);
    match provided {
        None => Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "error": { "code": "unauthorized", "message": "missing admin token" }
            })),
        )
            .into_response()),
        Some(ref t) if t == admin_token => Ok(()),
        _ => Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": { "code": "forbidden", "message": "invalid admin token" }
            })),
        )
            .into_response()),
    }
}

fn token_from_headers(headers: &HeaderMap) -> Option<String> {
    if let Some(value) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
        if let Some(token) = value.strip_prefix("Bearer ") {
            let token = token.trim();
            if !token.is_empty() {
                return Some(token.to_string());
            }
        }
    }
    headers
        .get("x-aegis-admin-token")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(|v| v.to_string())
}

fn token_hint(token: &str) -> String {
    if token.len() <= 8 {
        "[token]".to_string()
    } else {
        format!("{}…{}", &token[..4], &token[token.len() - 4..])
    }
}

fn persist(state: &AppState, rt: &RuntimeConfig) {
    rt.save(&state.runtime_config_path);
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

pub async fn admin_status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    if let Err(e) = require_admin_auth(&state, &headers) {
        return e;
    }
    match state.store.metrics().await {
        Ok(m) => {
            let rt = state.runtime.read().unwrap();
            Json(AdminStatusResponse {
                version: env!("CARGO_PKG_VERSION"),
                envelopes_total: m.envelopes_total,
                envelopes_acknowledged: m.envelopes_acknowledged,
                envelopes_active: m.envelopes_active,
                identities_total: m.identities_total,
                auth_mode: format!("{:?}", rt.auth_mode()).to_lowercase(),
                token_count: rt.tokens.len(),
                require_token_for_push: rt.require_token_for_push,
                require_token_for_identity_put: rt.require_token_for_identity_put,
                purge_acknowledged_on_cleanup: rt.purge_acknowledged_on_cleanup,
                max_message_age_days: rt.max_message_age_days,
                audit_log_configured: state.audit.log_path.is_some(),
            })
            .into_response()
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": { "code": "storage_error", "message": "failed to read metrics" } })),
        )
            .into_response(),
    }
}

pub async fn admin_get_config(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    if let Err(e) = require_admin_auth(&state, &headers) {
        return e;
    }
    let rt = state.runtime.read().unwrap();
    Json(AdminConfigResponse {
        tokens: rt
            .tokens
            .iter()
            .enumerate()
            .map(|(i, t)| TokenEntry { index: i, hint: token_hint(t) })
            .collect(),
        require_token_for_push: rt.require_token_for_push,
        require_token_for_identity_put: rt.require_token_for_identity_put,
        purge_acknowledged_on_cleanup: rt.purge_acknowledged_on_cleanup,
        max_message_age_days: rt.max_message_age_days,
    })
    .into_response()
}

pub async fn admin_put_config(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    payload: Result<Json<AdminConfigPut>, axum::extract::rejection::JsonRejection>,
) -> Response {
    if let Err(e) = require_admin_auth(&state, &headers) {
        return e;
    }
    let Json(body) = match payload {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": { "code": "invalid_request", "message": e.body_text() } })),
            )
                .into_response()
        }
    };
    {
        let mut rt = state.runtime.write().unwrap();
        if let Some(v) = body.require_token_for_push {
            rt.require_token_for_push = v;
        }
        if let Some(v) = body.require_token_for_identity_put {
            rt.require_token_for_identity_put = v;
        }
        if let Some(v) = body.purge_acknowledged_on_cleanup {
            rt.purge_acknowledged_on_cleanup = v;
        }
        if let Some(v) = body.max_message_age_days {
            rt.max_message_age_days = v;
        }
        persist(&state, &rt);
    }
    state
        .audit
        .record(AuditEvent {
            at: chrono::Utc::now(),
            operation: "admin_put_config",
            outcome: "ok",
            recipient_id: None,
            envelope_id: None,
            identity_id: None,
            detail: None,
        })
        .await;
    StatusCode::NO_CONTENT.into_response()
}

pub async fn admin_list_tokens(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    if let Err(e) = require_admin_auth(&state, &headers) {
        return e;
    }
    let rt = state.runtime.read().unwrap();
    let tokens: Vec<TokenEntry> = rt
        .tokens
        .iter()
        .enumerate()
        .map(|(i, t)| TokenEntry { index: i, hint: token_hint(t) })
        .collect();
    Json(serde_json::json!({ "tokens": tokens })).into_response()
}

pub async fn admin_add_token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    if let Err(e) = require_admin_auth(&state, &headers) {
        return e;
    }
    let new_token = uuid::Uuid::new_v4().to_string();
    let index = {
        let mut rt = state.runtime.write().unwrap();
        rt.tokens.push(new_token.clone());
        let idx = rt.tokens.len() - 1;
        persist(&state, &rt);
        idx
    };
    state
        .audit
        .record(AuditEvent {
            at: chrono::Utc::now(),
            operation: "admin_add_token",
            outcome: "ok",
            recipient_id: None,
            envelope_id: None,
            identity_id: None,
            detail: Some(&format!("index={index}")),
        })
        .await;
    Json(AddTokenResponse { index, token: new_token }).into_response()
}

pub async fn admin_revoke_token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(index): Path<usize>,
) -> Response {
    if let Err(e) = require_admin_auth(&state, &headers) {
        return e;
    }
    let removed = {
        let mut rt = state.runtime.write().unwrap();
        if index >= rt.tokens.len() {
            false
        } else {
            rt.tokens.remove(index);
            persist(&state, &rt);
            true
        }
    };
    if removed {
        state
            .audit
            .record(AuditEvent {
                at: chrono::Utc::now(),
                operation: "admin_revoke_token",
                outcome: "ok",
                recipient_id: None,
                envelope_id: None,
                identity_id: None,
                detail: Some(&format!("index={index}")),
            })
            .await;
        StatusCode::NO_CONTENT.into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": { "code": "not_found", "message": "token index out of range" } })),
        )
            .into_response()
    }
}

pub async fn admin_cleanup(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    if let Err(e) = require_admin_auth(&state, &headers) {
        return e;
    }
    let policy = state.runtime.read().unwrap().retention_policy();
    match state.store.cleanup(&policy).await {
        Ok(report) => {
            state
                .audit
                .record(AuditEvent {
                    at: chrono::Utc::now(),
                    operation: "admin_cleanup",
                    outcome: "ok",
                    recipient_id: None,
                    envelope_id: None,
                    identity_id: None,
                    detail: Some(&format!(
                        "expired={} orphan={} old={}",
                        report.expired_removed, report.orphan_ack_removed, report.old_removed
                    )),
                })
                .await;
            Json(serde_json::json!({
                "expired_removed": report.expired_removed,
                "orphan_ack_removed": report.orphan_ack_removed,
                "old_removed": report.old_removed,
            }))
            .into_response()
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": { "code": "storage_error", "message": "cleanup failed" } })),
        )
            .into_response(),
    }
}

pub async fn admin_list_identities(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<PaginationParams>,
) -> Response {
    if let Err(e) = require_admin_auth(&state, &headers) {
        return e;
    }
    let limit = params.limit.min(200);
    match state.store.list_identities(params.offset, limit).await {
        Ok(entries) => Json(IdentityListResponse {
            offset: params.offset,
            limit,
            items: entries
                .into_iter()
                .map(|e| IdentityListItem {
                    identity_id: e.identity_id,
                    aliases: e.aliases,
                    updated_at: e.updated_at,
                })
                .collect(),
        })
        .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": { "code": "storage_error", "message": "failed to list identities" } })),
        )
            .into_response(),
    }
}

pub async fn admin_audit_log(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<PaginationParams>,
) -> Response {
    if let Err(e) = require_admin_auth(&state, &headers) {
        return e;
    }
    let Some(log_path) = &state.audit.log_path else {
        return Json(serde_json::json!({
            "error": { "code": "not_configured", "message": "audit log path not configured" }
        }))
        .into_response();
    };

    let path = log_path.clone();
    let offset = params.offset;
    let limit = params.limit.min(500);

    let result = tokio::task::spawn_blocking(move || {
        let content = std::fs::read_to_string(&path)?;
        let lines: Vec<serde_json::Value> = content
            .lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| serde_json::from_str(l).ok())
            .skip(offset)
            .take(limit)
            .collect();
        Ok::<_, std::io::Error>(lines)
    })
    .await;

    match result {
        Ok(Ok(lines)) => Json(AuditLogResponse { offset, limit, lines }).into_response(),
        Ok(Err(e)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": { "code": "io_error", "message": e.to_string() } })),
        )
            .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": { "code": "internal_error", "message": "task panicked" } })),
        )
            .into_response(),
    }
}
