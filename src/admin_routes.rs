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

// ---------------------------------------------------------------------------
// Domain management
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct DomainListItem {
    pub domain: String,
    pub verification_token: String,
    pub verified: bool,
    pub verified_at: Option<String>,
    pub added_at: String,
}

#[derive(Debug, Serialize)]
pub struct DomainListResponse {
    pub offset: usize,
    pub limit: usize,
    /// Total number of domains claimed (across all pages). Lets callers
    /// render a "showing N of M" summary without a second round-trip.
    pub total: usize,
    pub items: Vec<DomainListItem>,
}

#[derive(Debug, Deserialize)]
pub struct DomainListParams {
    #[serde(default)]
    pub offset: usize,
    #[serde(default = "default_limit")]
    pub limit: usize,
}

#[derive(Debug, Deserialize)]
pub struct ClaimDomainRequest {
    pub domain: String,
}

#[derive(Debug, Serialize)]
pub struct ClaimDomainResponse {
    pub domain: String,
    pub verification_record: String,
    pub verification_token: String,
    pub verified: bool,
}

#[derive(Debug, Serialize)]
pub struct VerifyDomainResponse {
    pub domain: String,
    pub verified: bool,
    pub detail: Option<String>,
}

fn domain_entry_to_item(e: crate::storage::DomainEntry) -> DomainListItem {
    DomainListItem {
        verified: e.verified_at.is_some(),
        domain: e.domain,
        verification_token: e.verification_token,
        verified_at: e.verified_at,
        added_at: e.added_at,
    }
}

/// Classified failure modes from the DNS TXT lookup that backs
/// `admin_verify_domain`. Kept narrow: most callers only care about the
/// "no record yet" vs "transient timeout" distinction so the SPA can
/// give operator-actionable advice (mlaify/aegis-relay#34).
#[derive(Debug)]
enum VerifyDnsError {
    /// Authoritative answer with no TXT records (covers NXDOMAIN too —
    /// hickory collapses both into `NoRecordsFound`). Operator action:
    /// publish the record from the claim response.
    NoRecord,
    /// Hickory gave up after the configured timeout window.
    Timeout,
    /// Anything else from the resolver — surfaced verbatim.
    Other(String),
}

/// How long (in seconds) the DNS verify lookup waits before giving up.
/// Read at lookup time so operators can tune live without a redeploy.
fn verify_timeout_secs() -> u64 {
    parse_verify_timeout_secs(
        std::env::var("AEGIS_DNS_VERIFY_TIMEOUT_SECS").ok().as_deref(),
    )
}

fn parse_verify_timeout_secs(raw: Option<&str>) -> u64 {
    raw.and_then(|v| v.parse::<u64>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(3)
}

/// Build the hickory `ResolverOpts` used by `admin_verify_domain`.
/// Pulled out as a pure function so tests can inject the env-var value
/// without `set_var` (which races against parallel tests).
///
/// Defaults differ from `ResolverOpts::default()` on two axes:
///   - `timeout`: 3s (vs hickory's 5s)
///   - `attempts`: 1 (vs hickory's 2)
/// Combined: a missing record fails in ~3s instead of ~10s+. Verified
/// records aren't affected — the cap is on the outright-fail path.
fn build_verify_resolver_opts_with(timeout_secs_env: Option<&str>) -> hickory_resolver::config::ResolverOpts {
    let timeout_secs = parse_verify_timeout_secs(timeout_secs_env);
    let mut opts = hickory_resolver::config::ResolverOpts::default();
    opts.timeout = std::time::Duration::from_secs(timeout_secs);
    opts.attempts = 1;
    opts
}

fn normalize_domain(input: &str) -> Option<String> {
    let d = input.trim().trim_end_matches('.').to_ascii_lowercase();
    if d.is_empty() || d.contains('/') || d.contains(' ') || !d.contains('.') {
        return None;
    }
    Some(d)
}

pub async fn admin_list_domains(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<DomainListParams>,
) -> Response {
    if let Err(e) = require_admin_auth(&state, &headers) {
        return e;
    }
    // Cap the per-page limit so a malicious or buggy client can't pull
    // every domain in one shot. Mirrors the cap on `admin_list_users`.
    let limit = params.limit.min(200);
    let total = match state.store.count_served_domains().await {
        Ok(n) => n,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": { "code": "storage_error", "message": "count domains failed" } })),
            )
                .into_response()
        }
    };
    match state.store.list_served_domains(params.offset, limit).await {
        Ok(entries) => Json(DomainListResponse {
            offset: params.offset,
            limit,
            total,
            items: entries.into_iter().map(domain_entry_to_item).collect(),
        })
        .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": { "code": "storage_error", "message": "list domains failed" } })),
        )
            .into_response(),
    }
}

pub async fn admin_claim_domain(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    payload: Result<Json<ClaimDomainRequest>, axum::extract::rejection::JsonRejection>,
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
    let domain = match normalize_domain(&body.domain) {
        Some(d) => d,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": { "code": "invalid_domain", "message": "domain must be a non-empty hostname with at least one dot" } })),
            )
                .into_response()
        }
    };
    let token = format!("aegis-verify-{}", uuid::Uuid::new_v4().simple());
    match state.store.add_served_domain(&domain, &token).await {
        Ok(entry) => {
            state
                .audit
                .record(AuditEvent {
                    at: chrono::Utc::now(),
                    operation: "admin_claim_domain",
                    outcome: "ok",
                    recipient_id: None,
                    envelope_id: None,
                    identity_id: None,
                    detail: Some(&format!("domain={}", entry.domain)),
                })
                .await;
            let verified = entry.verified_at.is_some();
            Json(ClaimDomainResponse {
                verification_record: format!(
                    "_aegis-verify.{}. IN TXT \"{}\"",
                    entry.domain, entry.verification_token
                ),
                domain: entry.domain,
                verification_token: entry.verification_token,
                verified,
            })
            .into_response()
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": { "code": "storage_error", "message": "claim failed" } })),
        )
            .into_response(),
    }
}

pub async fn admin_verify_domain(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(domain): Path<String>,
) -> Response {
    if let Err(e) = require_admin_auth(&state, &headers) {
        return e;
    }
    let domain = match normalize_domain(&domain) {
        Some(d) => d,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": { "code": "invalid_domain", "message": "invalid domain" } })),
            )
                .into_response()
        }
    };
    let entry = match state.store.get_served_domain(&domain).await {
        Ok(Some(e)) => e,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "error": { "code": "not_found", "message": "domain not claimed" } })),
            )
                .into_response()
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": { "code": "storage_error", "message": "lookup failed" } })),
            )
                .into_response()
        }
    };

    let verify_target = format!("_aegis-verify.{}", domain);
    let timeout_secs = verify_timeout_secs();
    let lookup = tokio::task::spawn_blocking(move || -> Result<Vec<String>, VerifyDnsError> {
        use hickory_resolver::config::ResolverConfig;
        use hickory_resolver::error::ResolveErrorKind;
        use hickory_resolver::Resolver;

        let opts = build_verify_resolver_opts_with(
            std::env::var("AEGIS_DNS_VERIFY_TIMEOUT_SECS").ok().as_deref(),
        );
        let resolver = Resolver::new(ResolverConfig::default(), opts)
            .map_err(|e| VerifyDnsError::Other(e.to_string()))?;

        match resolver.txt_lookup(verify_target) {
            Ok(txts) => Ok(txts
                .into_iter()
                .flat_map(|r| {
                    r.txt_data()
                        .iter()
                        .map(|d| String::from_utf8_lossy(d).to_string())
                        .collect::<Vec<_>>()
                })
                .collect()),
            Err(e) => Err(match e.kind() {
                // hickory returns NoRecordsFound both for NXDOMAIN and
                // "domain exists but no TXT records published" — for
                // operator-facing UX they mean the same thing: there's
                // nothing at the verify name yet.
                ResolveErrorKind::NoRecordsFound { .. } => VerifyDnsError::NoRecord,
                // Explicit timeout. With our 3s default + 1 attempt
                // this should fire ~3s after the click rather than
                // the 10s+ that hickory's defaults produced.
                ResolveErrorKind::Timeout => VerifyDnsError::Timeout,
                // Most other proto-layer errors aren't transient; surface
                // the raw message and let the operator decide.
                _ => VerifyDnsError::Other(e.to_string()),
            }),
        }
    })
    .await;

    let detail;
    let verified = match lookup {
        Ok(Ok(values)) => {
            let found = values.iter().any(|v| v == &entry.verification_token);
            if !found {
                detail = Some(format!(
                    "expected TXT \"{}\" at _aegis-verify.{} (found {} record(s))",
                    entry.verification_token, domain, values.len()
                ));
            } else {
                detail = None;
            }
            found
        }
        Ok(Err(VerifyDnsError::NoRecord)) => {
            detail = Some(format!(
                "no TXT record published at _aegis-verify.{}; \
                 publish the record from the claim response and retry",
                domain
            ));
            false
        }
        Ok(Err(VerifyDnsError::Timeout)) => {
            detail = Some(format!(
                "DNS lookup for _aegis-verify.{} timed out after {}s; \
                 retry in a moment (your record may still be propagating)",
                domain, timeout_secs
            ));
            false
        }
        Ok(Err(VerifyDnsError::Other(msg))) => {
            detail = Some(format!("DNS lookup failed: {msg}"));
            false
        }
        Err(_) => {
            detail = Some("verification task panicked".to_string());
            false
        }
    };

    if verified {
        let _ = state.store.mark_domain_verified(&domain).await;
    }

    state
        .audit
        .record(AuditEvent {
            at: chrono::Utc::now(),
            operation: "admin_verify_domain",
            outcome: if verified { "ok" } else { "failed" },
            recipient_id: None,
            envelope_id: None,
            identity_id: None,
            detail: Some(&format!("domain={}", domain)),
        })
        .await;

    Json(VerifyDomainResponse { domain, verified, detail }).into_response()
}

pub async fn admin_release_domain(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(domain): Path<String>,
) -> Response {
    if let Err(e) = require_admin_auth(&state, &headers) {
        return e;
    }
    let domain = match normalize_domain(&domain) {
        Some(d) => d,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": { "code": "invalid_domain", "message": "invalid domain" } })),
            )
                .into_response()
        }
    };
    match state.store.release_served_domain(&domain).await {
        Ok(removed) => {
            state
                .audit
                .record(AuditEvent {
                    at: chrono::Utc::now(),
                    operation: "admin_release_domain",
                    outcome: "ok",
                    recipient_id: None,
                    envelope_id: None,
                    identity_id: None,
                    detail: Some(&format!("domain={} aliases_removed={}", domain, removed)),
                })
                .await;
            Json(serde_json::json!({ "domain": domain, "aliases_removed": removed })).into_response()
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": { "code": "storage_error", "message": "release failed" } })),
        )
            .into_response(),
    }
}

// ---------------------------------------------------------------------------
// User provisioning
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct UserListParams {
    #[serde(default)]
    pub offset: usize,
    #[serde(default = "default_limit")]
    pub limit: usize,
    pub domain: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct UserListItem {
    pub alias: String,
    pub identity_id: Option<String>,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Serialize)]
pub struct UserListResponse {
    pub offset: usize,
    pub limit: usize,
    pub items: Vec<UserListItem>,
}

#[derive(Debug, Deserialize)]
pub struct ProvisionUserRequest {
    pub alias: String,
}

/// Body of `DELETE /admin/users/:alias`. Returned with HTTP 200 (not 204)
/// so callers can read the count — flipping from "204 No Content" is the
/// breaking change tracked in #24, but no production deployments yet.
#[derive(Debug, Serialize)]
pub struct DeprovisionUserResponse {
    pub alias: String,
    pub envelopes_purged: u64,
}

pub async fn admin_list_users(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<UserListParams>,
) -> Response {
    if let Err(e) = require_admin_auth(&state, &headers) {
        return e;
    }
    let limit = params.limit.min(200);
    match state
        .store
        .list_provisioned_users(params.domain.as_deref(), params.offset, limit)
        .await
    {
        Ok(entries) => Json(UserListResponse {
            offset: params.offset,
            limit,
            items: entries
                .into_iter()
                .map(|e| UserListItem {
                    alias: e.alias,
                    identity_id: e.identity_id,
                    status: e.status,
                    created_at: e.created_at,
                    updated_at: e.updated_at,
                })
                .collect(),
        })
        .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": { "code": "storage_error", "message": "list users failed" } })),
        )
            .into_response(),
    }
}

pub async fn admin_provision_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    payload: Result<Json<ProvisionUserRequest>, axum::extract::rejection::JsonRejection>,
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
    let alias = body.alias.trim().to_ascii_lowercase();
    if !alias.contains('@') || alias.starts_with('@') || alias.ends_with('@') {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": { "code": "invalid_alias", "message": "alias must be in user@domain form" } })),
        )
            .into_response();
    }
    match state.store.provision_user(&alias).await {
        Ok(crate::storage::ProvisionOutcome::Created) => {
            state
                .audit
                .record(AuditEvent {
                    at: chrono::Utc::now(),
                    operation: "admin_provision_user",
                    outcome: "ok",
                    recipient_id: None,
                    envelope_id: None,
                    identity_id: None,
                    detail: Some(&format!("alias={}", alias)),
                })
                .await;
            (
                StatusCode::CREATED,
                Json(serde_json::json!({ "alias": alias, "status": "provisioned" })),
            )
                .into_response()
        }
        Ok(crate::storage::ProvisionOutcome::AlreadyExists) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({ "error": { "code": "already_exists", "message": "alias is already provisioned" } })),
        )
            .into_response(),
        Ok(crate::storage::ProvisionOutcome::DomainNotServed) => (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": { "code": "domain_not_served", "message": "alias domain is not served by this relay" } })),
        )
            .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": { "code": "storage_error", "message": "provision failed" } })),
        )
            .into_response(),
    }
}

pub async fn admin_deprovision_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(alias): Path<String>,
) -> Response {
    if let Err(e) = require_admin_auth(&state, &headers) {
        return e;
    }
    let alias = alias.trim().to_ascii_lowercase();
    match state.store.deprovision_user(&alias).await {
        Ok(outcome) if outcome.alias_removed => {
            state
                .audit
                .record(AuditEvent {
                    at: chrono::Utc::now(),
                    operation: "admin_deprovision_user",
                    outcome: "ok",
                    recipient_id: None,
                    envelope_id: None,
                    identity_id: None,
                    detail: Some(&format!(
                        "alias={} envelopes_purged={}",
                        alias, outcome.envelopes_purged
                    )),
                })
                .await;
            Json(DeprovisionUserResponse {
                alias,
                envelopes_purged: outcome.envelopes_purged,
            })
            .into_response()
        }
        Ok(_) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": { "code": "not_found", "message": "alias not provisioned" } })),
        )
            .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": { "code": "storage_error", "message": "deprovision failed" } })),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // --- DNS verify resolver options (mlaify/aegis-relay#34) -----------

    #[test]
    fn parse_verify_timeout_defaults_to_three_seconds() {
        // No env var set → 3s default. Chosen to be tight enough that
        // the SPA Verify button doesn't feel hung when the TXT record
        // is missing, loose enough that real lookups against slow
        // resolvers (corporate split-horizon, captive portals) still
        // succeed.
        assert_eq!(parse_verify_timeout_secs(None), 3);
    }

    #[test]
    fn parse_verify_timeout_honors_env_var() {
        assert_eq!(parse_verify_timeout_secs(Some("7")), 7);
        assert_eq!(parse_verify_timeout_secs(Some("30")), 30);
    }

    #[test]
    fn parse_verify_timeout_falls_back_on_invalid_input() {
        // Garbage / negatives / floats / empty all collapse to default.
        // Operators editing .env shouldn't be able to silently shoot
        // themselves in the foot.
        assert_eq!(parse_verify_timeout_secs(Some("nope")), 3);
        assert_eq!(parse_verify_timeout_secs(Some("")), 3);
        assert_eq!(parse_verify_timeout_secs(Some("3.5")), 3);
        assert_eq!(parse_verify_timeout_secs(Some("-1")), 3);
    }

    #[test]
    fn parse_verify_timeout_zero_falls_back_to_default() {
        // Zero would mean "never timeout" in some libs; here it'd be
        // an instant-fail. Either way it's not what an operator
        // intended, so default it.
        assert_eq!(parse_verify_timeout_secs(Some("0")), 3);
    }

    #[test]
    fn build_verify_resolver_opts_uses_short_timeout_and_one_attempt() {
        let opts = build_verify_resolver_opts_with(None);
        assert_eq!(opts.timeout, Duration::from_secs(3));
        assert_eq!(
            opts.attempts, 1,
            "we want one attempt so a missing record fails fast — \
             hickory's default of 2 doubles the perceived latency"
        );
    }

    #[test]
    fn build_verify_resolver_opts_threads_env_through() {
        let opts = build_verify_resolver_opts_with(Some("12"));
        assert_eq!(opts.timeout, Duration::from_secs(12));
        // attempts stays pinned at 1 regardless of the env timeout —
        // operators don't get to dial up retries on this code path.
        assert_eq!(opts.attempts, 1);
    }
}
