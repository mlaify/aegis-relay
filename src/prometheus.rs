//! Prometheus text-format exposition for federation metrics
//! (mlaify/aegis-relay#31). Hand-rolled rather than pulling in the
//! `prometheus` crate — the surface is small (a handful of gauges +
//! counters keyed by `target_url`), our snapshot already has the right
//! shape, and avoiding the dep keeps the relay's binary lean.
//!
//! Off by default. Enable via `AEGIS_PROMETHEUS_ENABLED=true`. When
//! disabled the route isn't registered and `GET /metrics` returns 404
//! — a deliberately clean signal vs returning empty bodies, so
//! operators noticing an empty scrape know to flip the flag.
//!
//! No auth on `/metrics`. Prometheus' canonical deployment pattern is
//! "the scrape endpoint is reachable only from the metrics LAN /
//! Tailscale net"; bolting a token check on top would force operators
//! to pre-share secrets with their Prometheus server. Operators can
//! still gate the endpoint at the reverse proxy / firewall.

use std::sync::Arc;

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};

use crate::storage::{FederationMetricsSnapshot, TargetStats};
use crate::AppState;

/// Default sliding-window for the scrape. Matches what the JSON
/// `/admin/federation/metrics` endpoint defaults to so dashboards
/// reading either feel consistent.
const SCRAPE_WINDOW_SECS: i64 = 24 * 60 * 60;

/// Route handler. Wired in `main.rs` only when
/// `AEGIS_PROMETHEUS_ENABLED=true` so the surface is invisible by
/// default. We pull a fresh metrics snapshot per scrape — Prometheus
/// scrape intervals (typically 15-60s) make caching unnecessary.
pub async fn metrics_handler(State(state): State<Arc<AppState>>) -> Response {
    let snapshot = match state.store.federation_metrics(SCRAPE_WINDOW_SECS).await {
        Ok(s) => s,
        Err(_) => {
            // Prometheus' convention is to return non-2xx on scrape
            // failures so the scrape is marked as such in `up{}`.
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "# scrape failed: metrics aggregation error\n",
            )
                .into_response();
        }
    };

    let body = render(&snapshot);
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        body,
    )
        .into_response()
}

/// True iff the operator has opted in via env var. Pulled out as a
/// pure helper so `main.rs` can short-circuit registering the route
/// AND so tests can assert the gate without `set_var`-ing.
pub fn is_enabled() -> bool {
    parse_enabled(std::env::var("AEGIS_PROMETHEUS_ENABLED").ok().as_deref())
}

/// Pure helper backing `is_enabled`. Accepts the canonical "truthy"
/// shapes operators use in shell + .env files.
pub fn parse_enabled(raw: Option<&str>) -> bool {
    let Some(s) = raw else { return false };
    matches!(
        s.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// Convert a metrics snapshot into Prometheus text exposition format.
/// Pure function so tests can pin the on-the-wire format without an
/// HTTP roundtrip. Output is line-stable and ASCII-only — the format
/// spec requires LF terminators and forbids escapable control chars
/// in label values.
pub fn render(snap: &FederationMetricsSnapshot) -> String {
    let mut out = String::new();

    // Queue-level metrics — single-row gauges (no labels).
    queue_gauge(
        &mut out,
        "aegis_federation_queue_pending",
        "Number of envelopes currently in `status='pending'` (regardless of age).",
        snap.queue.pending,
    );
    queue_gauge(
        &mut out,
        "aegis_federation_queue_delivered_recent",
        "Envelopes that flipped to `delivered` in the last 24 hours.",
        snap.queue.delivered_recent,
    );
    queue_gauge(
        &mut out,
        "aegis_federation_queue_expired_recent",
        "Envelopes that exhausted retries in the last 24 hours.",
        snap.queue.expired_recent,
    );
    queue_gauge(
        &mut out,
        "aegis_federation_queue_superseded_recent",
        "Envelopes superseded by a sibling target's success in the last 24 hours.",
        snap.queue.superseded_recent,
    );
    queue_gauge_signed(
        &mut out,
        "aegis_federation_queue_oldest_pending_age_seconds",
        "Age in seconds of the oldest still-pending row. -1 when the queue is empty.",
        snap.queue.oldest_pending_age_seconds.unwrap_or(-1),
    );

    // Per-target metrics. Same five "recent" counts plus the percentile
    // gauges. We write one HELP/TYPE block per metric name, then iterate
    // targets — that's the format-conformant ordering.
    target_block(
        &mut out,
        "aegis_federation_target_pending",
        "gauge",
        "Pending envelopes for a given target relay.",
        &snap.targets,
        |t| t.pending as i64,
    );
    target_block(
        &mut out,
        "aegis_federation_target_delivered_recent",
        "counter",
        "Envelopes delivered to a target relay in the last 24 hours.",
        &snap.targets,
        |t| t.delivered_recent as i64,
    );
    target_block(
        &mut out,
        "aegis_federation_target_expired_recent",
        "counter",
        "Envelopes that expired against a target relay in the last 24 hours.",
        &snap.targets,
        |t| t.expired_recent as i64,
    );
    target_block(
        &mut out,
        "aegis_federation_target_superseded_recent",
        "counter",
        "Envelopes superseded by a sibling target in the last 24 hours.",
        &snap.targets,
        |t| t.superseded_recent as i64,
    );
    target_block(
        &mut out,
        "aegis_federation_target_p50_attempts",
        "gauge",
        "Median attempts to deliver to a target in the last 24 hours.",
        &snap.targets,
        |t| t.p50_attempts as i64,
    );
    target_block(
        &mut out,
        "aegis_federation_target_p95_attempts",
        "gauge",
        "95th percentile attempts to deliver to a target in the last 24 hours.",
        &snap.targets,
        |t| t.p95_attempts as i64,
    );

    out
}

fn queue_gauge(out: &mut String, name: &str, help: &str, value: u64) {
    use std::fmt::Write;
    let _ = writeln!(out, "# HELP {} {}", name, help);
    let _ = writeln!(out, "# TYPE {} gauge", name);
    let _ = writeln!(out, "{} {}", name, value);
}

fn queue_gauge_signed(out: &mut String, name: &str, help: &str, value: i64) {
    use std::fmt::Write;
    let _ = writeln!(out, "# HELP {} {}", name, help);
    let _ = writeln!(out, "# TYPE {} gauge", name);
    let _ = writeln!(out, "{} {}", name, value);
}

fn target_block(
    out: &mut String,
    name: &str,
    type_str: &str,
    help: &str,
    targets: &[TargetStats],
    extract: impl Fn(&TargetStats) -> i64,
) {
    use std::fmt::Write;
    let _ = writeln!(out, "# HELP {} {}", name, help);
    let _ = writeln!(out, "# TYPE {} {}", name, type_str);
    for t in targets {
        let _ = writeln!(
            out,
            "{}{{target=\"{}\"}} {}",
            name,
            escape_label(&t.target_url),
            extract(t)
        );
    }
}

/// Per the exposition format: backslash, double-quote, and newline must
/// be escaped in label values. Other ASCII characters pass through.
fn escape_label(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::QueueStats;

    #[test]
    fn parse_enabled_recognizes_truthy_values() {
        for v in ["1", "true", "TRUE", "yes", "on", " on ", "True"] {
            assert!(parse_enabled(Some(v)), "should be enabled: {:?}", v);
        }
    }

    #[test]
    fn parse_enabled_rejects_falsy_or_missing() {
        for v in ["0", "false", "no", "off", "", "anything"] {
            assert!(!parse_enabled(Some(v)), "should NOT be enabled: {:?}", v);
        }
        assert!(!parse_enabled(None));
    }

    #[test]
    fn render_emits_help_and_type_for_every_queue_metric() {
        let snap = FederationMetricsSnapshot {
            queue: QueueStats {
                pending: 3,
                delivered_recent: 100,
                expired_recent: 1,
                superseded_recent: 5,
                oldest_pending_age_seconds: Some(120),
            },
            targets: vec![],
        };
        let body = render(&snap);

        // Every queue-level metric has its HELP, TYPE, and value line.
        for metric in [
            "aegis_federation_queue_pending",
            "aegis_federation_queue_delivered_recent",
            "aegis_federation_queue_expired_recent",
            "aegis_federation_queue_superseded_recent",
            "aegis_federation_queue_oldest_pending_age_seconds",
        ] {
            assert!(
                body.contains(&format!("# HELP {} ", metric)),
                "missing HELP for {}",
                metric
            );
            assert!(
                body.contains(&format!("# TYPE {} gauge", metric)),
                "missing TYPE for {}",
                metric
            );
        }

        // Spot-check that values made it through.
        assert!(body.contains("aegis_federation_queue_pending 3\n"));
        assert!(body.contains("aegis_federation_queue_delivered_recent 100\n"));
        assert!(body.contains("aegis_federation_queue_oldest_pending_age_seconds 120\n"));
    }

    #[test]
    fn render_uses_neg_one_for_empty_oldest_pending_age() {
        // Prom format doesn't have a "null"; -1 is the conventional
        // sentinel for "no data" on age gauges and is what dashboards
        // typically filter on (`age >= 0`).
        let snap = FederationMetricsSnapshot {
            queue: QueueStats::default(),
            targets: vec![],
        };
        let body = render(&snap);
        assert!(
            body.contains("aegis_federation_queue_oldest_pending_age_seconds -1\n"),
            "expected -1 sentinel; body=\n{}",
            body
        );
    }

    #[test]
    fn render_emits_one_row_per_target_per_metric() {
        let snap = FederationMetricsSnapshot {
            queue: QueueStats::default(),
            targets: vec![
                TargetStats {
                    target_url: "https://peer-a.example".into(),
                    pending: 0,
                    delivered_recent: 100,
                    expired_recent: 0,
                    superseded_recent: 2,
                    p50_attempts: 1,
                    p95_attempts: 1,
                    last_success_at: None,
                    last_failure_at: None,
                },
                TargetStats {
                    target_url: "https://peer-b.example".into(),
                    pending: 1,
                    delivered_recent: 50,
                    expired_recent: 3,
                    superseded_recent: 0,
                    p50_attempts: 1,
                    p95_attempts: 4,
                    last_success_at: None,
                    last_failure_at: None,
                },
            ],
        };
        let body = render(&snap);

        // Two targets × the per-target metric should produce two rows.
        assert!(
            body.contains("aegis_federation_target_delivered_recent{target=\"https://peer-a.example\"} 100"),
            "missing peer-a row"
        );
        assert!(
            body.contains("aegis_federation_target_delivered_recent{target=\"https://peer-b.example\"} 50"),
            "missing peer-b row"
        );
        // Counter type for the cumulative metrics.
        assert!(
            body.contains("# TYPE aegis_federation_target_delivered_recent counter"),
            "delivered_recent should be typed `counter`"
        );
        // Gauge type for the percentile metrics.
        assert!(
            body.contains("# TYPE aegis_federation_target_p95_attempts gauge"),
            "p95_attempts should be typed `gauge`"
        );
    }

    #[test]
    fn escape_label_handles_special_characters() {
        // Exposition-format hostile characters in label values.
        assert_eq!(escape_label(r#"a\b"c"#), r#"a\\b\"c"#);
        assert_eq!(escape_label("line\nbreak"), "line\\nbreak");
        // Most chars pass through unchanged.
        assert_eq!(escape_label("https://relay.example/path"), "https://relay.example/path");
    }
}
