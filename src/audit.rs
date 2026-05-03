use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::Serialize;

#[derive(Debug, Clone)]
pub struct AuditSink {
    pub log_path: Option<PathBuf>,
}

#[derive(Debug, Serialize)]
pub struct AuditEvent<'a> {
    pub at: DateTime<Utc>,
    pub operation: &'a str,
    pub outcome: &'a str,
    pub recipient_id: Option<&'a str>,
    pub envelope_id: Option<&'a str>,
    pub identity_id: Option<&'a str>,
    pub detail: Option<&'a str>,
}

impl AuditSink {
    pub fn new(log_path: Option<PathBuf>) -> Self {
        Self { log_path }
    }

    pub async fn record<'a>(&self, event: AuditEvent<'a>) {
        tracing::info!(
            operation = event.operation,
            outcome = event.outcome,
            recipient_id = event.recipient_id.unwrap_or_default(),
            envelope_id = event.envelope_id.unwrap_or_default(),
            identity_id = event.identity_id.unwrap_or_default(),
            detail = event.detail.unwrap_or_default(),
            "relay_audit"
        );

        let Some(path) = &self.log_path else {
            return;
        };
        if let Ok(line) = serde_json::to_string(&event) {
            let line = format!("{line}\n");
            let path = path.clone();
            let _ = tokio::task::spawn_blocking(move || {
                use std::io::Write;
                if let Ok(mut file) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                {
                    let _ = file.write_all(line.as_bytes());
                }
            })
            .await;
        }
    }
}
