use std::path::{Path, PathBuf};

use aegis_proto::{Envelope, IdentityDocument};
use async_trait::async_trait;
use chrono::Utc;
use rusqlite::OptionalExtension;
use tokio_rusqlite::Connection;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleOutcome {
    Deleted,
    Acknowledged,
    NotFound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CleanupReport {
    pub expired_removed: usize,
    pub orphan_ack_removed: usize,
}

// ---------------------------------------------------------------------------
// Store trait
// ---------------------------------------------------------------------------

#[async_trait]
pub trait Store: Send + Sync {
    async fn store(
        &self,
        envelope: &Envelope,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
    async fn fetch(
        &self,
        recipient_id: &str,
    ) -> Result<Vec<Envelope>, Box<dyn std::error::Error + Send + Sync>>;
    async fn acknowledge(
        &self,
        recipient_id: &str,
        envelope_id: &str,
    ) -> Result<LifecycleOutcome, Box<dyn std::error::Error + Send + Sync>>;
    async fn delete(
        &self,
        recipient_id: &str,
        envelope_id: &str,
    ) -> Result<LifecycleOutcome, Box<dyn std::error::Error + Send + Sync>>;
    async fn cleanup(&self) -> Result<CleanupReport, Box<dyn std::error::Error + Send + Sync>>;
    async fn store_identity(
        &self,
        doc: &IdentityDocument,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
    async fn fetch_identity(
        &self,
        identity_id: &str,
    ) -> Result<Option<IdentityDocument>, Box<dyn std::error::Error + Send + Sync>>;
}

// ---------------------------------------------------------------------------
// FileStore
// ---------------------------------------------------------------------------

#[allow(dead_code)]
pub struct FileStore {
    base: PathBuf,
}

impl FileStore {
    #[allow(dead_code)]
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        Self {
            base: path.as_ref().to_path_buf(),
        }
    }

    fn envelope_path(&self, recipient_id: &str, envelope_id: &str) -> PathBuf {
        self.base
            .join(safe_name(recipient_id))
            .join(format!("{envelope_id}.json"))
    }

    fn ack_path(&self, recipient_id: &str, envelope_id: &str) -> PathBuf {
        self.base
            .join(safe_name(recipient_id))
            .join(format!("{envelope_id}.ack"))
    }
}

#[async_trait]
impl Store for FileStore {
    async fn store(
        &self,
        envelope: &Envelope,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let dir = self.base.join(safe_name(&envelope.recipient_id.0));
        tokio::fs::create_dir_all(&dir).await?;
        let file = dir.join(format!("{}.json", envelope.envelope_id.0));
        let data = serde_json::to_vec_pretty(envelope)?;
        tokio::fs::write(file, data).await?;
        Ok(())
    }

    async fn fetch(
        &self,
        recipient_id: &str,
    ) -> Result<Vec<Envelope>, Box<dyn std::error::Error + Send + Sync>> {
        let dir = self.base.join(safe_name(recipient_id));
        let mut out = Vec::new();

        if !tokio::fs::try_exists(&dir).await? {
            return Ok(out);
        }

        let mut entries = tokio::fs::read_dir(dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.extension().and_then(|v| v.to_str()) == Some("json") {
                let envelope_id = path
                    .file_stem()
                    .and_then(|v| v.to_str())
                    .unwrap_or_default()
                    .to_string();
                if !envelope_id.is_empty() {
                    let ack_path = self.ack_path(recipient_id, &envelope_id);
                    if tokio::fs::try_exists(&ack_path).await? {
                        continue;
                    }
                }
                let raw = tokio::fs::read_to_string(path).await?;
                let envelope: Envelope = serde_json::from_str(&raw)?;
                if is_expired(&envelope) {
                    // Opportunistic cleanup in file-backed mode.
                    let _ = tokio::fs::remove_file(entry.path()).await;
                    continue;
                }
                out.push(envelope);
            }
        }

        Ok(out)
    }

    async fn acknowledge(
        &self,
        recipient_id: &str,
        envelope_id: &str,
    ) -> Result<LifecycleOutcome, Box<dyn std::error::Error + Send + Sync>> {
        let envelope_path = self.envelope_path(recipient_id, envelope_id);
        if !tokio::fs::try_exists(&envelope_path).await? {
            return Ok(LifecycleOutcome::NotFound);
        }

        let ack_path = self.ack_path(recipient_id, envelope_id);
        if let Some(parent) = ack_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::write(ack_path, b"acknowledged\n").await?;
        Ok(LifecycleOutcome::Acknowledged)
    }

    async fn delete(
        &self,
        recipient_id: &str,
        envelope_id: &str,
    ) -> Result<LifecycleOutcome, Box<dyn std::error::Error + Send + Sync>> {
        let envelope_path = self.envelope_path(recipient_id, envelope_id);
        if !tokio::fs::try_exists(&envelope_path).await? {
            return Ok(LifecycleOutcome::NotFound);
        }
        tokio::fs::remove_file(&envelope_path).await?;

        let ack_path = self.ack_path(recipient_id, envelope_id);
        if tokio::fs::try_exists(&ack_path).await? {
            let _ = tokio::fs::remove_file(ack_path).await;
        }
        Ok(LifecycleOutcome::Deleted)
    }

    async fn cleanup(&self) -> Result<CleanupReport, Box<dyn std::error::Error + Send + Sync>> {
        let mut report = CleanupReport {
            expired_removed: 0,
            orphan_ack_removed: 0,
        };
        if !tokio::fs::try_exists(&self.base).await? {
            return Ok(report);
        }

        let mut recipient_dirs = tokio::fs::read_dir(&self.base).await?;
        while let Some(recipient_entry) = recipient_dirs.next_entry().await? {
            let recipient_path = recipient_entry.path();
            if !recipient_path.is_dir() {
                continue;
            }
            let mut files = tokio::fs::read_dir(&recipient_path).await?;
            while let Some(file_entry) = files.next_entry().await? {
                let path = file_entry.path();
                match path.extension().and_then(|v| v.to_str()) {
                    Some("json") => {
                        let raw = tokio::fs::read_to_string(&path).await?;
                        let envelope: Envelope = serde_json::from_str(&raw)?;
                        if is_expired(&envelope) {
                            let _ = tokio::fs::remove_file(&path).await;
                            report.expired_removed += 1;
                        }
                    }
                    Some("ack") => {
                        let stem = path
                            .file_stem()
                            .and_then(|v| v.to_str())
                            .unwrap_or_default();
                        if stem.is_empty() {
                            continue;
                        }
                        let envelope_path = recipient_path.join(format!("{stem}.json"));
                        if !tokio::fs::try_exists(envelope_path).await? {
                            let _ = tokio::fs::remove_file(&path).await;
                            report.orphan_ack_removed += 1;
                        }
                    }
                    _ => {}
                }
            }
        }

        Ok(report)
    }

    async fn store_identity(
        &self,
        doc: &IdentityDocument,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let dir = self.base.join("identities");
        tokio::fs::create_dir_all(&dir).await?;
        let safe = safe_name(&doc.identity_id.0);
        let path = dir.join(format!("{safe}.json"));
        tokio::fs::write(path, serde_json::to_vec_pretty(doc)?).await?;
        Ok(())
    }

    async fn fetch_identity(
        &self,
        identity_id: &str,
    ) -> Result<Option<IdentityDocument>, Box<dyn std::error::Error + Send + Sync>> {
        let dir = self.base.join("identities");
        let path = dir.join(format!("{}.json", safe_name(identity_id)));
        if !tokio::fs::try_exists(&path).await? {
            return Ok(None);
        }
        let raw = tokio::fs::read_to_string(path).await?;
        Ok(Some(serde_json::from_str(&raw)?))
    }
}

// ---------------------------------------------------------------------------
// SqliteStore
// ---------------------------------------------------------------------------

const MIGRATIONS: &str = "
    PRAGMA journal_mode=WAL;
    CREATE TABLE IF NOT EXISTS envelopes (
        envelope_id TEXT PRIMARY KEY,
        recipient_id TEXT NOT NULL,
        envelope_json TEXT NOT NULL,
        expires_at TEXT,
        acknowledged INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS idx_envelopes_recipient
        ON envelopes(recipient_id);
    CREATE TABLE IF NOT EXISTS identities (
        identity_id TEXT PRIMARY KEY,
        identity_json TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
";

pub struct SqliteStore {
    conn: Connection,
}

impl SqliteStore {
    pub async fn open(path: &str) -> Result<Self, tokio_rusqlite::Error> {
        let conn = Connection::open(path).await?;
        conn.call(|c| c.execute_batch(MIGRATIONS).map_err(|e| e.into()))
            .await?;
        Ok(Self { conn })
    }

    #[allow(dead_code)]
    pub async fn open_in_memory() -> Result<Self, tokio_rusqlite::Error> {
        let conn = Connection::open_in_memory().await?;
        conn.call(|c| c.execute_batch(MIGRATIONS).map_err(|e| e.into()))
            .await?;
        Ok(Self { conn })
    }
}

#[async_trait]
impl Store for SqliteStore {
    async fn store(
        &self,
        envelope: &Envelope,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let json = serde_json::to_string(envelope)?;
        let envelope_id = envelope.envelope_id.0.to_string();
        let recipient_id = envelope.recipient_id.0.clone();
        let expires_at = envelope.expires_at.map(|t| t.to_rfc3339());
        self.conn
            .call(move |c| {
                c.execute(
                    "INSERT OR REPLACE INTO envelopes \
                     (envelope_id, recipient_id, envelope_json, expires_at, acknowledged) \
                     VALUES (?1, ?2, ?3, ?4, 0)",
                    rusqlite::params![envelope_id, recipient_id, json, expires_at],
                )
                .map_err(|e| e.into())
            })
            .await?;
        Ok(())
    }

    async fn fetch(
        &self,
        recipient_id: &str,
    ) -> Result<Vec<Envelope>, Box<dyn std::error::Error + Send + Sync>> {
        let recipient_id = recipient_id.to_string();
        let rows: Vec<String> = self
            .conn
            .call(move |c| {
                let mut stmt = c.prepare(
                    "SELECT envelope_json FROM envelopes \
                     WHERE recipient_id = ?1 AND acknowledged = 0 \
                     AND (expires_at IS NULL OR expires_at > datetime('now'))",
                )?;
                let result = stmt
                    .query_map(rusqlite::params![recipient_id], |row| {
                        row.get::<_, String>(0)
                    })?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e: rusqlite::Error| e.into());
                result
            })
            .await?;
        rows.into_iter()
            .map(|json| {
                serde_json::from_str(&json)
                    .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
            })
            .collect()
    }

    async fn acknowledge(
        &self,
        recipient_id: &str,
        envelope_id: &str,
    ) -> Result<LifecycleOutcome, Box<dyn std::error::Error + Send + Sync>> {
        let recipient_id = recipient_id.to_string();
        let envelope_id = envelope_id.to_string();
        let rows_changed = self
            .conn
            .call(move |c| {
                c.execute(
                    "UPDATE envelopes SET acknowledged = 1 \
                     WHERE envelope_id = ?1 AND recipient_id = ?2",
                    rusqlite::params![envelope_id, recipient_id],
                )
                .map_err(|e| e.into())
            })
            .await?;
        Ok(if rows_changed == 0 {
            LifecycleOutcome::NotFound
        } else {
            LifecycleOutcome::Acknowledged
        })
    }

    async fn delete(
        &self,
        recipient_id: &str,
        envelope_id: &str,
    ) -> Result<LifecycleOutcome, Box<dyn std::error::Error + Send + Sync>> {
        let recipient_id = recipient_id.to_string();
        let envelope_id = envelope_id.to_string();
        let rows_changed = self
            .conn
            .call(move |c| {
                c.execute(
                    "DELETE FROM envelopes WHERE envelope_id = ?1 AND recipient_id = ?2",
                    rusqlite::params![envelope_id, recipient_id],
                )
                .map_err(|e| e.into())
            })
            .await?;
        Ok(if rows_changed == 0 {
            LifecycleOutcome::NotFound
        } else {
            LifecycleOutcome::Deleted
        })
    }

    async fn cleanup(&self) -> Result<CleanupReport, Box<dyn std::error::Error + Send + Sync>> {
        let (expired_removed, orphan_ack_removed) = self
            .conn
            .call(|c| {
                let expired = c.execute(
                    "DELETE FROM envelopes \
                     WHERE expires_at IS NOT NULL AND expires_at <= datetime('now')",
                    [],
                )?;
                let acked = c.execute("DELETE FROM envelopes WHERE acknowledged = 1", [])?;
                Ok((expired, acked))
            })
            .await?;
        Ok(CleanupReport {
            expired_removed,
            orphan_ack_removed,
        })
    }

    async fn store_identity(
        &self,
        doc: &IdentityDocument,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let identity_id = doc.identity_id.0.clone();
        let json = serde_json::to_string(doc)?;
        let updated_at = Utc::now().to_rfc3339();
        self.conn
            .call(move |c| {
                c.execute(
                    "INSERT OR REPLACE INTO identities \
                     (identity_id, identity_json, updated_at) VALUES (?1, ?2, ?3)",
                    rusqlite::params![identity_id, json, updated_at],
                )
                .map_err(|e| e.into())
            })
            .await?;
        Ok(())
    }

    async fn fetch_identity(
        &self,
        identity_id: &str,
    ) -> Result<Option<IdentityDocument>, Box<dyn std::error::Error + Send + Sync>> {
        let identity_id = identity_id.to_string();
        let result: Option<String> = self
            .conn
            .call(move |c| {
                c.query_row(
                    "SELECT identity_json FROM identities WHERE identity_id = ?1",
                    rusqlite::params![identity_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(|e| e.into())
            })
            .await?;
        match result {
            Some(json) => Ok(Some(serde_json::from_str(&json)?)),
            None => Ok(None),
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[allow(dead_code)]
fn safe_name(input: &str) -> String {
    input.replace([':', '/'], "_")
}

#[allow(dead_code)]
fn is_expired(envelope: &Envelope) -> bool {
    envelope
        .expires_at
        .as_ref()
        .map(|expires_at| expires_at <= &Utc::now())
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::{FileStore, LifecycleOutcome, Store};
    use aegis_proto::{EncryptedBlob, Envelope, IdentityId, SuiteId};
    use chrono::{Duration, Utc};

    fn sample_envelope(recipient: &str) -> Envelope {
        Envelope::new(
            IdentityId(recipient.to_string()),
            None,
            SuiteId::DemoXChaCha20Poly1305,
            EncryptedBlob {
                nonce_b64: "bm9uY2U=".to_string(),
                ciphertext_b64: "Y2lwaGVydGV4dA==".to_string(),
                eph_x25519_public_key_b64: None,
                mlkem_ciphertext_b64: None,
            },
        )
    }

    #[tokio::test]
    async fn fetch_skips_and_cleans_up_expired_envelopes() {
        let base = std::env::temp_dir().join(format!("aegis-relay-store-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&base).await;
        let store = FileStore::new(&base);

        let mut expired = sample_envelope("amp:did:key:z6MkRecipient");
        expired.expires_at = Some(Utc::now() - Duration::seconds(10));
        let fresh = sample_envelope("amp:did:key:z6MkRecipient");

        store.store(&expired).await.expect("store expired");
        store.store(&fresh).await.expect("store fresh");

        let fetched = store
            .fetch("amp:did:key:z6MkRecipient")
            .await
            .expect("fetch");
        assert_eq!(fetched.len(), 1);
        assert_eq!(fetched[0].envelope_id.0, fresh.envelope_id.0);

        let recipient_dir = base.join("amp_did_key_z6MkRecipient");
        let expired_path = recipient_dir.join(format!("{}.json", expired.envelope_id.0));
        assert!(!tokio::fs::try_exists(expired_path)
            .await
            .expect("exists check"));

        let _ = tokio::fs::remove_dir_all(&base).await;
    }

    #[tokio::test]
    async fn acknowledge_marks_envelope_and_fetch_skips_it() {
        let base = std::env::temp_dir().join(format!("aegis-relay-ack-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&base).await;
        let store = FileStore::new(&base);

        let envelope = sample_envelope("amp:did:key:z6MkRecipient");
        store.store(&envelope).await.expect("store");
        let outcome = store
            .acknowledge(
                "amp:did:key:z6MkRecipient",
                &envelope.envelope_id.0.to_string(),
            )
            .await
            .expect("ack");
        assert_eq!(outcome, LifecycleOutcome::Acknowledged);

        let fetched = store
            .fetch("amp:did:key:z6MkRecipient")
            .await
            .expect("fetch");
        assert!(fetched.is_empty());
        let _ = tokio::fs::remove_dir_all(&base).await;
    }

    #[tokio::test]
    async fn delete_removes_envelope_file() {
        let base = std::env::temp_dir().join(format!("aegis-relay-del-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&base).await;
        let store = FileStore::new(&base);

        let envelope = sample_envelope("amp:did:key:z6MkRecipient");
        let id = envelope.envelope_id.0.to_string();
        store.store(&envelope).await.expect("store");
        let outcome = store
            .delete("amp:did:key:z6MkRecipient", &id)
            .await
            .expect("delete");
        assert_eq!(outcome, LifecycleOutcome::Deleted);

        let fetched = store
            .fetch("amp:did:key:z6MkRecipient")
            .await
            .expect("fetch");
        assert!(fetched.is_empty());
        let _ = tokio::fs::remove_dir_all(&base).await;
    }

    #[tokio::test]
    async fn cleanup_removes_expired_and_orphan_ack_files() {
        let base = std::env::temp_dir().join(format!("aegis-relay-clean-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&base).await;
        let store = FileStore::new(&base);

        let mut expired = sample_envelope("amp:did:key:z6MkRecipient");
        expired.expires_at = Some(Utc::now() - Duration::seconds(10));
        store.store(&expired).await.expect("store expired");

        let recipient_dir = base.join("amp_did_key_z6MkRecipient");
        let orphan_ack = recipient_dir.join("orphan-envelope.ack");
        tokio::fs::write(&orphan_ack, b"ack")
            .await
            .expect("write orphan ack");

        let report = store.cleanup().await.expect("cleanup");
        assert_eq!(report.expired_removed, 1);
        assert_eq!(report.orphan_ack_removed, 1);

        let _ = tokio::fs::remove_dir_all(&base).await;
    }
}
