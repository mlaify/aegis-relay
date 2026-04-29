use std::path::{Path, PathBuf};

use aegis_proto::Envelope;
use chrono::Utc;

pub struct FileStore {
    base: PathBuf,
}

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

impl FileStore {
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        Self {
            base: path.as_ref().to_path_buf(),
        }
    }

    pub async fn store(
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

    pub async fn fetch(
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

    pub async fn acknowledge(
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

    pub async fn delete(
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

    pub async fn cleanup(&self) -> Result<CleanupReport, Box<dyn std::error::Error + Send + Sync>> {
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

fn safe_name(input: &str) -> String {
    input.replace([':', '/'], "_")
}

fn is_expired(envelope: &Envelope) -> bool {
    envelope
        .expires_at
        .as_ref()
        .map(|expires_at| expires_at <= &Utc::now())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::{FileStore, LifecycleOutcome};
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
