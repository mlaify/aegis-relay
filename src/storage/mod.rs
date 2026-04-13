use std::{io, path::PathBuf};

use aegis_proto::Envelope;

pub struct FileEnvelopeStore {
    root: PathBuf,
}

impl FileEnvelopeStore {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub async fn put(&self, envelope: &Envelope) -> io::Result<()> {
        let dir = self.root.join(safe_name(&envelope.recipient_id.0));
        tokio::fs::create_dir_all(&dir).await?;
        let path = dir.join(format!("{}.json", envelope.envelope_id.0));
        let bytes = serde_json::to_vec_pretty(envelope)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        tokio::fs::write(path, bytes).await
    }

    pub async fn get_for_recipient(&self, recipient_id: &str) -> io::Result<Vec<Envelope>> {
        let dir = self.root.join(safe_name(recipient_id));
        let mut out = Vec::new();

        if !dir.exists() {
            return Ok(out);
        }

        let mut entries = tokio::fs::read_dir(dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let bytes = tokio::fs::read(entry.path()).await?;
            let envelope = serde_json::from_slice::<Envelope>(&bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
            out.push(envelope);
        }

        Ok(out)
    }
}

fn safe_name(value: &str) -> String {
    value.replace('/', "_").replace(':', "_")
}
