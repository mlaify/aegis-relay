use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct RelayConfig {
    pub bind: String,
    pub storage_dir: PathBuf,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:8080".to_string(),
            storage_dir: PathBuf::from("./var/envelopes"),
        }
    }
}
