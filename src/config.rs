use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use anyhow::{Context, Result};

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct Config {
    pub listen: Option<String>,
    pub local_addr: Option<String>,
    pub local_port: Option<u16>,
    pub remote_addr: Option<String>,
    pub remote_port: Option<u16>,
    pub password: Vec<String>,
    pub protocol: Option<String>,
    pub websocket: Option<WebsocketConfig>,
    pub tls: Option<TlsConfig>,
    pub ssl: Option<TlsConfig>, // Alias for tls in some formats
    pub fast_open: Option<bool>,
    pub tcp_keepalive: Option<bool>,
    pub zero_copy: Option<bool>,
    pub run_type: Option<String>, // "server" or "client"
    pub log_level: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct WebsocketConfig {
    pub enabled: bool,
    pub path: String,
    pub hostname: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct TlsConfig {
    pub enabled: Option<bool>,
    pub certificate: Option<PathBuf>,
    pub certificate_key: Option<PathBuf>,
    pub key: Option<PathBuf>, // Alias for certificate_key
    pub cert: Option<PathBuf>, // Alias for certificate
    pub alpn: Option<Vec<String>>,
    pub sni: Option<String>,
    pub verify: Option<bool>,
}

impl Config {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut file = File::open(path).context("failed to open config file")?;
        let mut contents = String::new();
        file.read_to_string(&mut contents).context("failed to read config file")?;
        let config: Config = serde_json::from_str(&contents).context("failed to parse config JSON")?;
        Ok(config)
    }
}
