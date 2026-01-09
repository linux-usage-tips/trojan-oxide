#[cfg(feature = "client")]
use crate::client::ConnectionMode;
use crate::protocol::HASH_LEN;
use sha2::{Digest, Sha224};
use std::fmt::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use structopt::StructOpt;
use tokio::sync::broadcast;

fn parse_log_level(l: &str) -> tracing::Level {
    match &l.to_lowercase()[..] {
        "info" => tracing::Level::INFO,
        "debug" => tracing::Level::DEBUG,
        "warn" => tracing::Level::WARN,
        "error" => tracing::Level::ERROR,
        "trace" => tracing::Level::TRACE,
        _ => tracing::Level::INFO,
    }
}

#[cfg(feature = "client")]
fn parse_connection_mode(l: &str) -> ConnectionMode {
    use ConnectionMode::*;
    #[allow(unreachable_patterns)]
    match &l.to_lowercase()[..] {
        #[cfg(feature = "tcp_tls")]
        "tcp-tls" => TcpTLS,
        #[cfg(feature = "tcp_tls")]
        "t" => TcpTLS,
        #[cfg(feature = "tcp_tls")]
        "tcp" => TcpTLS,
        #[cfg(feature = "tcp_tls")]
        "tcp_tls" => TcpTLS,
        #[cfg(feature = "quic")]
        "quic" => Quic,
        #[cfg(feature = "quic")]
        "q" => Quic,
        #[cfg(feature = "lite_tls")]
        "l" => LiteTLS,
        #[cfg(feature = "tcp_tls")]
        _ => TcpTLS,
        #[cfg(feature = "lite_tls")]
        #[allow(unreachable_patterns)]
        _ => LiteTLS,
        #[cfg(feature = "quic")]
        #[allow(unreachable_patterns)]
        _ => Quic,
    }
}

#[cfg(feature = "client")]
fn into_local_addr(l: &str) -> SocketAddr {
    ("127.0.0.1:".to_owned() + l).parse::<SocketAddr>().unwrap()
}

fn into_u16(l: &str) -> u16 {
    let mut res = 0;
    for i in l.bytes() {
        if i <= b'9' && i >= b'0' {
            res = res * 10 + (i - b'0') as u16;
        } else {
            panic!("invalid port value")
        }
    }
    res
}

fn password_to_hash(s: &str) -> String {
    let h = password_to_hash_bytes(s);
    let mut s = String::with_capacity(HASH_LEN);
    for i in h {
        write!(&mut s, "{:02x}", i).unwrap();
    }
    s
}

pub fn password_to_hash_bytes(s: &str) -> Vec<u8> {
    let mut hasher = Sha224::new();
    hasher.update(s);
    let h = hasher.finalize();
    h.to_vec()
}

#[derive(StructOpt, Clone)]
#[cfg_attr(feature = "debug_info", derive(Debug))]
#[structopt(name = "basic")]
pub struct Opt {
    /// client http proxy port
    #[cfg(feature = "client")]
    #[structopt(short = "h", long = "http_port", default_value = "8888", parse(from_str = into_local_addr))]
    pub local_http_addr: SocketAddr,

    /// local ip address
    #[structopt(skip)]
    pub local_ip: String,

    /// local port
    #[structopt(skip)]
    pub local_port: u16,

    /// client socks5 proxy port
    #[cfg(feature = "client")]
    #[structopt(short = "5", long = "socks5_port", default_value = "8889", parse(from_str = into_local_addr))]
    pub local_socks5_addr: SocketAddr,

    /// Log level (from least to most verbose): 
    /// 
    /// error < warn < info < debug < trace
    #[structopt(short = "l", long, default_value = "info", parse(from_str = parse_log_level))]
    pub log_level: tracing::Level,

    #[structopt(parse(from_os_str), long = "ca")]
    pub ca: Option<PathBuf>,

    /// Server Name Indication (sni), or Hostname.
    #[structopt(short = "u", long, default_value = "localhost")]
    pub server_hostname: String,

    /// server proxy port
    #[structopt(short = "x", long, default_value = "443", parse(from_str = into_u16))]
    pub server_port: u16,

    /// server ip address
    #[structopt(short = "d", long, default_value = "")]
    pub server_ip: String,

    /// whether to start as server
    #[structopt(short, long)]
    pub server: bool,

    /// TLS private key in PEM format
    #[cfg(feature = "server")]
    #[structopt(parse(from_os_str), short = "k", long = "key", requires = "cert")]
    pub key: Option<PathBuf>,

    /// TLS certificate in PEM format
    #[cfg(feature = "server")]
    #[structopt(parse(from_os_str), long = "cert", requires = "key")]
    pub cert: Option<PathBuf>,

    /// the password to authenticate connections
    #[structopt(short = "w", long, parse(from_str = password_to_hash))]
    pub password: Option<String>,

    /// port to re-direct unauthenticated connections
    #[cfg(feature = "server")]
    #[structopt(short = "f", long, default_value = "0", parse(from_str = into_u16))]
    pub fallback_port: u16,

    /// Connetion Mode:
    /// 
    /// - t (for tcp-tls)
    /// 
    /// - q (for quic)
    /// 
    /// - l (for lite-tls)
    #[structopt(short = "m", long, default_value = "t", parse(from_str = parse_connection_mode))]
    pub connection_mode: ConnectionMode,

    /// configuration file path
    #[structopt(short = "c", long = "config", parse(from_os_str))]
    pub config: Option<PathBuf>,

    /// password list from config file
    #[structopt(skip)]
    pub password_list: Vec<String>,

    /// websocket config from config file
    #[structopt(skip)]
    pub websocket: Option<crate::config::WebsocketConfig>,

    /// use zero copy
    #[structopt(skip)]
    pub zero_copy: bool,

    /// fast open
    #[structopt(skip)]
    pub fast_open: bool,

    /// tcp keepalive
    #[structopt(skip)]
    pub tcp_keepalive: bool,

    /// ALPN protocols
    #[structopt(skip)]
    pub alpn: Vec<String>,

    pub remote_socket_addr: Option<SocketAddr>,
}

impl Opt {
    pub fn merge_config(&mut self, config: crate::config::Config) -> anyhow::Result<()> {
        if let Some(listen) = config.listen {
            if let Ok(addr) = listen.parse::<SocketAddr>() {
                self.server_port = addr.port();
                self.server_ip = addr.ip().to_string();
            } else if let Ok(port) = listen.parse::<u16>() {
                self.server_port = port;
            }
        }

        if !config.password.is_empty() {
            self.password_list = config.password.clone();
            // For backward compatibility, set the first password as the main one
            if self.password.is_none() {
                self.password = Some(password_to_hash(&config.password[0]));
            }
        }

        if let Some(ws) = config.websocket {
            if ws.enabled {
                self.websocket = Some(ws);
            }
        }

    if let Some(tls) = config.tls.or(config.ssl) {
        if let Some(cert) = tls.certificate.or(tls.cert) {
            self.cert = Some(cert);
        }
        if let Some(key) = tls.certificate_key.or(tls.key) {
            self.key = Some(key);
        }
        if let Some(sni) = tls.sni {
            self.server_hostname = sni;
        }
        if let Some(alpn) = tls.alpn {
            self.alpn = alpn;
        }
    }

        if let Some(zc) = config.zero_copy {
            self.zero_copy = zc;
        }

        if let Some(fo) = config.fast_open {
            self.fast_open = fo;
        }

        if let Some(tk) = config.tcp_keepalive {
            self.tcp_keepalive = tk;
        }

        if let Some(log) = config.log_level {
            self.log_level = parse_log_level(&log);
        }

        if let Some(run_type) = config.run_type {
            self.server = run_type == "server";
        }

        if let Some(protocol) = config.protocol {
            self.connection_mode = parse_connection_mode(&protocol);
        }

        if let Some(local_addr) = config.local_addr {
            self.local_ip = local_addr;
        }

        if let Some(local_port) = config.local_port {
            self.local_port = local_port;
            // Update local_http_addr and local_socks5_addr if local_ip is also set
            let ip = if !self.local_ip.is_empty() {
                &self.local_ip
            } else {
                "127.0.0.1"
            };
            if let Ok(addr) = format!("{}:{}", ip, local_port).parse::<SocketAddr>() {
                self.local_http_addr = addr;
            }
            if let Ok(addr) = format!("{}:{}", ip, local_port + 1).parse::<SocketAddr>() {
                self.local_socks5_addr = addr;
            }
        }

        if let Some(remote_addr) = config.remote_addr {
            self.server_ip = remote_addr;
        }

        if let Some(remote_port) = config.remote_port {
            self.server_port = remote_port;
        }

        Ok(())
    }
}

#[cfg_attr(feature = "debug_info", derive(Debug))]
pub struct TrojanContext {
    pub options: Arc<Opt>,
    pub shutdown: broadcast::Receiver<()>,
}

impl TrojanContext {
    pub fn clone_with_signal(&self, shutdown: broadcast::Receiver<()>) -> Self {
        Self {
            options: self.options.clone(),
            shutdown,
        }
    }
}
