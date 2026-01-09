use crate::{
    args::Opt,
    client::utils::{get_rustls_config, ClientServerConnection},
    utils::{EitherIO, WebSocketStreamWrapper},
};
use anyhow::{anyhow, Result};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::{
    rustls::{ClientConfig, RootCertStore, ServerName},
    TlsConnector,
};
use url::Url;
use tokio_tungstenite::client_async;
use http::Request;

pub async fn tls_client_config(options: &Opt) -> ClientConfig {
    let mut config = get_rustls_config(RootCertStore::empty());
    if !options.alpn.is_empty() {
        config.alpn_protocols = options.alpn.iter().map(|s| s.as_bytes().to_vec()).collect();
    }
    config
}

pub struct TrojanTcpTlsConnector {
    tls_config: Arc<ClientConfig>,
    is_lite: bool,
}

impl TrojanTcpTlsConnector {
    pub fn new(tls_config: Arc<ClientConfig>, is_lite: bool) -> Self {
        Self {
            tls_config,
            is_lite,
        }
    }

    pub async fn connect(self, opt: Arc<Opt>) -> Result<ClientServerConnection> {
        let Self {
            tls_config,
            is_lite,
        } = self;
        let opt = &*opt;
        let connector = TlsConnector::from(tls_config);
        let stream = TcpStream::connect(&opt.remote_socket_addr.unwrap()).await?;
        stream.set_nodelay(true)?;
        let stream = connector
            .connect(
                ServerName::try_from(opt.server_hostname.as_str()).expect("invalid DNS name"),
                stream,
            )
            .await?;

        if let Some(ws_config) = &opt.websocket {
            let host = if ws_config.hostname.is_empty() {
                &opt.server_hostname
            } else {
                &ws_config.hostname
            };
            let url = format!("wss://{}{}", host, ws_config.path);
            let url = Url::parse(&url).map_err(|e| anyhow!("invalid websocket url: {}", e))?;

            let request = Request::builder()
                .uri(url.as_str())
                .header("Host", host)
                .header("Connection", "Upgrade")
                .header("Upgrade", "websocket")
                .header("Sec-WebSocket-Version", "13")
                .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
                .body(())?;

            let (ws_stream, _) = client_async(request, stream)
                .await
                .map_err(|e| anyhow!("websocket handshake failed: {}", e))?;

            let wrapped_stream = WebSocketStreamWrapper::new(ws_stream);
            use ClientServerConnection::*;
            return Ok(match is_lite {
                #[cfg(feature = "lite_tls")]
                true => LiteTLS(EitherIO::Right(wrapped_stream)),
                #[cfg(feature = "tcp_tls")]
                false => TcpTLS(EitherIO::Right(wrapped_stream)),
                #[allow(unreachable_patterns)]
                _ => unreachable!(),
            });
        }

        use ClientServerConnection::*;
        return Ok(match is_lite {
            #[cfg(feature = "lite_tls")]
            true => LiteTLS(EitherIO::Left(stream)),
            #[cfg(feature = "tcp_tls")]
            false => TcpTLS(EitherIO::Left(stream)),
            #[allow(unreachable_patterns)]
            _ => unreachable!(),
        });
    }
}
