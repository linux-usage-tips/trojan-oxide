use crate::{args::TrojanContext, server::outbound::handle_outbound, utils::WebSocketStreamWrapper};
use anyhow::{anyhow, Result};
use tokio::{
    sync::broadcast,
    time::{timeout, Duration},
};
use tokio_rustls::Accept;
use tracing::{debug, error, info};
#[cfg(feature = "quic")]
use {
    futures::{StreamExt, TryFutureExt},
    quinn::*,
};

#[cfg(any(feature = "tcp_tls", feature = "lite_tls"))]
use tokio::net::TcpStream;
use tokio_tungstenite::accept_hdr_async;
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};

#[cfg(feature = "quic")]
pub async fn handle_quic_connection(
    mut context: TrojanContext,
    mut streams: IncomingBiStreams,
) -> Result<()> {
    use crate::utils::WRTuple;
    use tokio::select;
    use tracing::{error, info};
    let (shutdown_tx, _) = broadcast::channel(1);

    loop {
        let stream = select! {
            s = streams.next() => {
                match s {
                    Some(stream) => stream,
                    None => {break;}
                }
            },
            _ = context.shutdown.recv() => {
                // info
                break;
            }
        };

        let stream = match stream {
            Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                info!("connection closed");
                return Ok(());
            }
            Err(e) => {
                return Err(anyhow::Error::new(e));
            }
            Ok(s) => s,
        };
        tokio::spawn(
            handle_outbound(
                context.clone_with_signal(shutdown_tx.subscribe()),
                WRTuple::from_wr_tuple(stream),
            )
            .map_err(|e| {
                error!("handle_quic_outbound quit due to {:#}", e);
                e
            }),
        );
    }
    Ok(())
}

#[cfg(any(feature = "tcp_tls", feature = "lite_tls"))]
pub async fn handle_tcp_tls_connection(
    context: TrojanContext,
    incoming: Accept<TcpStream>,
) -> Result<()> {
    let stream = match timeout(Duration::from_secs(5), incoming).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            error!("TLS accept failed: {:#}", e);
            return Err(anyhow::Error::new(e));
        }
        Err(_) => {
            error!("TLS accept timed out");
            return Err(anyhow!("TLS accept timed out"));
        }
    };

    let (_, session) = stream.get_ref();
    let alpn = session.alpn_protocol().map(|p| String::from_utf8_lossy(p).to_string());
    debug!("TLS handshake completed. ALPN: {:?}", alpn);

    if let Some(ws_config) = &context.options.websocket {
        let ws_path = if ws_config.path.starts_with('/') {
            ws_config.path.clone()
        } else {
            format!("/{}", ws_config.path)
        };
        let callback = move |req: &Request, response: Response| {
            let req_path = req.uri().path();
            info!("WebSocket handshake attempt: Path={}, Host={:?}, URI={}", 
                req_path,
                req.headers().get("host"),
                req.uri()
            );
            if req_path == ws_path || req_path.trim_end_matches('/') == ws_path.trim_end_matches('/') {
                debug!("WebSocket handshake path match: {}", req_path);
                Ok(response)
            } else {
                error!("WebSocket handshake path mismatch: expected '{}', got '{}'", ws_path, req_path);
                Err(Response::builder()
                    .status(http::StatusCode::NOT_FOUND)
                    .body(None)
                    .unwrap())
            }
        };

        let ws_stream = accept_hdr_async(stream, callback)
            .await
            .map_err(|e| anyhow!("websocket handshake failed: {}", e))?;

        let wrapped_stream = WebSocketStreamWrapper::new(ws_stream);
        handle_outbound(context, wrapped_stream).await?;
    } else {
        handle_outbound(context, stream).await?;
    }
    Ok(())
}
