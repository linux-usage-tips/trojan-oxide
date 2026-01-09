use tokio::net::TcpStream;
use crate::utils::{EitherIO, WebSocketStreamWrapper};
use tokio_tungstenite::WebSocketStream;

#[cfg(feature = "quic")]
use quinn::*;
#[cfg(any(feature = "tcp_tls", feature = "lite_tls"))]
use tokio_rustls::client::TlsStream;

pub type TlsOrWsStream = EitherIO<TlsStream<TcpStream>, WebSocketStreamWrapper<WebSocketStream<TlsStream<TcpStream>>>>;

pub enum ClientServerConnection {
    #[cfg(feature = "quic")]
    Quic((SendStream, RecvStream)),
    #[cfg(feature = "tcp_tls")]
    TcpTLS(TlsOrWsStream),
    #[cfg(feature = "lite_tls")]
    LiteTLS(TlsOrWsStream),
}
