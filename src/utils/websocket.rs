use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use bytes::BytesMut;
use futures::{Sink, Stream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::tungstenite::Message;
use pin_project_lite::pin_project;
use tokio::net::TcpStream;
use crate::utils::lite_tls::LeaveTls;

pin_project! {
    pub struct WebSocketStreamWrapper<S> {
        #[pin]
        inner: S,
        read_buffer: BytesMut,
    }
}

impl<S> WebSocketStreamWrapper<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            read_buffer: BytesMut::new(),
        }
    }
}

impl<S> LeaveTls for WebSocketStreamWrapper<S> {
    fn leave(self) -> TcpStream {
        unimplemented!("WebSocket cannot leave TLS/WS layer directly into TcpStream")
    }
}

impl<S> AsyncRead for WebSocketStreamWrapper<S>
where
    S: Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut this = self.project();

        loop {
            if !this.read_buffer.is_empty() {
                let len = std::cmp::min(this.read_buffer.len(), buf.remaining());
                let data = this.read_buffer.split_to(len);
                buf.put_slice(&data);
                return Poll::Ready(Ok(()));
            }

            match Pin::new(&mut this.inner).poll_next(cx) {
                Poll::Ready(Some(Ok(msg))) => match msg {
                    Message::Binary(bin) => {
                        this.read_buffer.extend_from_slice(&bin);
                    }
                    Message::Text(txt) => {
                        this.read_buffer.extend_from_slice(txt.as_bytes());
                    }
                    Message::Close(_) => return Poll::Ready(Ok(())),
                    _ => continue,
                },
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e)))
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S> AsyncWrite for WebSocketStreamWrapper<S>
where
    S: Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut this = self.project();
        match this.inner.as_mut().poll_ready(cx) {
            Poll::Ready(Ok(())) => {
                let msg = Message::Binary(buf.to_vec());
                match this.inner.as_mut().start_send(msg) {
                    Ok(()) => Poll::Ready(Ok(buf.len())),
                    Err(e) => Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e))),
                }
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.project();
        this.inner.poll_flush(cx).map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.project();
        this.inner.poll_close(cx).map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }
}
