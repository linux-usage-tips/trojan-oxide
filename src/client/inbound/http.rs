use crate::{
    client::utils::new_client_tcp_stream,
    utils::ConnectionRequest,
    utils::{MixAddrType, ParserError},
};

use anyhow::{Error, Result as AnyResult};
use futures::{future::BoxFuture, FutureExt};
use std::result::Result as StdResult;
// use futures::future;
// use std::io::IoSlice;
// use std::pin::Pin;
use tokio::io::*;
use tokio::net::TcpStream;
#[cfg(feature = "debug_info")]
use tracing::{debug, error};

use crate::client::utils::ClientConnectionRequest;

use super::{listener::RequestFromClient, ClientRequestAcceptResult};

pub struct HttpRequest {
    is_https: bool,
    addr: MixAddrType,
    cursor: usize,
    inbound: Option<TcpStream>,
}

impl HttpRequest {
    fn parse(&mut self, buf: &[u8]) -> StdResult<(), ParserError> {
        let header_end = buf.windows(4).position(|w| w == b"\r\n\r\n");
        if header_end.is_none() {
            return Err(ParserError::Incomplete("header incomplete".into()));
        }
        let header_end = header_end.unwrap() + 4;
        let header = &buf[..header_end];

        #[cfg(feature = "debug_info")]
        debug!("parsing header: {:?}", String::from_utf8_lossy(header));

        let first_space = header.iter().position(|&b| b == b' ');
        if let Some(pos) = first_space {
            let method = &header[..pos];
            self.is_https = method == b"CONNECT";
            self.cursor = pos + 1;
        } else {
            return Err(ParserError::Invalid("Invalid HTTP method".into()));
        }

        // 1. Try to extract host from request line
        let mut pos = self.cursor;
        while pos < header.len() && header[pos] == b' ' {
            pos += 1;
        }
        
        let mut host_start = pos;
        if !self.is_https && header[pos..].to_ascii_lowercase().starts_with(b"http://") {
            host_start += 7;
        }
        
        let mut host_end = host_start;
        while host_end < header.len() && header[host_end] != b' ' && header[host_end] != b'/' && header[host_end] != b'\r' {
            host_end += 1;
        }

        if host_end > host_start {
            if let Ok(addr) = MixAddrType::from_http_header(self.is_https, &header[host_start..host_end]) {
                self.addr = addr;
                return Ok(());
            }
        }

        // 2. Try to extract host from Host header
        let header_str = String::from_utf8_lossy(header);
        for line in header_str.lines() {
            let lower = line.to_ascii_lowercase();
            if lower.trim().starts_with("host:") {
                let host_val = line.splitn(2, ':').nth(1).unwrap_or("").trim();
                if let Ok(addr) = MixAddrType::from_http_header(self.is_https, host_val.as_bytes()) {
                    self.addr = addr;
                    return Ok(());
                }
            }
        }

        Err(ParserError::Invalid("No host found in request line or Host header".into()))
    }

    async fn impl_accept(&mut self) -> AnyResult<ClientConnectionRequest> {
        let mut buffer = Vec::with_capacity(1024);
        let mut inbound = self.inbound.take().unwrap();
        loop {
            let read = inbound.read_buf(&mut buffer).await?;
            if read == 0 {
                return Err(Error::new(ParserError::Invalid(
                    "HttpRequest::accept unable to accept before EOF".into(),
                )));
            }
            match self.parse(&buffer) {
                Ok(_) => {
                    #[cfg(feature = "debug_info")]
                    debug!("http request parsed successfully, target: {:?}", self.addr);
                    break;
                }
                Err(ParserError::Incomplete(_)) => continue,
                Err(e) => return Err(Error::new(e)),
            }
        }

        let extension = if self.is_https {
            inbound
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await?;
            inbound.flush().await?;
            #[cfg(feature = "debug_info")]
            debug!("https CONNECT tunnel established");
            None
        } else {
            #[cfg(feature = "debug_info")]
            debug!("plain http request forwarding, buffer size: {}", buffer.len());
            Some(buffer)
        };

        Ok(ConnectionRequest::TCP(new_client_tcp_stream(
            inbound, extension,
        )))
    }
}

impl RequestFromClient for HttpRequest {
    fn accept<'a>(mut self) -> BoxFuture<'a, ClientRequestAcceptResult> {
        async move { Ok::<_, Error>((self.impl_accept().await?, self.addr)) }.boxed()
    }

    fn new(inbound: TcpStream) -> Self {
        Self {
            is_https: false,
            addr: MixAddrType::None,
            cursor: 0,
            inbound: Some(inbound),
        }
    }
}
