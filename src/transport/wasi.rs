//! Async transport over WASI 0.2 HTTP, for `wasm32-wasip2` components
//! (feature `wasi`; built on `wstd`, which needs Rust 1.91.1).
//!
//! Run the component in a host that provides `wasi:http`, e.g.
//! `wasmtime run -S http`.

use std::time::Duration;

use bytes::Bytes;

use super::{BaseUrl, HttpTransport};
use crate::Result;
use crate::error::BoxError;

/// An [`HttpTransport`] using `wasi:http` through `wstd`.
#[derive(Debug, Clone, Default)]
pub struct WasiTransport {
    base_url: Option<BaseUrl>,
    connect_timeout: Option<Duration>,
}

impl WasiTransport {
    /// A transport with the host's default timeouts.
    pub fn new() -> Self {
        Self::default()
    }

    /// Fails connections that take longer than `timeout`.
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = Some(timeout);
        self
    }

    /// Connects to `base_url` (`scheme://host[:port]`) instead of the
    /// Cybersource host. Requests are still signed for the configured host.
    pub fn with_base_url(mut self, base_url: &str) -> Result<Self> {
        self.base_url = Some(BaseUrl::parse(base_url)?);
        Ok(self)
    }
}

impl HttpTransport for WasiTransport {
    async fn send(
        &self,
        mut request: http::Request<Bytes>,
    ) -> Result<http::Response<Bytes>, BoxError> {
        if let Some(base_url) = &self.base_url {
            base_url.apply(&mut request)?;
        }
        let mut client = wstd::http::Client::new();
        if let Some(timeout) = self.connect_timeout {
            client.set_connect_timeout(timeout);
        }
        let response = client.send(request).await?;
        let (parts, mut body) = response.into_parts();
        let bytes = body.bytes_contents().await?;
        Ok(http::Response::from_parts(parts, bytes))
    }
}
