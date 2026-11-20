//! Async transport backed by `reqwest` (also works on wasm32 via `fetch`).

use bytes::Bytes;

use super::{BaseUrl, HttpTransport};
use crate::Result;
use crate::error::BoxError;

/// An [`HttpTransport`] using a `reqwest::Client`.
#[derive(Debug, Clone, Default)]
pub struct ReqwestTransport {
    client: reqwest::Client,
    base_url: Option<BaseUrl>,
}

impl ReqwestTransport {
    /// A transport with a default `reqwest::Client`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Uses a preconfigured `reqwest::Client` (timeouts, proxies, TLS).
    pub fn with_client(client: reqwest::Client) -> Self {
        ReqwestTransport {
            client,
            base_url: None,
        }
    }

    /// Connects to `base_url` (`scheme://host[:port]`) instead of the
    /// Cybersource host, e.g. an intermediate host or a mock server.
    /// Requests are still signed for the configured environment's host.
    pub fn with_base_url(mut self, base_url: &str) -> Result<Self> {
        self.base_url = Some(BaseUrl::parse(base_url)?);
        Ok(self)
    }
}

impl HttpTransport for ReqwestTransport {
    async fn send(
        &self,
        mut request: http::Request<Bytes>,
    ) -> Result<http::Response<Bytes>, BoxError> {
        if let Some(base_url) = &self.base_url {
            base_url.apply(&mut request)?;
        }
        let response = self
            .client
            .execute(reqwest::Request::try_from(request)?)
            .await?;

        let mut builder = http::Response::builder().status(response.status());
        if let Some(headers) = builder.headers_mut() {
            headers.extend(response.headers().clone());
        }
        let body = response.bytes().await?;
        Ok(builder.body(body)?)
    }
}
