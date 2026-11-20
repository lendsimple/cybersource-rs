//! Blocking transport backed by `ureq`. Not available on wasm32.

use bytes::Bytes;

use super::{BaseUrl, BlockingHttpTransport};
use crate::Result;
use crate::error::BoxError;

/// Largest response body read, in bytes. Report downloads can be large.
const MAX_BODY_BYTES: u64 = 100 * 1024 * 1024;

/// A [`BlockingHttpTransport`] using a `ureq::Agent`.
#[derive(Debug, Clone)]
pub struct UreqTransport {
    agent: ureq::Agent,
    base_url: Option<BaseUrl>,
}

impl Default for UreqTransport {
    fn default() -> Self {
        UreqTransport::with_agent(
            ureq::Agent::config_builder()
                .http_status_as_error(false)
                .build()
                .into(),
        )
    }
}

impl UreqTransport {
    /// A transport with a default agent.
    pub fn new() -> Self {
        Self::default()
    }

    /// Uses a preconfigured agent (timeouts, proxies, TLS).
    ///
    /// The agent must have `http_status_as_error(false)` so that error
    /// responses reach the client and become typed API errors.
    pub fn with_agent(agent: ureq::Agent) -> Self {
        UreqTransport {
            agent,
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

impl BlockingHttpTransport for UreqTransport {
    fn send(&self, mut request: http::Request<Bytes>) -> Result<http::Response<Bytes>, BoxError> {
        if let Some(base_url) = &self.base_url {
            base_url.apply(&mut request)?;
        }
        let (parts, body) = request.into_parts();
        let request = http::Request::from_parts(parts, body.as_ref());
        let response = self.agent.run(request)?;

        let (parts, mut body) = response.into_parts();
        let bytes = body.with_config().limit(MAX_BODY_BYTES).read_to_vec()?;
        Ok(http::Response::from_parts(parts, Bytes::from(bytes)))
    }
}
