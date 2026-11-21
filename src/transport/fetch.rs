//! Async transport over the JavaScript `fetch` API, for wasm32 server hosts:
//! Cloudflare Workers, Deno and Node 18+ (feature `fetch`).
//!
//! It calls the global `fetch` (not `window.fetch`), so it works wherever a
//! global `fetch` exists. It carries merchant credentials: never use it in
//! code that ships to browsers.
//!
//! ```ignore
//! // Cloudflare Workers
//! #[event(fetch)]
//! async fn main(req: Request, env: Env, _ctx: Context) -> worker::Result<Response> {
//!     let config = Config::builder()
//!         .environment(Environment::Production)
//!         .merchant_id(env.var("CYBS_MERCHANT_ID")?.to_string())
//!         .credentials(Credentials::jwt_shared_secret(
//!             env.var("CYBS_KEY_ID")?.to_string(),
//!             &env.secret("CYBS_SHARED_SECRET")?.to_string(),
//!         )?)
//!         .build()?;
//!     let client = Client::new(config, FetchTransport::new());
//!     // ...
//! }
//! ```

use bytes::Bytes;

use super::{BaseUrl, HttpTransport};
use crate::Result;
use crate::error::BoxError;
use crate::js_fetch::fetch;

/// An [`HttpTransport`] using the JavaScript `fetch` API.
#[derive(Debug, Clone, Default)]
pub struct FetchTransport {
    base_url: Option<BaseUrl>,
}

impl FetchTransport {
    /// A transport using the global `fetch`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Connects to `base_url` (`scheme://host[:port]`) instead of the
    /// Cybersource host. Requests are still signed for the configured host.
    pub fn with_base_url(mut self, base_url: &str) -> Result<Self> {
        self.base_url = Some(BaseUrl::parse(base_url)?);
        Ok(self)
    }
}

impl HttpTransport for FetchTransport {
    async fn send(
        &self,
        mut request: http::Request<Bytes>,
    ) -> Result<http::Response<Bytes>, BoxError> {
        if let Some(base_url) = &self.base_url {
            base_url.apply(&mut request)?;
        }
        let (parts, body) = request.into_parts();
        let mut headers = Vec::with_capacity(parts.headers.len());
        for (name, value) in &parts.headers {
            headers.push((name.as_str(), value.to_str()?));
        }
        let response = fetch(
            parts.method.as_str(),
            &parts.uri.to_string(),
            &headers,
            &body,
        )
        .await?;

        let mut builder = http::Response::builder().status(response.status);
        for (name, value) in response.headers {
            builder = builder.header(name, value);
        }
        Ok(builder.body(Bytes::from(response.body))?)
    }
}
