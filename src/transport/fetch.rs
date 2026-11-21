//! Async transport over the JavaScript `fetch` API, for wasm32 hosts:
//! Cloudflare Workers, Deno, Node 18+ and browsers (feature `fetch`).
//!
//! It calls the global `fetch` (not `window.fetch`), so it works wherever a
//! global `fetch` exists, including service workers and Workers.
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
use js_sys::Uint8Array;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;

use super::{BaseUrl, HttpTransport};
use crate::Result;
use crate::error::BoxError;

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

/// JS errors are not `Send`; keep their text.
fn js_error(context: &str, e: JsValue) -> BoxError {
    let detail = e
        .as_string()
        .or_else(|| {
            e.dyn_ref::<js_sys::Error>()
                .map(|e| String::from(e.message()))
        })
        .unwrap_or_else(|| format!("{e:?}"));
    format!("{context}: {detail}").into()
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

        let headers = web_sys::Headers::new().map_err(|e| js_error("creating headers", e))?;
        for (name, value) in &parts.headers {
            headers
                .append(name.as_str(), value.to_str()?)
                .map_err(|e| js_error("setting a header", e))?;
        }
        let init = web_sys::RequestInit::new();
        init.set_method(parts.method.as_str());
        init.set_headers(&headers);
        if !body.is_empty() {
            init.set_body(&Uint8Array::from(&body[..]).into());
        }
        let js_request = web_sys::Request::new_with_str_and_init(&parts.uri.to_string(), &init)
            .map_err(|e| js_error("building the request", e))?;

        let scope: web_sys::WorkerGlobalScope = js_sys::global().unchecked_into();
        let response: web_sys::Response = JsFuture::from(scope.fetch_with_request(&js_request))
            .await
            .map_err(|e| js_error("fetch", e))?
            .dyn_into()
            .map_err(|e| js_error("fetch returned a non-Response", e))?;

        let mut builder = http::Response::builder().status(response.status());
        let entries = js_sys::try_iter(&response.headers())
            .map_err(|e| js_error("reading headers", e))?
            .ok_or("response headers are not iterable")?;
        for entry in entries {
            let pair: js_sys::Array = entry.map_err(|e| js_error("reading a header", e))?.into();
            if let (Some(name), Some(value)) = (pair.get(0).as_string(), pair.get(1).as_string()) {
                builder = builder.header(name, value);
            }
        }
        let buffer = JsFuture::from(
            response
                .array_buffer()
                .map_err(|e| js_error("reading the body", e))?,
        )
        .await
        .map_err(|e| js_error("reading the body", e))?;
        Ok(builder.body(Bytes::from(Uint8Array::new(&buffer).to_vec()))?)
    }
}
