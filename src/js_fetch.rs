//! The global JavaScript `fetch`, for the `fetch` transport.

use js_sys::Uint8Array;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;

/// A response read in full.
pub(crate) struct JsResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// JS errors are not `Send`; keep their text.
fn js_error(context: &str, e: JsValue) -> String {
    let detail = e
        .as_string()
        .or_else(|| {
            e.dyn_ref::<js_sys::Error>()
                .map(|e| String::from(e.message()))
        })
        .unwrap_or_else(|| format!("{e:?}"));
    format!("{context}: {detail}")
}

/// Sends a request with the global `fetch` (not `window.fetch`), so it works
/// in Cloudflare Workers, Deno and Node.
pub(crate) async fn fetch(
    method: &str,
    url: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Result<JsResponse, String> {
    let js_headers = web_sys::Headers::new().map_err(|e| js_error("creating headers", e))?;
    for (name, value) in headers {
        js_headers
            .append(name, value)
            .map_err(|e| js_error("setting a header", e))?;
    }
    let init = web_sys::RequestInit::new();
    init.set_method(method);
    init.set_headers(&js_headers);
    if !body.is_empty() {
        init.set_body(&Uint8Array::from(body).into());
    }
    let request = web_sys::Request::new_with_str_and_init(url, &init)
        .map_err(|e| js_error("building the request", e))?;

    let scope: web_sys::WorkerGlobalScope = js_sys::global().unchecked_into();
    let response: web_sys::Response = JsFuture::from(scope.fetch_with_request(&request))
        .await
        .map_err(|e| js_error("fetch", e))?
        .dyn_into()
        .map_err(|e| js_error("fetch returned a non-Response", e))?;

    let mut out_headers = Vec::new();
    let entries = js_sys::try_iter(&response.headers())
        .map_err(|e| js_error("reading headers", e))?
        .ok_or("response headers are not iterable")?;
    for entry in entries {
        let pair: js_sys::Array = entry.map_err(|e| js_error("reading a header", e))?.into();
        if let (Some(name), Some(value)) = (pair.get(0).as_string(), pair.get(1).as_string()) {
            out_headers.push((name, value));
        }
    }
    let buffer = JsFuture::from(
        response
            .array_buffer()
            .map_err(|e| js_error("reading the body", e))?,
    )
    .await
    .map_err(|e| js_error("reading the body", e))?;
    Ok(JsResponse {
        status: response.status(),
        headers: out_headers,
        body: Uint8Array::new(&buffer).to_vec(),
    })
}
