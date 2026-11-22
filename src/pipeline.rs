//! The sans-IO request pipeline shared by every client.
//!
//! [`prepare`] turns an [`Operation`] into a signed `http::Request`;
//! [`finish`] turns the `http::Response` into the operation's output or a
//! typed error. Neither performs I/O, so they work with any transport.

use bytes::Bytes;
use http::header::{ACCEPT, CONTENT_TYPE, USER_AGENT};
use http::{HeaderValue, Method, Request, Uri};

use crate::auth::{self, SigningInput};
use crate::clock::Clock;
use crate::config::Config;
use crate::entropy::Entropy;
use crate::error::{ApiError, ErrorBody};
use crate::jose::jwe::{self, Enc, KeyAlg};
use crate::mle::policy;
use crate::operation::{Operation, encode_path_segment};
use crate::response::{self, Response};
use crate::{Error, Result};

const CONTENT_TYPE_JSON: &str = "application/json;charset=utf-8";
const ACCEPT_JSON: &str = "application/hal+json;charset=utf-8, application/json";
const CLIENT_ID: &str = concat!("cybersource-rs-", env!("CARGO_PKG_VERSION"));

/// Builds the signed HTTP request for `op`.
///
/// The URI, body and authentication are computed once, from the same
/// bytes, so the signature always covers exactly what is sent.
pub fn prepare<O: Operation + ?Sized>(
    op: &O,
    config: &Config,
    clock: &dyn Clock,
    entropy: &dyn Entropy,
) -> Result<Request<Bytes>> {
    let meta = op.meta();
    let target = request_target(&op.path(), &op.query());
    let uri: Uri = format!("https://{}{target}", config.environment().host())
        .parse()
        .map_err(|e| Error::Request(format!("invalid request URI for {target:?}: {e}")))?;

    if config.validate_requests() {
        op.validate()?;
    }

    let body_method = matches!(meta.method, Method::POST | Method::PUT | Method::PATCH);
    let mut body = match op.body()? {
        Some(body) => body,
        // Cybersource signs the digest of the body; an empty body is sent as `{}`.
        None if body_method => Bytes::from_static(b"{}"),
        None => Bytes::new(),
    };

    if meta.developer_id
        && let Some(developer_id) = config.developer_id()
    {
        body = with_developer_id(body, developer_id)?;
    }

    #[cfg(feature = "tracing")]
    tracing::trace!(body = %crate::redact::redact_body(&body), "request body");

    let mle = policy::resolve(meta, config.mle());
    if mle.request && !body.is_empty() {
        body = encrypt_request(meta.id, &body, config, clock, entropy)?;
    }
    let response_mle_kid = if mle.response {
        let kid = config
            .mle()
            .response_key
            .as_ref()
            .and_then(|k| k.key_id())
            .ok_or_else(|| {
                Error::Mle(format!(
                    "{} requires an encrypted response; configure MleConfig::response_key",
                    meta.id
                ))
            })?;
        Some(kid)
    } else {
        None
    };

    let auth_headers = if meta.no_auth {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "v-c-merchant-id",
            HeaderValue::from_str(config.merchant_id())
                .map_err(|_| Error::Config("merchant id contains invalid characters".into()))?,
        );
        headers
    } else {
        auth::authenticate(
            config,
            &SigningInput {
                method: &meta.method,
                target: &target,
                body: &body,
                response_mle_kid,
            },
            clock,
            entropy,
        )?
    };

    let has_content = !body.is_empty();
    let mut request = Request::builder()
        .method(meta.method.clone())
        .uri(uri)
        .body(body)
        .map_err(|e| Error::Request(e.to_string()))?;
    let headers = request.headers_mut();
    headers.extend(op.headers()?);
    headers.insert(
        ACCEPT,
        HeaderValue::from_static(op.accept().unwrap_or(ACCEPT_JSON)),
    );
    if has_content {
        headers.insert(CONTENT_TYPE, HeaderValue::from_static(CONTENT_TYPE_JSON));
    }
    headers.insert("v-c-client-id", HeaderValue::from_static(CLIENT_ID));
    headers.insert(
        USER_AGENT,
        HeaderValue::from_str(config.user_agent())
            .map_err(|_| Error::Config("user agent contains invalid characters".into()))?,
    );
    // Inserted last so operation headers can never replace authentication.
    for (name, value) in &auth_headers {
        headers.insert(name.clone(), value.clone());
    }
    #[cfg(feature = "tracing")]
    tracing::trace!(uri = %request.uri(), headers = ?crate::redact::redact_headers(request.headers()), "request");
    Ok(request)
}

/// Sets `clientReferenceInformation.partner.developerId` in a serialized
/// body unless it is already set. Works on the bytes, never the caller's
/// value.
fn with_developer_id(body: Bytes, developer_id: &str) -> Result<Bytes> {
    let mut value: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| Error::Request(format!("request body is not JSON: {e}")))?;
    let Some(root) = value.as_object_mut() else {
        return Ok(body);
    };
    let partner = root
        .entry("clientReferenceInformation")
        .or_insert_with(|| serde_json::json!({}))
        .as_object_mut()
        .map(|cri| {
            cri.entry("partner")
                .or_insert_with(|| serde_json::json!({}))
        });
    match partner.and_then(serde_json::Value::as_object_mut) {
        Some(partner) if !partner.contains_key("developerId") => {
            partner.insert("developerId".into(), developer_id.into());
            serde_json::to_vec(&value)
                .map(Bytes::from)
                .map_err(|e| Error::Request(e.to_string()))
        }
        _ => Ok(body),
    }
}

/// Replaces `body` with `{"encryptedRequest": "<JWE>"}`, encrypted to
/// Cybersource's request certificate.
fn encrypt_request(
    operation_id: &str,
    body: &[u8],
    config: &Config,
    clock: &dyn Clock,
    entropy: &dyn Entropy,
) -> Result<Bytes> {
    let jwt = matches!(
        config.credentials(),
        crate::config::Credentials::JwtSharedSecret { .. }
            | crate::config::Credentials::JwtRsa { .. }
    );
    let cert = config
        .mle()
        .request_cert
        .as_ref()
        .filter(|_| jwt)
        .ok_or_else(|| {
            Error::Mle(format!(
                "{operation_id} requires message-level encryption; use JWT authentication with \
             a request MLE certificate (a Business Center P12, or MleConfig::request_cert)"
            ))
        })?;
    let mut header = serde_json::Map::new();
    header.insert("kid".into(), cert.kid.clone().into());
    header.insert("iat".into(), clock.now().as_secs().into());
    header.insert("cty".into(), "application/json".into());
    let token = jwe::encrypt(
        &cert.key,
        KeyAlg::RsaOaep256,
        Enc::A256Gcm,
        &header,
        body,
        entropy,
    )
    .map_err(|e| Error::Mle(e.to_string()))?;
    let wrapper = serde_json::json!({ "encryptedRequest": token });
    Ok(Bytes::from(
        serde_json::to_vec(&wrapper).map_err(|e| Error::Mle(e.to_string()))?,
    ))
}

/// The JWE in a body that is exactly `{"encryptedResponse": "<string>"}`.
fn encrypted_response(body: &[u8]) -> Option<String> {
    // Cheap check first: most responses are not encrypted.
    if !body.windows(19).any(|w| w == b"\"encryptedResponse\"") {
        return None;
    }
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    let object = value.as_object().filter(|o| o.len() == 1)?;
    object.get("encryptedResponse")?.as_str().map(str::to_owned)
}

/// Decodes a response: decrypts it if it is MLE-encrypted, then 2xx goes
/// to the operation and anything else becomes [`Error::Api`].
pub fn finish<O: Operation + ?Sized>(
    op: &O,
    config: &Config,
    response: http::Response<Bytes>,
) -> Result<Response<O::Output>> {
    let (parts, mut body) = response.into_parts();
    if let Some(token) = encrypted_response(&body) {
        let key = config.mle().response_key.as_ref().ok_or_else(|| {
            Error::Mle("the response is encrypted but no response MLE key is configured".into())
        })?;
        let decrypted = jwe::decrypt(&key.key, &token, &[KeyAlg::RsaOaep256, KeyAlg::RsaOaep])
            .map_err(|e| Error::Mle(format!("could not decrypt the response: {e}")))?;
        body = Bytes::from(decrypted.plaintext);
    }
    #[cfg(feature = "tracing")]
    tracing::trace!(status = parts.status.as_u16(), body = %crate::redact::redact_body(&body), "response body");
    if !parts.status.is_success() {
        return Err(Error::Api(Box::new(ApiError {
            status: parts.status,
            body: ErrorBody::parse(&body),
            correlation_id: response::correlation_id(&parts.headers).map(str::to_owned),
            raw: body,
            retry_safe: op.meta().retry_safe,
        })));
    }
    let decoded = op.decode(parts.status, &body)?;
    Ok(Response {
        status: parts.status,
        headers: parts.headers,
        body: decoded,
    })
}

/// `path?query` with RFC 3986 encoding, exactly as signed and sent.
fn request_target(path: &str, query: &[(&'static str, String)]) -> String {
    if query.is_empty() {
        return path.to_owned();
    }
    let query = query
        .iter()
        .map(|(k, v)| format!("{}={}", encode_path_segment(k), encode_path_segment(v)))
        .collect::<Vec<_>>()
        .join("&");
    format!("{path}?{query}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_without_query_is_the_path() {
        assert_eq!(request_target("/pts/v2/payments", &[]), "/pts/v2/payments");
    }

    #[test]
    fn target_encodes_query_with_percent_twenty() {
        assert_eq!(
            request_target(
                "/reporting/v3/reports",
                &[
                    ("reportName", "My Report".into()),
                    ("startTime", "2026-11-01T00:00:00Z".into())
                ]
            ),
            "/reporting/v3/reports?reportName=My%20Report&startTime=2026-11-01T00%3A00%3A00Z"
        );
    }
}
