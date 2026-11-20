//! The [`Operation`] trait: one Cybersource API call, described as data.
//!
//! Operations know how to describe their request (path, query, headers,
//! body) and decode their response. They never perform I/O, so the same
//! operation runs on any client and transport.

use std::borrow::Cow;

use bytes::Bytes;
use http::{HeaderMap, Method, StatusCode};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use serde::de::DeserializeOwned;

use crate::{Error, Result};

/// Whether an operation uses message-level encryption (from the spec's
/// `x-devcenter-metaData`). Enforced from Stage 3; recorded now so
/// generated operations carry it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MlePolicy {
    /// Never encrypted.
    Never,
    /// Encrypted when enabled in the configuration.
    Optional,
    /// Cybersource requires encryption.
    Mandatory,
}

/// Static facts about an operation.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct OperationMeta {
    /// The spec's operation id, e.g. `createPayment`.
    pub id: &'static str,
    /// HTTP method.
    pub method: Method,
    /// Path template from the spec, e.g. `/pts/v2/payments/{id}/captures`.
    pub path_template: &'static str,
    /// Request encryption policy.
    pub mle_request: MlePolicy,
    /// Response encryption policy.
    pub mle_response: MlePolicy,
    /// False for operations that move money; never retry those blindly.
    pub retry_safe: bool,
    /// True for the few operations Cybersource serves without authentication.
    pub no_auth: bool,
}

impl OperationMeta {
    /// Metadata with no encryption, retry-safe. Adjust with struct update syntax.
    pub const fn new(id: &'static str, method: Method, path_template: &'static str) -> Self {
        OperationMeta {
            id,
            method,
            path_template,
            mle_request: MlePolicy::Never,
            mle_response: MlePolicy::Never,
            retry_safe: true,
            no_auth: false,
        }
    }

    /// Sets the request and response encryption policies.
    pub const fn mle(mut self, request: MlePolicy, response: MlePolicy) -> Self {
        self.mle_request = request;
        self.mle_response = response;
        self
    }

    /// Marks the operation as served without authentication.
    pub const fn no_auth(mut self) -> Self {
        self.no_auth = true;
        self
    }

    /// Marks the operation as moving money (not safe to retry).
    pub const fn moves_money(mut self) -> Self {
        self.retry_safe = false;
        self
    }
}

/// One Cybersource API operation.
pub trait Operation {
    /// The decoded success response.
    type Output;

    /// Static facts about the operation.
    fn meta(&self) -> &'static OperationMeta;

    /// The request path with parameters substituted and percent-encoded
    /// (see [`encode_path_segment`]).
    fn path(&self) -> Cow<'_, str>;

    /// Query parameters, unencoded.
    fn query(&self) -> Vec<(&'static str, String)> {
        Vec::new()
    }

    /// Extra request headers. They can never override authentication headers.
    fn headers(&self) -> HeaderMap {
        HeaderMap::new()
    }

    /// The serialized request body, if any. POST, PUT and PATCH without a
    /// body send `{}`; a GET or DELETE body is sent as given.
    fn body(&self) -> Result<Option<Bytes>> {
        Ok(None)
    }

    /// The `Accept` header, for operations that return non-JSON content
    /// (CSV, XML, PDF, JWT). `None` means JSON.
    fn accept(&self) -> Option<&'static str> {
        None
    }

    /// Decodes a success (2xx) response body.
    fn decode(&self, status: StatusCode, body: &Bytes) -> Result<Self::Output>;
}

/// Characters left unescaped: RFC 3986 unreserved (`A-Z a-z 0-9 - . _ ~`).
const UNRESERVED: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// Percent-encodes a path parameter or query component (RFC 3986; space
/// becomes `%20`, never `+`).
pub fn encode_path_segment(value: &str) -> Cow<'_, str> {
    utf8_percent_encode(value, UNRESERVED).into()
}

/// Serializes a request body to JSON bytes.
pub fn json_body<T: serde::Serialize>(body: &T) -> Result<Option<Bytes>> {
    serde_json::to_vec(body)
        .map(|v| Some(Bytes::from(v)))
        .map_err(|e| Error::Request(format!("failed to serialize request body: {e}")))
}

/// Deserializes a JSON response body.
pub fn json_decode<T: DeserializeOwned>(body: &Bytes) -> Result<T> {
    serde_json::from_slice(body).map_err(|e| Error::decode(e, body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_reserved_characters_and_spaces() {
        assert_eq!(
            encode_path_segment("My Report/2026:11+x~y"),
            "My%20Report%2F2026%3A11%2Bx~y"
        );
    }

    #[test]
    fn moves_money_clears_retry_safe() {
        let meta = OperationMeta::new("x", Method::POST, "/x").moves_money();
        assert!(!meta.retry_safe);
    }
}
