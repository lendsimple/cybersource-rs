//! Error types.

use bytes::Bytes;
use http::StatusCode;
use serde::Deserialize;

/// Convenience alias for results returned by this crate.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Boxed error from a transport or other external source.
pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Any error returned by this crate.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The client configuration is invalid.
    #[error("invalid configuration: {0}")]
    Config(String),

    /// A request could not be authenticated (signing, key or token failure).
    #[error("authentication failed: {0}")]
    Auth(String),

    /// The HTTP transport failed. The request may or may not have reached
    /// Cybersource; see [`Error::outcome_unknown`].
    #[error("transport error: {0}")]
    Transport(#[source] BoxError),

    /// Cybersource answered with a non-success HTTP status.
    #[error(transparent)]
    Api(Box<ApiError>),

    /// The operating system could not supply random bytes.
    #[error("random number generator failed: {0}")]
    Entropy(String),

    /// A request could not be built (body serialization, invalid URI or header).
    #[error("invalid request: {0}")]
    Request(String),

    /// A response body could not be decoded.
    #[error("failed to decode response body: {source}; body starts with: {body_snippet:?}")]
    Decode {
        /// The underlying decode error.
        #[source]
        source: serde_json::Error,
        /// The first bytes of the body, for debugging.
        body_snippet: String,
    },
}

impl Error {
    /// Builds a [`Error::Decode`] keeping at most 200 characters of the body.
    #[cfg(feature = "server")]
    pub(crate) fn decode(source: serde_json::Error, body: &[u8]) -> Self {
        let body_snippet = String::from_utf8_lossy(body).chars().take(200).collect();
        Error::Decode {
            source,
            body_snippet,
        }
    }

    /// The API error, if Cybersource answered with a non-success status.
    pub fn api(&self) -> Option<&ApiError> {
        match self {
            Error::Api(e) => Some(e),
            _ => None,
        }
    }

    /// Whether the request may have been processed even though it failed.
    ///
    /// True for transport failures (the request may have reached
    /// Cybersource) and for 5xx responses, which Cybersource documents as
    /// "status unknown". Never assume a payment failed when this is true:
    /// look it up (for example with the transaction details API) before
    /// retrying.
    pub fn outcome_unknown(&self) -> bool {
        match self {
            Error::Transport(_) => true,
            Error::Api(e) => e.outcome_unknown(),
            _ => false,
        }
    }
}

/// A non-success HTTP response from Cybersource.
#[derive(Debug, Clone, thiserror::Error)]
#[error("Cybersource returned HTTP {status}: {}", body.summary())]
pub struct ApiError {
    /// The HTTP status.
    pub status: StatusCode,
    /// The parsed error body.
    pub body: ErrorBody,
    /// The `v-c-correlation-id` response header, for Cybersource support.
    pub correlation_id: Option<String>,
    /// The raw response body.
    pub raw: Bytes,
    /// Whether the operation is safe to retry (it does not move money).
    pub retry_safe: bool,
}

impl ApiError {
    /// Whether the request may have been processed: any 5xx status.
    pub fn outcome_unknown(&self) -> bool {
        self.status.is_server_error()
    }

    /// Whether the operation is safe to retry. Money-moving operations
    /// (payments, captures, refunds, credits, reversals, payouts) are not.
    pub fn is_retry_safe(&self) -> bool {
        self.retry_safe
    }
}

/// A parsed error response body.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ErrorBody {
    /// The payments-style error body (`/pts`, risk, and most other APIs).
    Pts(PtsError),
    /// The Token Management Service error body: `{"errors": [...]}`.
    Tms(TmsErrors),
    /// JSON in a shape not modelled here.
    Json(serde_json::Value),
    /// A non-JSON body (possibly empty).
    Text(String),
}

impl ErrorBody {
    /// Parses a body as a [`PtsError`], falling back to raw JSON or text.
    #[cfg(feature = "server")]
    pub(crate) fn parse(raw: &[u8]) -> Self {
        if let Ok(tms) = serde_json::from_slice::<TmsErrors>(raw)
            && !tms.errors.is_empty()
        {
            return ErrorBody::Tms(tms);
        }
        if let Ok(pts) = serde_json::from_slice::<PtsError>(raw)
            && (pts.reason.is_some() || pts.message.is_some())
        {
            return ErrorBody::Pts(pts);
        }
        match serde_json::from_slice(raw) {
            Ok(value) => ErrorBody::Json(value),
            Err(_) => ErrorBody::Text(String::from_utf8_lossy(raw).into_owned()),
        }
    }

    fn summary(&self) -> String {
        match self {
            ErrorBody::Pts(e) => format!(
                "{} {}",
                e.reason.as_deref().unwrap_or("UNKNOWN"),
                e.message.as_deref().unwrap_or("")
            ),
            ErrorBody::Tms(e) => e
                .errors
                .iter()
                .map(|e| {
                    format!(
                        "{} {}",
                        e.r#type.as_deref().unwrap_or("UNKNOWN"),
                        e.message.as_deref().unwrap_or("")
                    )
                })
                .collect::<Vec<_>>()
                .join("; "),
            ErrorBody::Json(v) => v.to_string().chars().take(200).collect(),
            ErrorBody::Text(t) => t.chars().take(200).collect(),
        }
    }
}

/// The payments-style error body, e.g. for HTTP 400 and 502 from `/pts/v2/payments`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct PtsError {
    /// When Cybersource processed the request.
    pub submit_time_utc: Option<String>,
    /// e.g. `INVALID_REQUEST` or `SERVER_ERROR`.
    pub status: Option<String>,
    /// e.g. `MISSING_FIELD`, `INVALID_DATA`, `DUPLICATE_REQUEST`, `SYSTEM_ERROR`.
    pub reason: Option<String>,
    /// Human-readable description.
    pub message: Option<String>,
    /// Field-level problems.
    #[serde(default)]
    pub details: Vec<PtsErrorDetail>,
}

/// A field-level problem in a [`PtsError`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[non_exhaustive]
pub struct PtsErrorDetail {
    /// The offending field, e.g. `paymentInformation.card.number`.
    pub field: Option<String>,
    /// e.g. `MISSING_FIELD` or `INVALID_DATA`.
    pub reason: Option<String>,
}

/// The Token Management Service error body.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[non_exhaustive]
pub struct TmsErrors {
    /// The errors, usually one.
    #[serde(default)]
    pub errors: Vec<TmsError>,
}

/// One TMS error.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[non_exhaustive]
pub struct TmsError {
    /// e.g. `notFound`, `invalidHeaders`, `missingFields`, `forbidden`, `conflict`.
    pub r#type: Option<String>,
    /// Human-readable description.
    pub message: Option<String>,
    /// The offending fields or headers.
    #[serde(default)]
    pub details: Vec<TmsErrorDetail>,
}

/// A field- or header-level problem in a [`TmsError`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[non_exhaustive]
pub struct TmsErrorDetail {
    /// The field or header name.
    pub name: Option<String>,
    /// Where it is, e.g. `header` or `body`.
    pub location: Option<String>,
}

#[cfg(all(test, feature = "server"))]
mod tests {
    use super::*;

    #[test]
    fn decode_truncates_body_snippet() {
        let body = "x".repeat(500);
        let source = serde_json::from_str::<u8>("not json").unwrap_err();
        let Error::Decode { body_snippet, .. } = Error::decode(source, body.as_bytes()) else {
            panic!("expected Decode");
        };
        assert_eq!(body_snippet.len(), 200);
    }

    #[test]
    fn parses_pts_error() {
        let body = br#"{"submitTimeUtc":"2026-11-20T00:00:00Z","status":"INVALID_REQUEST","reason":"MISSING_FIELD","message":"Declined","details":[{"field":"orderInformation.billTo.country","reason":"MISSING_FIELD"}]}"#;
        let ErrorBody::Pts(e) = ErrorBody::parse(body) else {
            panic!("expected Pts");
        };
        assert_eq!(e.reason.as_deref(), Some("MISSING_FIELD"));
        assert_eq!(
            e.details[0].field.as_deref(),
            Some("orderInformation.billTo.country")
        );
    }

    #[test]
    fn parses_tms_errors() {
        let body = br#"{"errors":[{"type":"notFound","message":"Token not found","details":[{"name":"customerId","location":"path"}]}]}"#;
        let ErrorBody::Tms(e) = ErrorBody::parse(body) else {
            panic!("expected Tms");
        };
        assert_eq!(e.errors[0].r#type.as_deref(), Some("notFound"));
        assert_eq!(e.errors[0].details[0].name.as_deref(), Some("customerId"));
    }

    #[test]
    fn falls_back_to_json_then_text() {
        assert!(matches!(
            ErrorBody::parse(br#"{"errors":[]}"#),
            ErrorBody::Json(_)
        ));
        assert!(matches!(ErrorBody::parse(b"<html>"), ErrorBody::Text(_)));
    }
}
