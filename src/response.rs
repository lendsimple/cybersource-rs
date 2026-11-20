//! A decoded response with its HTTP metadata.

use http::{HeaderMap, StatusCode};

/// A successful response: the decoded body plus status and headers.
#[derive(Debug, Clone)]
pub struct Response<T> {
    /// The HTTP status (e.g. 201 for a payment, even when it was declined).
    pub status: StatusCode,
    /// Response headers.
    pub headers: HeaderMap,
    /// The decoded body.
    pub body: T,
}

impl<T> Response<T> {
    /// The `v-c-correlation-id` header, which Cybersource support asks for.
    /// Some APIs spell it `v-c-correlationid`; both are accepted.
    pub fn correlation_id(&self) -> Option<&str> {
        correlation_id(&self.headers)
    }

    /// Discards the metadata and returns the body.
    pub fn into_body(self) -> T {
        self.body
    }
}

pub(crate) fn correlation_id(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("v-c-correlation-id")
        .or_else(|| headers.get("v-c-correlationid"))
        .and_then(|v| v.to_str().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_header(name: &'static str) -> Response<()> {
        let mut headers = HeaderMap::new();
        headers.insert(name, "abc-123".parse().unwrap());
        Response {
            status: StatusCode::OK,
            headers,
            body: (),
        }
    }

    #[test]
    fn correlation_id_accepts_both_spellings() {
        assert_eq!(
            with_header("v-c-correlation-id").correlation_id(),
            Some("abc-123")
        );
        assert_eq!(
            with_header("v-c-correlationid").correlation_id(),
            Some("abc-123")
        );
    }
}
