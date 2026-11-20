//! HTTP transports.
//!
//! A transport sends an `http::Request<Bytes>` and returns the full
//! response. Implement [`HttpTransport`] (async) or
//! [`BlockingHttpTransport`] to use any HTTP client.

use std::future::Future;

use bytes::Bytes;

use crate::error::BoxError;

pub mod mock;
#[cfg(feature = "reqwest")]
pub mod reqwest;
#[cfg(all(feature = "ureq", not(target_family = "wasm")))]
pub mod ureq;

#[cfg(feature = "reqwest")]
pub use self::reqwest::ReqwestTransport;
#[cfg(all(feature = "ureq", not(target_family = "wasm")))]
pub use self::ureq::UreqTransport;
pub use mock::MockTransport;

/// `Send` on native targets, nothing on WebAssembly, whose futures are
/// single-threaded and not `Send`.
#[cfg(not(target_family = "wasm"))]
pub trait MaybeSend: Send {}
#[cfg(not(target_family = "wasm"))]
impl<T: Send + ?Sized> MaybeSend for T {}

/// `Send` on native targets, nothing on WebAssembly, whose futures are
/// single-threaded and not `Send`.
#[cfg(target_family = "wasm")]
pub trait MaybeSend {}
#[cfg(target_family = "wasm")]
impl<T: ?Sized> MaybeSend for T {}

/// An asynchronous HTTP transport.
pub trait HttpTransport {
    /// Sends `request` and reads the whole response body.
    fn send(
        &self,
        request: http::Request<Bytes>,
    ) -> impl Future<Output = Result<http::Response<Bytes>, BoxError>> + MaybeSend;
}

/// A blocking HTTP transport.
pub trait BlockingHttpTransport {
    /// Sends `request` and reads the whole response body.
    fn send(&self, request: http::Request<Bytes>) -> Result<http::Response<Bytes>, BoxError>;
}

/// Where a transport actually connects, when that differs from the
/// Cybersource host the request is signed for: an intermediate host, a
/// proxy, or a local mock server in tests.
#[derive(Debug, Clone)]
#[cfg_attr(not(any(feature = "reqwest", feature = "ureq")), allow(dead_code))]
pub(crate) struct BaseUrl {
    scheme: http::uri::Scheme,
    authority: http::uri::Authority,
}

#[cfg_attr(not(any(feature = "reqwest", feature = "ureq")), allow(dead_code))]
impl BaseUrl {
    /// Parses `scheme://host[:port]` (no path).
    pub(crate) fn parse(url: &str) -> crate::Result<Self> {
        let uri: http::Uri = url
            .parse()
            .map_err(|e| crate::Error::Config(format!("invalid base URL {url:?}: {e}")))?;
        let parts = uri.into_parts();
        match (parts.scheme, parts.authority, parts.path_and_query) {
            (Some(scheme), Some(authority), path)
                if path.as_ref().is_none_or(|p| p.as_str() == "/") =>
            {
                Ok(BaseUrl { scheme, authority })
            }
            _ => Err(crate::Error::Config(format!(
                "base URL must be scheme://host[:port] with no path, got {url:?}"
            ))),
        }
    }

    /// Replaces the request URI's scheme and authority, keeping path and query.
    pub(crate) fn apply(&self, request: &mut http::Request<Bytes>) -> Result<(), BoxError> {
        let mut parts = request.uri().clone().into_parts();
        parts.scheme = Some(self.scheme.clone());
        parts.authority = Some(self.authority.clone());
        *request.uri_mut() = http::Uri::from_parts(parts)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_url_rewrites_origin_and_keeps_path_and_query() {
        let base = BaseUrl::parse("http://127.0.0.1:8080").unwrap();
        let mut request = http::Request::builder()
            .uri("https://apitest.cybersource.com/pts/v2/payments?x=1")
            .body(Bytes::new())
            .unwrap();
        base.apply(&mut request).unwrap();
        assert_eq!(
            request.uri().to_string(),
            "http://127.0.0.1:8080/pts/v2/payments?x=1"
        );
    }

    #[test]
    fn base_url_rejects_paths() {
        assert!(BaseUrl::parse("https://proxy.example/cybs").is_err());
        assert!(BaseUrl::parse("proxy.example").is_err());
    }
}
