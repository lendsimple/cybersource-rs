//! HTTP transports.
//!
//! A transport sends an `http::Request<Bytes>` and returns the full
//! response. Implement [`HttpTransport`] (async) or
//! [`BlockingHttpTransport`] to use any HTTP client.

use std::future::Future;

use bytes::Bytes;

use crate::error::BoxError;

pub mod mock;

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
