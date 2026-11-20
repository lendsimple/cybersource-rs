//! An in-memory transport for tests: queued responses, recorded requests.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard};

use bytes::Bytes;

use super::{BlockingHttpTransport, HttpTransport};
use crate::error::BoxError;

#[derive(Debug, Default)]
struct State {
    responses: VecDeque<Result<http::Response<Bytes>, String>>,
    requests: Vec<http::Request<Bytes>>,
}

/// A transport that returns queued responses and records every request.
///
/// Clones share state, so a test can keep a handle after giving one to a
/// client. Works as both an async and a blocking transport.
#[derive(Debug, Clone, Default)]
pub struct MockTransport {
    state: Arc<Mutex<State>>,
}

impl MockTransport {
    /// An empty mock. Sending with no queued response is an error.
    pub fn new() -> Self {
        Self::default()
    }

    /// Queues a JSON response with the given status.
    pub fn push_json(&self, status: u16, body: impl Into<String>) -> &Self {
        let response = http::Response::builder()
            .status(status)
            .header("content-type", "application/hal+json;charset=utf-8")
            .body(Bytes::from(body.into()))
            .expect("valid mock response");
        self.push_response(response)
    }

    /// Queues an arbitrary response.
    pub fn push_response(&self, response: http::Response<Bytes>) -> &Self {
        self.lock().responses.push_back(Ok(response));
        self
    }

    /// Queues a transport failure.
    pub fn push_error(&self, message: impl Into<String>) -> &Self {
        self.lock().responses.push_back(Err(message.into()));
        self
    }

    /// The requests sent so far, in order.
    pub fn requests(&self) -> Vec<http::Request<Bytes>> {
        self.lock().requests.clone()
    }

    /// The most recent request.
    ///
    /// # Panics
    /// If nothing has been sent.
    pub fn last_request(&self) -> http::Request<Bytes> {
        self.lock()
            .requests
            .last()
            .cloned()
            .expect("no request has been sent")
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        // A panic in another test thread must not hide this test's result.
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn respond(&self, request: http::Request<Bytes>) -> Result<http::Response<Bytes>, BoxError> {
        let mut state = self.lock();
        state.requests.push(request);
        match state.responses.pop_front() {
            Some(Ok(response)) => Ok(response),
            Some(Err(message)) => Err(message.into()),
            None => Err("MockTransport has no queued response".into()),
        }
    }
}

impl HttpTransport for MockTransport {
    async fn send(&self, request: http::Request<Bytes>) -> Result<http::Response<Bytes>, BoxError> {
        self.respond(request)
    }
}

impl BlockingHttpTransport for MockTransport {
    fn send(&self, request: http::Request<Bytes>) -> Result<http::Response<Bytes>, BoxError> {
        self.respond(request)
    }
}
