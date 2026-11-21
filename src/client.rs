//! Clients: [`Client`] (async) and [`BlockingClient`].
//!
//! Both are thin: they run the shared sans-IO [`pipeline`]
//! around a transport. Cloning is cheap; configuration and keys are shared.

use std::sync::Arc;

use crate::clock::{Clock, SystemClock};
use crate::config::Config;
use crate::entropy::{Entropy, OsEntropy};
use crate::operation::Operation;
use crate::pipeline;
use crate::response::Response;
#[cfg(not(target_family = "wasm"))]
use crate::transport::BlockingHttpTransport;
use crate::transport::HttpTransport;
#[cfg(feature = "reqwest")]
use crate::transport::ReqwestTransport;
#[cfg(all(feature = "ureq", not(target_family = "wasm")))]
use crate::transport::UreqTransport;
use crate::{Error, Result};

struct Inner {
    config: Config,
    clock: Arc<dyn Clock>,
    entropy: Arc<dyn Entropy>,
}

impl std::fmt::Debug for Inner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Inner")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl Inner {
    fn new(config: Config) -> Self {
        Inner {
            config,
            clock: Arc::new(SystemClock),
            entropy: Arc::new(OsEntropy),
        }
    }
}

macro_rules! client_common {
    ($client:ident, $bound:path) => {
        impl<T: $bound> $client<T> {
            /// Creates a client from a validated configuration, sending requests
            /// through `transport`.
            pub fn with_transport(config: Config, transport: T) -> Self {
                $client {
                    inner: Arc::new(Inner::new(config)),
                    transport,
                }
            }

            /// Replaces the clock (for deterministic tests).
            ///
            /// # Panics
            /// If the client has already been cloned.
            pub fn with_clock(mut self, clock: impl Clock + 'static) -> Self {
                self.inner_mut().clock = Arc::new(clock);
                self
            }

            /// Replaces the entropy source (for deterministic tests).
            ///
            /// # Panics
            /// If the client has already been cloned.
            pub fn with_entropy(mut self, entropy: impl Entropy + 'static) -> Self {
                self.inner_mut().entropy = Arc::new(entropy);
                self
            }

            /// The client's configuration.
            pub fn config(&self) -> &Config {
                &self.inner.config
            }

            /// The underlying transport.
            pub fn transport(&self) -> &T {
                &self.transport
            }

            /// The client's clock, as time since the Unix epoch.
            pub(crate) fn now(&self) -> ::std::time::Duration {
                self.inner.clock.now()
            }

            fn inner_mut(&mut self) -> &mut Inner {
                Arc::get_mut(&mut self.inner)
                    .expect("with_clock/with_entropy must be called before the client is cloned")
            }

            fn prepare<O: Operation + ?Sized>(
                &self,
                op: &O,
            ) -> Result<http::Request<bytes::Bytes>> {
                let inner = &*self.inner;
                pipeline::prepare(op, &inner.config, &*inner.clock, &*inner.entropy)
            }
        }
    };
}

/// An asynchronous Cybersource client.
///
/// [`Client::new`] sends requests through a [`ReqwestTransport`];
/// [`Client::with_transport`] takes any other [`HttpTransport`].
#[cfg(feature = "reqwest")]
#[derive(Debug, Clone)]
pub struct Client<T = ReqwestTransport> {
    inner: Arc<Inner>,
    transport: T,
}

/// An asynchronous Cybersource client.
///
/// It sends requests through an [`HttpTransport`]; enable the `reqwest`
/// feature for a default one.
#[cfg(not(feature = "reqwest"))]
#[derive(Debug, Clone)]
pub struct Client<T> {
    inner: Arc<Inner>,
    transport: T,
}

client_common!(Client, HttpTransport);

#[cfg(feature = "reqwest")]
impl Client {
    /// Creates a client that sends requests through a default
    /// [`ReqwestTransport`].
    ///
    /// # Panics
    /// Like `reqwest::Client::new`, if the TLS backend cannot be initialized.
    pub fn new(config: Config) -> Self {
        Self::with_transport(config, ReqwestTransport::new())
    }
}

impl<T: HttpTransport> Client<T> {
    /// Runs an operation and returns its decoded body.
    pub async fn execute<O: Operation + ?Sized>(&self, op: &O) -> Result<O::Output> {
        self.execute_with_response(op)
            .await
            .map(Response::into_body)
    }

    /// Runs an operation and returns the body with status and headers.
    pub async fn execute_with_response<O: Operation + ?Sized>(
        &self,
        op: &O,
    ) -> Result<Response<O::Output>> {
        #[cfg(feature = "tracing")]
        {
            use tracing::Instrument;
            let span = crate::telemetry::span(op.meta());
            let start = web_time::Instant::now();
            let result = self.run(op).instrument(span.clone()).await;
            crate::telemetry::finished(&span, &result, start);
            result
        }
        #[cfg(not(feature = "tracing"))]
        self.run(op).await
    }

    async fn run<O: Operation + ?Sized>(&self, op: &O) -> Result<Response<O::Output>> {
        let request = self.prepare(op)?;
        let response = self
            .transport
            .send(request)
            .await
            .map_err(Error::Transport)?;
        pipeline::finish(op, &self.inner.config, response)
    }
}

/// A blocking Cybersource client. Not available on WebAssembly.
///
/// [`BlockingClient::new`] sends requests through a [`UreqTransport`];
/// [`BlockingClient::with_transport`] takes any other
/// [`BlockingHttpTransport`].
#[cfg(all(feature = "ureq", not(target_family = "wasm")))]
#[derive(Debug, Clone)]
pub struct BlockingClient<T = UreqTransport> {
    inner: Arc<Inner>,
    transport: T,
}

/// A blocking Cybersource client. Not available on WebAssembly.
///
/// It sends requests through a [`BlockingHttpTransport`]; enable the `ureq`
/// feature for a default one.
#[cfg(all(not(feature = "ureq"), not(target_family = "wasm")))]
#[derive(Debug, Clone)]
pub struct BlockingClient<T> {
    inner: Arc<Inner>,
    transport: T,
}

#[cfg(not(target_family = "wasm"))]
client_common!(BlockingClient, BlockingHttpTransport);

#[cfg(all(feature = "ureq", not(target_family = "wasm")))]
impl BlockingClient {
    /// Creates a client that sends requests through a default
    /// [`UreqTransport`].
    pub fn new(config: Config) -> Self {
        Self::with_transport(config, UreqTransport::new())
    }
}

#[cfg(not(target_family = "wasm"))]
impl<T: BlockingHttpTransport> BlockingClient<T> {
    /// Runs an operation and returns its decoded body.
    pub fn execute<O: Operation + ?Sized>(&self, op: &O) -> Result<O::Output> {
        self.execute_with_response(op).map(Response::into_body)
    }

    /// Runs an operation and returns the body with status and headers.
    pub fn execute_with_response<O: Operation + ?Sized>(
        &self,
        op: &O,
    ) -> Result<Response<O::Output>> {
        #[cfg(feature = "tracing")]
        {
            let span = crate::telemetry::span(op.meta());
            let start = web_time::Instant::now();
            let result = span.in_scope(|| self.run(op));
            crate::telemetry::finished(&span, &result, start);
            result
        }
        #[cfg(not(feature = "tracing"))]
        self.run(op)
    }

    fn run<O: Operation + ?Sized>(&self, op: &O) -> Result<Response<O::Output>> {
        let request = self.prepare(op)?;
        let response = self.transport.send(request).map_err(Error::Transport)?;
        pipeline::finish(op, &self.inner.config, response)
    }
}
