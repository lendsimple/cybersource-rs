//! Idiomatic Rust client for the [Cybersource REST API](https://developer.cybersource.com/api-reference-assets/index.html).
//!
//! The crate is built around a sans-IO core: requests are built, signed and
//! parsed by pure functions, and sent through a pluggable transport. This lets
//! the same client run async, blocking, or on WebAssembly.
//!
//! See `implementation.md` in the repository for the design.

#[cfg(feature = "server")]
pub mod auth;
#[cfg(feature = "server")]
pub mod call;
#[cfg(feature = "server")]
pub mod client;
pub mod clock;
#[cfg(feature = "server")]
pub mod config;
pub mod entropy;
pub mod error;
#[cfg(feature = "server")]
pub mod flows;
#[cfg(feature = "server")]
mod generated;
pub mod jose;
#[cfg(feature = "server")]
pub mod keys;
#[cfg(feature = "server")]
pub mod mle;
#[cfg(feature = "server")]
pub mod operation;
#[cfg(feature = "server")]
pub mod pipeline;
#[cfg(feature = "server")]
pub mod response;
#[cfg(feature = "server")]
pub mod transport;
pub mod types;

#[cfg(feature = "server")]
pub use call::Call;
#[cfg(all(feature = "server", not(target_family = "wasm")))]
pub use client::BlockingClient;
#[cfg(feature = "server")]
pub use client::Client;
#[cfg(feature = "server")]
pub use config::{Config, Credentials, Environment};
pub use error::{Error, Result};

#[doc(hidden)]
pub mod __private {
    pub use serde;
}
#[cfg(feature = "server")]
pub use generated::{apis, models, operations};
