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
pub mod client;
pub mod clock;
#[cfg(feature = "server")]
pub mod config;
pub mod entropy;
pub mod error;
pub mod jose;
#[cfg(feature = "server")]
pub mod keys;
#[cfg(feature = "server")]
pub mod models;
#[cfg(feature = "server")]
pub mod operation;
#[cfg(feature = "server")]
pub mod operations;
#[cfg(feature = "server")]
pub mod pipeline;
#[cfg(feature = "server")]
pub mod response;
#[cfg(feature = "server")]
pub mod transport;

#[cfg(all(feature = "server", not(target_family = "wasm")))]
pub use client::BlockingClient;
#[cfg(feature = "server")]
pub use client::Client;
#[cfg(feature = "server")]
pub use config::{Config, Credentials, Environment};
pub use error::{Error, Result};
