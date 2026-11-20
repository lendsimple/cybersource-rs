//! Idiomatic Rust client for the [Cybersource REST API](https://developer.cybersource.com/api-reference-assets/index.html).
//!
//! The crate is built around a sans-IO core: requests are built, signed and
//! parsed by pure functions, and sent through a pluggable transport. This lets
//! the same client run async, blocking, or on WebAssembly.
//!
//! See `implementation.md` in the repository for the design.

#[cfg(feature = "server")]
pub mod auth;
pub mod clock;
#[cfg(feature = "server")]
pub mod config;
pub mod entropy;
pub mod error;
pub mod jose;
#[cfg(feature = "server")]
pub mod keys;

pub use error::{Error, Result};
