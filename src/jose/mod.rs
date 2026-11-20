//! Minimal JOSE primitives (base64url, compact JWS).
//!
//! Hand-written rather than pulled from a JOSE crate: we need exact control
//! over headers and claims, and the available crates either need OpenSSL or
//! don't build cleanly for every wasm target.

pub mod b64;
pub mod jws;
