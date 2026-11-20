//! Error types.

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

    /// The HTTP transport failed before a response was received.
    #[error("transport error: {0}")]
    Transport(#[source] BoxError),

    /// The operating system could not supply random bytes.
    #[error("random number generator failed: {0}")]
    Entropy(String),

    /// A request body could not be serialized.
    #[error("failed to serialize request body: {0}")]
    Serialize(#[source] serde_json::Error),

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
