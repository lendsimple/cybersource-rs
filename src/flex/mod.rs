//! Flex: capture contexts, transient tokens and client-side tokenization.
//!
//! The types and checks here need no merchant credentials, so they are
//! available without the `server` feature: a browser build uses
//! `default-features = false, features = ["browser"]`.

pub mod context;
pub mod tokenize;

pub use context::{CaptureContext, ContextEntry, Flx, TransientToken};
pub use tokenize::{
    CardData, FlexError, TokenizeRequest, parse_tokenize_response, tokenize_request,
};
