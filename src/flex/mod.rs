//! Flex: capture contexts, transient tokens and client-side tokenization.
//!
//! The types and checks here need no merchant credentials, so they are
//! available without any feature (`default-features = false`), for clients
//! that tokenize card data themselves: see [`tokenize`].
//!
//! **Browsers:** Cybersource rejects Flex API tokenization from web pages
//! ("Browser calls are not supported for Flex Direct API calls"). Web
//! checkouts use Microform or Unified Checkout, Cybersource's hosted
//! JavaScript: create their capture context on your server with
//! `capture_context()`, and verify the resulting token with
//! [`CaptureContext::verify_transient_token`].

pub mod context;
pub mod tokenize;

pub use context::{CaptureContext, ContextEntry, Flx, TransientToken};
pub use tokenize::{
    CardData, FlexError, TokenizeRequest, parse_tokenize_response, tokenize_request,
};
