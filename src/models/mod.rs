//! Request and response models.
//!
//! Stage 1 ships a hand-written subset for `POST /pts/v2/payments`. Stage 2
//! replaces this module with models generated from the official spec, in
//! the same shape: all fields optional, camelCase JSON, sensitive fields
//! redacted in `Debug`.

pub mod payments;

pub use payments::*;
