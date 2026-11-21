//! Higher-level helpers built on the generated operations.

#[cfg(any(feature = "payments", feature = "payouts"))]
pub mod outcome;
pub mod pages;

#[cfg(feature = "payments")]
pub use outcome::PaymentOutcome;
pub use pages::{PageInfo, Paged, Pager};
