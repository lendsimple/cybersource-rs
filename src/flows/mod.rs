//! Higher-level helpers built on the generated operations.

#[cfg(any(feature = "payments", feature = "payouts"))]
pub mod outcome;

#[cfg(feature = "payments")]
pub use outcome::PaymentOutcome;
