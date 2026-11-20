//! Operations and per-API accessors (`client.payments()`).
//!
//! Stage 1 ships `createPayment` by hand; Stage 2 generates every operation.

pub mod payments;

pub use payments::{CreatePayment, Payments};
