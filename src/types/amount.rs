//! Monetary amounts as Cybersource expects them: decimal strings.

use std::fmt;
use std::str::FromStr;

/// A decimal amount such as `"102.21"`: up to 12 integer digits and up to 4
/// decimals, no sign, no exponent. Cybersource takes amounts as strings, so
/// this never passes through floating point.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Amount(String);

/// Error from parsing an invalid [`Amount`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid amount {0:?}: expected digits with an optional decimal part, e.g. \"10.00\"")]
pub struct InvalidAmount(pub String);

/// Whether `s` is a valid amount. `const` so [`amount!`](crate::amount!) can
/// check literals at compile time.
pub const fn is_valid(s: &str) -> bool {
    let b = s.as_bytes();
    let (mut i, mut int_digits, mut frac_digits, mut seen_dot) = (0, 0, 0, false);
    while i < b.len() {
        match b[i] {
            b'0'..=b'9' if seen_dot => frac_digits += 1,
            b'0'..=b'9' => int_digits += 1,
            b'.' if !seen_dot => seen_dot = true,
            _ => return false,
        }
        i += 1;
    }
    int_digits >= 1 && int_digits <= 12 && (!seen_dot || (frac_digits >= 1 && frac_digits <= 4))
}

impl Amount {
    /// Parses an amount, rejecting anything Cybersource would not accept.
    pub fn new(s: impl Into<String>) -> Result<Self, InvalidAmount> {
        let s = s.into();
        if is_valid(&s) {
            Ok(Amount(s))
        } else {
            Err(InvalidAmount(s))
        }
    }

    /// Used by [`amount!`](crate::amount!) after its compile-time check.
    #[doc(hidden)]
    pub fn from_checked_literal(s: &'static str) -> Self {
        Amount(s.to_owned())
    }

    /// The amount as sent to Cybersource.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Amount {
    type Err = InvalidAmount;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Amount::new(s)
    }
}

impl From<Amount> for String {
    fn from(a: Amount) -> String {
        a.0
    }
}

#[cfg(feature = "rust_decimal")]
impl TryFrom<rust_decimal::Decimal> for Amount {
    type Error = InvalidAmount;
    fn try_from(d: rust_decimal::Decimal) -> Result<Self, Self::Error> {
        Amount::new(d.normalize().to_string())
    }
}

/// An [`Amount`] from a string literal, checked at compile time.
///
/// ```
/// let total = cybersource::amount!("102.21");
/// assert_eq!(total.as_str(), "102.21");
/// ```
///
/// ```compile_fail
/// let bad = cybersource::amount!("1,000");
/// ```
#[macro_export]
macro_rules! amount {
    ($s:literal) => {{
        const _: () = ::core::assert!(
            $crate::types::amount::is_valid($s),
            ::core::concat!("invalid amount literal: ", $s)
        );
        $crate::types::Amount::from_checked_literal($s)
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_cybersource_amounts() {
        for ok in ["0", "10", "10.0", "102.21", "0.0001", "999999999999.99"] {
            assert!(is_valid(ok), "{ok}");
        }
    }

    #[test]
    fn rejects_everything_else() {
        for bad in [
            "",
            ".",
            "1.",
            ".5",
            "-1",
            "+1",
            "1,000",
            "1e3",
            "1.23456",
            "1.2.3",
            " 1",
            "1234567890123",
        ] {
            assert!(Amount::new(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn macro_checks_at_compile_time() {
        assert_eq!(crate::amount!("5.00").to_string(), "5.00");
        assert_eq!(String::from(crate::amount!("7")), "7");
    }
}
