//! ISO 4217 currency codes.

use std::fmt;
use std::str::FromStr;

/// A three-letter currency code such as `USD`, stored upper case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Currency([u8; 3]);

/// Error from parsing an invalid [`Currency`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid currency code {0:?}: expected three letters, e.g. \"USD\"")]
pub struct InvalidCurrency(pub String);

/// Whether `s` is three ASCII letters. `const` for [`currency!`](crate::currency!).
pub const fn is_valid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 3
        && b[0].is_ascii_alphabetic()
        && b[1].is_ascii_alphabetic()
        && b[2].is_ascii_alphabetic()
}

impl Currency {
    /// The code, upper case.
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0).expect("ASCII")
    }
}

impl FromStr for Currency {
    type Err = InvalidCurrency;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !is_valid(s) {
            return Err(InvalidCurrency(s.to_owned()));
        }
        let b = s.as_bytes();
        Ok(Currency([
            b[0].to_ascii_uppercase(),
            b[1].to_ascii_uppercase(),
            b[2].to_ascii_uppercase(),
        ]))
    }
}

impl fmt::Display for Currency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<Currency> for String {
    fn from(c: Currency) -> String {
        c.as_str().to_owned()
    }
}

/// A [`Currency`] from an identifier, checked at compile time: `currency!(USD)`.
#[macro_export]
macro_rules! currency {
    ($code:ident) => {{
        const _: () = ::core::assert!(
            $crate::types::currency::is_valid(::core::stringify!($code)),
            ::core::concat!("invalid currency code: ", ::core::stringify!($code))
        );
        <$crate::types::Currency as ::core::str::FromStr>::from_str(::core::stringify!($code))
            .expect("checked at compile time")
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_normalizes() {
        assert_eq!("usd".parse::<Currency>().unwrap().as_str(), "USD");
        assert_eq!(crate::currency!(EUR).to_string(), "EUR");
        assert!("US".parse::<Currency>().is_err());
        assert!("U$D".parse::<Currency>().is_err());
    }
}
