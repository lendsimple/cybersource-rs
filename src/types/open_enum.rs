//! `open_enum!`: string enums that keep values they don't know.
//!
//! Cybersource adds status and reason codes over time. An open enum maps
//! each known string to a variant and keeps anything else in `Unknown`, so
//! a new value never fails deserialization.

/// Declares an open string enum.
///
/// ```
/// cybersource::open_enum! {
///     /// A traffic light.
///     pub enum Light { Red = "RED", Green = "GREEN" }
/// }
/// assert_eq!(Light::from("RED"), Light::Red);
/// assert_eq!(Light::from("BLUE"), Light::Unknown("BLUE".into()));
/// assert_eq!(Light::Green.as_str(), "GREEN");
/// ```
#[macro_export]
macro_rules! open_enum {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident {
            $( $(#[$vmeta:meta])* $variant:ident = $value:literal ),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        #[non_exhaustive]
        $vis enum $name {
            $( $(#[$vmeta])* #[doc = ::core::concat!("`", $value, "`")] $variant, )*
            /// A value this version of the crate does not know.
            Unknown(::std::string::String),
        }

        impl $name {
            /// Every known value.
            pub const KNOWN: &'static [&'static str] = &[$($value),*];

            /// The value as sent by Cybersource.
            pub fn as_str(&self) -> &str {
                match self {
                    $( Self::$variant => $value, )*
                    Self::Unknown(s) => s,
                }
            }

            /// Whether this is a value the crate does not know.
            pub fn is_unknown(&self) -> bool {
                ::core::matches!(self, Self::Unknown(_))
            }
        }

        impl ::core::convert::From<&str> for $name {
            fn from(s: &str) -> Self {
                match s {
                    $( $value => Self::$variant, )*
                    other => Self::Unknown(other.to_owned()),
                }
            }
        }

        impl ::core::convert::From<::std::string::String> for $name {
            fn from(s: ::std::string::String) -> Self {
                Self::from(s.as_str())
            }
        }

        impl ::core::str::FromStr for $name {
            type Err = ::core::convert::Infallible;
            fn from_str(s: &str) -> ::core::result::Result<Self, Self::Err> {
                Ok(Self::from(s))
            }
        }

        impl ::core::fmt::Display for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl ::core::cmp::PartialEq<str> for $name {
            fn eq(&self, other: &str) -> bool {
                self.as_str() == other
            }
        }

        impl ::core::cmp::PartialEq<&str> for $name {
            fn eq(&self, other: &&str) -> bool {
                self.as_str() == *other
            }
        }

        impl $crate::__private::serde::Serialize for $name {
            fn serialize<S: $crate::__private::serde::Serializer>(
                &self,
                serializer: S,
            ) -> ::core::result::Result<S::Ok, S::Error> {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> $crate::__private::serde::Deserialize<'de> for $name {
            fn deserialize<D: $crate::__private::serde::Deserializer<'de>>(
                deserializer: D,
            ) -> ::core::result::Result<Self, D::Error> {
                let s = <::std::string::String as $crate::__private::serde::Deserialize>::deserialize(deserializer)?;
                Ok(Self::from(s))
            }
        }
    };
}
