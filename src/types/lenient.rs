//! Lenient deserializers for generated model fields.
//!
//! Cybersource sometimes sends a JSON type other than the one its spec
//! declares (a number where a string is documented, `"true"` for a bool).
//! The official C# SDK added converters for exactly this. These accept the
//! declared type plus the obvious alternatives, so one odd field never fails
//! a whole response. Use with `#[serde(default, deserialize_with = "...")]`
//! on `Option` fields.

use std::fmt;

use serde::Deserializer;
use serde::de::{self, Visitor};

macro_rules! lenient {
    ($(#[$doc:meta])* $name:ident -> $ty:ty, $visitor:ident { $($body:tt)* }) => {
        $(#[$doc])*
        pub fn $name<'de, D: Deserializer<'de>>(d: D) -> Result<Option<$ty>, D::Error> {
            struct $visitor;
            impl<'de> Visitor<'de> for $visitor {
                type Value = Option<$ty>;
                fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.write_str(concat!("a value convertible to ", stringify!($ty)))
                }
                fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
                    Ok(None)
                }
                fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                    Ok(None)
                }
                fn visit_some<D2: Deserializer<'de>>(self, d: D2) -> Result<Self::Value, D2::Error> {
                    d.deserialize_any(self)
                }
                $($body)*
            }
            d.deserialize_option($visitor)
        }
    };
}

lenient!(
    /// A string, also accepting numbers and booleans (as their JSON text).
    string -> String, StringVisitor {
        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> { Ok(Some(v.to_owned())) }
        fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> { Ok(Some(v)) }
        fn visit_bool<E: de::Error>(self, v: bool) -> Result<Self::Value, E> { Ok(Some(v.to_string())) }
        fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> { Ok(Some(v.to_string())) }
        fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> { Ok(Some(v.to_string())) }
        fn visit_f64<E: de::Error>(self, v: f64) -> Result<Self::Value, E> { Ok(Some(v.to_string())) }
    }
);

lenient!(
    /// A 64-bit integer, also accepting integral floats and numeric strings
    /// (an empty string is `None`).
    i64 -> i64, I64Visitor {
        fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> { Ok(Some(v)) }
        fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
            i64::try_from(v).map(Some).map_err(|_| E::custom(format!("{v} does not fit in i64")))
        }
        fn visit_f64<E: de::Error>(self, v: f64) -> Result<Self::Value, E> {
            if v.fract() == 0.0 && v >= i64::MIN as f64 && v <= i64::MAX as f64 {
                Ok(Some(v as i64))
            } else {
                Err(E::custom(format!("{v} is not an integer")))
            }
        }
        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            let v = v.trim();
            if v.is_empty() { return Ok(None); }
            v.parse().map(Some).map_err(|_| E::custom(format!("{v:?} is not an integer")))
        }
    }
);

/// A 32-bit integer, with the same leniency as [`i64()`](fn@i64).
pub fn i32<'de, D: Deserializer<'de>>(d: D) -> Result<Option<i32>, D::Error> {
    match i64(d)? {
        None => Ok(None),
        Some(v) => i32::try_from(v)
            .map(Some)
            .map_err(|_| de::Error::custom(format!("{v} does not fit in i32"))),
    }
}

lenient!(
    /// A float, also accepting numeric strings (an empty string is `None`).
    f64 -> f64, F64Visitor {
        fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> { Ok(Some(v as f64)) }
        fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> { Ok(Some(v as f64)) }
        fn visit_f64<E: de::Error>(self, v: f64) -> Result<Self::Value, E> { Ok(Some(v)) }
        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            let v = v.trim();
            if v.is_empty() { return Ok(None); }
            v.parse().map(Some).map_err(|_| E::custom(format!("{v:?} is not a number")))
        }
    }
);

lenient!(
    /// A bool, also accepting `"true"`/`"false"` (any case), `"1"`/`"0"`,
    /// `"Y"`/`"N"` and the integers 1 and 0.
    bool -> bool, BoolVisitor {
        fn visit_bool<E: de::Error>(self, v: bool) -> Result<Self::Value, E> { Ok(Some(v)) }
        fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> { int_bool(v) }
        fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> { int_bool(v as i64) }
        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            match v.trim().to_ascii_lowercase().as_str() {
                "" => Ok(None),
                "true" | "1" | "y" | "yes" => Ok(Some(true)),
                "false" | "0" | "n" | "no" => Ok(Some(false)),
                _ => Err(E::custom(format!("{v:?} is not a boolean"))),
            }
        }
    }
);

fn int_bool<E: de::Error>(v: i64) -> Result<Option<bool>, E> {
    match v {
        0 => Ok(Some(false)),
        1 => Ok(Some(true)),
        _ => Err(E::custom(format!("{v} is not a boolean"))),
    }
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    #[derive(Debug, Default, Deserialize, PartialEq)]
    #[serde(default)]
    struct T {
        #[serde(deserialize_with = "super::string")]
        s: Option<String>,
        #[serde(deserialize_with = "super::i64")]
        l: Option<i64>,
        #[serde(deserialize_with = "super::i32")]
        i: Option<i32>,
        #[serde(deserialize_with = "super::f64")]
        f: Option<f64>,
        #[serde(deserialize_with = "super::bool")]
        b: Option<bool>,
    }

    fn parse(json: &str) -> T {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn declared_types_pass_through() {
        assert_eq!(
            parse(r#"{"s":"x","l":5,"i":6,"f":1.5,"b":true}"#),
            T {
                s: Some("x".into()),
                l: Some(5),
                i: Some(6),
                f: Some(1.5),
                b: Some(true)
            }
        );
    }

    #[test]
    fn missing_and_null_are_none() {
        assert_eq!(parse("{}"), T::default());
        assert_eq!(
            parse(r#"{"s":null,"l":null,"i":null,"f":null,"b":null}"#),
            T::default()
        );
    }

    #[test]
    fn alternative_types_are_converted() {
        assert_eq!(
            parse(r#"{"s":102.21,"l":"42","i":7.0,"f":"3.25","b":"TRUE"}"#),
            T {
                s: Some("102.21".into()),
                l: Some(42),
                i: Some(7),
                f: Some(3.25),
                b: Some(true)
            }
        );
        assert_eq!(parse(r#"{"s":true,"b":0}"#).s.as_deref(), Some("true"));
        assert_eq!(parse(r#"{"l":"","f":" "}"#), T::default());
    }

    #[test]
    fn nonsense_is_still_an_error() {
        assert!(serde_json::from_str::<T>(r#"{"l":"abc"}"#).is_err());
        assert!(serde_json::from_str::<T>(r#"{"i":3000000000}"#).is_err());
        assert!(serde_json::from_str::<T>(r#"{"b":"maybe"}"#).is_err());
        assert!(serde_json::from_str::<T>(r#"{"s":{"a":1}}"#).is_err());
    }
}
