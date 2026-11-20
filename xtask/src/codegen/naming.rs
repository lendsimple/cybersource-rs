//! Turning spec names into Rust identifiers.

use heck::{ToSnakeCase, ToUpperCamelCase};

/// Rust keywords (strict and reserved) that need escaping as identifiers.
const KEYWORDS: &[&str] = &[
    "abstract", "as", "async", "await", "become", "box", "break", "const", "continue", "crate",
    "do", "dyn", "else", "enum", "extern", "false", "final", "fn", "for", "gen", "if", "impl",
    "in", "let", "loop", "macro", "match", "mod", "move", "mut", "override", "priv", "pub", "ref",
    "return", "static", "struct", "super", "trait", "true", "try", "type", "typeof", "unsafe",
    "unsized", "use", "virtual", "where", "while", "yield",
];

/// Keywords that cannot be raw identifiers.
const NOT_RAW: &[&str] = &["self", "Self", "super", "crate"];

/// A type name: `ptsV2PaymentsPost201Response` -> `PtsV2PaymentsPost201Response`.
pub fn type_name(raw: &str) -> String {
    let name = raw.to_upper_camel_case();
    if name.starts_with(|c: char| c.is_ascii_digit()) {
        format!("N{name}")
    } else {
        name
    }
}

/// A field or function name: `submitTimeUtc` -> `submit_time_utc`,
/// `type` -> `r#type`, `self` -> `self_`, `_links` -> `links`.
pub fn field_name(raw: &str) -> String {
    let mut name = raw.to_snake_case();
    if name.is_empty() {
        name = "field".into();
    }
    if name.starts_with(|c: char| c.is_ascii_digit()) {
        name = format!("n_{name}");
    }
    escape_keyword(name)
}

/// Escapes a snake_case identifier that is a keyword.
pub fn escape_keyword(name: String) -> String {
    if NOT_RAW.contains(&name.as_str()) {
        format!("{name}_")
    } else if KEYWORDS.contains(&name.as_str()) {
        format!("r#{name}")
    } else {
        name
    }
}

/// Whether `s` is a valid Rust identifier once any `r#` prefix is removed.
pub fn is_ident(s: &str) -> bool {
    let s = s.strip_prefix("r#").unwrap_or(s);
    let mut chars = s.chars();
    matches!(chars.next(), Some(c) if c == '_' || c.is_ascii_alphabetic())
        && chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_names_are_upper_camel() {
        assert_eq!(
            type_name("ptsV2PaymentsPost201Response"),
            "PtsV2PaymentsPost201Response"
        );
        assert_eq!(
            type_name("Ptsv2paymentsClientReferenceInformation"),
            "Ptsv2paymentsClientReferenceInformation"
        );
        assert_eq!(type_name("createPaymentRequest"), "CreatePaymentRequest");
        assert_eq!(
            type_name("defaultShippingAddress"),
            type_name("DefaultShippingAddress")
        );
    }

    #[test]
    fn field_names_are_snake_and_escaped() {
        assert_eq!(field_name("submitTimeUtc"), "submit_time_utc");
        assert_eq!(field_name("type"), "r#type");
        assert_eq!(field_name("use"), "r#use");
        assert_eq!(field_name("self"), "self_");
        assert_eq!(field_name("_links"), "links");
        assert_eq!(field_name("Application.Name"), "application_name");
        assert_eq!(field_name("RISK_INSIGHTS"), "risk_insights");
        assert_eq!(field_name("SECCode"), "sec_code");
        assert_eq!(field_name("3ds"), "n_3ds");
    }

    #[test]
    fn identifiers_are_validated() {
        assert!(is_ident("r#type"));
        assert!(is_ident("submit_time_utc"));
        assert!(!is_ident("a.b"));
        assert!(!is_ident("1a"));
    }
}
