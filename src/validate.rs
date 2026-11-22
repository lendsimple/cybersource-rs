//! Checks of the spec's constraints on request bodies: required fields,
//! string lengths, patterns, numeric ranges and list sizes.
//!
//! Every generated request model implements [`Validate`]. The client
//! validates request bodies before sending them (see
//! [`Config::validate_requests`](crate::Config::validate_requests)), so a
//! value Cybersource would reject with a terse `INVALID_DATA` is reported
//! with the path of the offending field instead, and never leaves the
//! process.

use std::collections::BTreeMap;
use std::fmt;

/// A type whose values can be checked against the spec's constraints.
pub trait Validate {
    /// Checks `self` and everything inside it, collecting every violation.
    fn validate(&self) -> Result<(), ValidationError> {
        let mut path = Path::default();
        let mut violations = Vec::new();
        self.validate_into(&mut path, &mut violations);
        if violations.is_empty() {
            Ok(())
        } else {
            Err(ValidationError { violations })
        }
    }

    #[doc(hidden)]
    fn validate_into(&self, path: &mut Path, out: &mut Vec<Violation>);
}

/// One value that breaks a constraint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    /// Where the value is, by JSON names: `orderInformation.lineItems[0].productSku`.
    pub path: String,
    /// What is wrong with it.
    pub message: String,
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.path, self.message)
    }
}

/// A request body does not satisfy the spec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError {
    violations: Vec<Violation>,
}

impl ValidationError {
    /// Every violation found, in field order. Never empty.
    pub fn violations(&self) -> &[Violation] {
        &self.violations
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (first, rest) = self.violations.split_first().expect("never empty");
        write!(f, "{first}")?;
        match rest.len() {
            0 => Ok(()),
            1 => write!(f, " (and 1 more violation)"),
            n => write!(f, " (and {n} more violations)"),
        }
    }
}

impl std::error::Error for ValidationError {}

/// The location being validated, maintained by generated code.
#[doc(hidden)]
#[derive(Debug, Default)]
pub struct Path {
    segments: Vec<Segment>,
}

#[derive(Debug)]
enum Segment {
    Field(&'static str),
    Index(usize),
    Key(String),
}

impl Path {
    pub fn push_field(&mut self, name: &'static str) {
        self.segments.push(Segment::Field(name));
    }

    pub fn push_index(&mut self, index: usize) {
        self.segments.push(Segment::Index(index));
    }

    pub fn push_key(&mut self, key: &str) {
        self.segments.push(Segment::Key(key.to_owned()));
    }

    pub fn pop(&mut self) {
        self.segments.pop();
    }

    fn render(&self) -> String {
        let mut out = String::new();
        for segment in &self.segments {
            match segment {
                Segment::Field(name) => {
                    if !out.is_empty() {
                        out.push('.');
                    }
                    out.push_str(name);
                }
                Segment::Index(i) => out.push_str(&format!("[{i}]")),
                Segment::Key(k) => out.push_str(&format!("[{k:?}]")),
            }
        }
        out
    }
}

fn violation(path: &Path, out: &mut Vec<Violation>, message: String) {
    out.push(Violation {
        path: path.render(),
        message,
    });
}

/// Types with no constraints of their own.
macro_rules! no_constraints {
    ($($ty:ty),*) => {$(
        impl Validate for $ty {
            fn validate_into(&self, _path: &mut Path, _out: &mut Vec<Violation>) {}
        }
    )*};
}

no_constraints!(String, bool, i32, i64, f64, serde_json::Value);

impl<T: Validate> Validate for Vec<T> {
    fn validate_into(&self, path: &mut Path, out: &mut Vec<Violation>) {
        for (i, item) in self.iter().enumerate() {
            path.push_index(i);
            item.validate_into(path, out);
            path.pop();
        }
    }
}

impl<T: Validate> Validate for BTreeMap<String, T> {
    fn validate_into(&self, path: &mut Path, out: &mut Vec<Violation>) {
        for (key, value) in self {
            path.push_key(key);
            value.validate_into(path, out);
            path.pop();
        }
    }
}

// Constraint checks called by generated code. Lengths count characters, as
// JSON Schema does.

#[doc(hidden)]
pub fn check_required(present: bool, path: &Path, out: &mut Vec<Violation>) {
    if !present {
        violation(path, out, "is required".into());
    }
}

#[doc(hidden)]
pub fn check_length(
    value: &str,
    min: Option<usize>,
    max: Option<usize>,
    path: &Path,
    out: &mut Vec<Violation>,
) {
    let len = value.chars().count();
    if let Some(min) = min
        && len < min
    {
        violation(
            path,
            out,
            format!("must be at least {min} characters, not {len}"),
        );
    }
    if let Some(max) = max
        && len > max
    {
        violation(
            path,
            out,
            format!("must be at most {max} characters, not {len}"),
        );
    }
}

/// `matches` is the generated matcher for `pattern`, the spec's pattern as
/// shown to the user.
#[doc(hidden)]
pub fn check_pattern(
    value: &str,
    pattern: &'static str,
    matches: fn(&str) -> bool,
    path: &Path,
    out: &mut Vec<Violation>,
) {
    if !matches(value) {
        violation(path, out, format!("must match the pattern {pattern}"));
    }
}

#[doc(hidden)]
pub fn check_range<T>(
    value: T,
    min: Option<T>,
    max: Option<T>,
    path: &Path,
    out: &mut Vec<Violation>,
) where
    T: PartialOrd + fmt::Display + Copy,
{
    if let Some(min) = min
        && value < min
    {
        violation(path, out, format!("must be at least {min}, not {value}"));
    }
    if let Some(max) = max
        && value > max
    {
        violation(path, out, format!("must be at most {max}, not {value}"));
    }
}

#[doc(hidden)]
pub fn check_items(
    len: usize,
    min: Option<usize>,
    max: Option<usize>,
    path: &Path,
    out: &mut Vec<Violation>,
) {
    if let Some(min) = min
        && len < min
    {
        violation(
            path,
            out,
            format!("must have at least {min} items, not {len}"),
        );
    }
    if let Some(max) = max
        && len > max
    {
        violation(
            path,
            out,
            format!("must have at most {max} items, not {len}"),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(check: impl FnOnce(&Path, &mut Vec<Violation>)) -> Vec<String> {
        let mut path = Path::default();
        path.push_field("orderInformation");
        path.push_field("lineItems");
        path.push_index(2);
        path.push_field("productSku");
        let mut out = Vec::new();
        check(&path, &mut out);
        out.into_iter().map(|v| v.to_string()).collect()
    }

    #[test]
    fn path_renders_fields_and_indexes() {
        let out = run(|p, o| check_length("abc", None, Some(2), p, o));
        assert_eq!(
            out,
            ["orderInformation.lineItems[2].productSku: must be at most 2 characters, not 3"]
        );
    }

    #[test]
    fn path_renders_map_keys() {
        let mut path = Path::default();
        path.push_field("metadata");
        path.push_key("a.b");
        assert_eq!(path.render(), r#"metadata["a.b"]"#);
    }

    #[test]
    fn length_counts_characters_not_bytes() {
        assert!(run(|p, o| check_length("ééé", None, Some(3), p, o)).is_empty());
    }

    #[test]
    fn min_length() {
        assert_eq!(
            run(|p, o| check_length("", Some(1), None, p, o)),
            ["orderInformation.lineItems[2].productSku: must be at least 1 characters, not 0"]
        );
    }

    #[test]
    fn required() {
        assert!(run(|p, o| check_required(true, p, o)).is_empty());
        assert_eq!(
            run(|p, o| check_required(false, p, o)),
            ["orderInformation.lineItems[2].productSku: is required"]
        );
    }

    #[test]
    fn pattern_uses_the_matcher() {
        let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
        assert!(run(|p, o| check_pattern("123", "^[0-9]+$", digits, p, o)).is_empty());
        assert_eq!(
            run(|p, o| check_pattern("12a", "^[0-9]+$", digits, p, o)),
            ["orderInformation.lineItems[2].productSku: must match the pattern ^[0-9]+$"]
        );
    }

    #[test]
    fn integer_range() {
        assert_eq!(
            run(|p, o| check_range(1001, Some(1), Some(1000), p, o)),
            ["orderInformation.lineItems[2].productSku: must be at most 1000, not 1001"]
        );
        assert!(run(|p, o| check_range(1, Some(1), Some(1000), p, o)).is_empty());
    }

    #[test]
    fn float_range() {
        assert_eq!(
            run(|p, o| check_range(-0.5, Some(0.0), None, p, o)).len(),
            1
        );
    }

    #[test]
    fn item_counts() {
        assert_eq!(run(|p, o| check_items(31, None, Some(30), p, o)).len(), 1);
        assert_eq!(run(|p, o| check_items(0, Some(1), None, p, o)).len(), 1);
    }

    #[test]
    fn lists_and_maps_recurse_with_their_position() {
        struct Sku(&'static str);
        impl Validate for Sku {
            fn validate_into(&self, path: &mut Path, out: &mut Vec<Violation>) {
                check_length(self.0, None, Some(3), path, out);
            }
        }
        let err = vec![Sku("ok"), Sku("toolong")].validate().unwrap_err();
        assert_eq!(err.to_string(), "[1]: must be at most 3 characters, not 7");

        let map = BTreeMap::from([("k".to_owned(), Sku("toolong"))]);
        assert_eq!(map.validate().unwrap_err().violations()[0].path, r#"["k"]"#);
    }

    #[test]
    fn error_display_counts_the_rest() {
        let v = |path: &str| Violation {
            path: path.into(),
            message: "bad".into(),
        };
        let err = ValidationError {
            violations: vec![v("a"), v("b"), v("c")],
        };
        assert_eq!(err.to_string(), "a: bad (and 2 more violations)");
    }
}
