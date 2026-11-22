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

/// A spec pattern and its generated matcher.
#[doc(hidden)]
#[derive(Debug)]
pub struct Pattern {
    /// The pattern as the spec writes it, for messages.
    pub text: &'static str,
    pub matches: fn(&str) -> bool,
}

#[doc(hidden)]
pub fn check_pattern(value: &str, pattern: &Pattern, path: &Path, out: &mut Vec<Violation>) {
    if !(pattern.matches)(value) {
        violation(
            path,
            out,
            format!("must match the pattern {}", pattern.text),
        );
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

// One call per constrained field, so the generated code stays small. Each
// takes the field's JSON name and whether the spec requires it.

/// A field that is only required.
#[doc(hidden)]
pub fn present<T>(
    path: &mut Path,
    out: &mut Vec<Violation>,
    name: &'static str,
    value: &Option<T>,
) {
    if value.is_none() {
        path.push_field(name);
        check_required(false, path, out);
        path.pop();
    }
}

/// A string field: length and pattern.
#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub fn string(
    path: &mut Path,
    out: &mut Vec<Violation>,
    name: &'static str,
    value: &Option<String>,
    required: bool,
    min: Option<usize>,
    max: Option<usize>,
    pattern: Option<&Pattern>,
) {
    path.push_field(name);
    match value {
        None => check_required(!required, path, out),
        Some(value) => text(value, min, max, pattern, path, out),
    }
    path.pop();
}

/// A list of strings: item count, and each item's length and pattern.
#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub fn strings(
    path: &mut Path,
    out: &mut Vec<Violation>,
    name: &'static str,
    value: &Option<Vec<String>>,
    required: bool,
    items: (Option<usize>, Option<usize>),
    min: Option<usize>,
    max: Option<usize>,
    pattern: Option<&Pattern>,
) {
    path.push_field(name);
    match value {
        None => check_required(!required, path, out),
        Some(values) => {
            check_items(values.len(), items.0, items.1, path, out);
            for (i, value) in values.iter().enumerate() {
                path.push_index(i);
                text(value, min, max, pattern, path, out);
                path.pop();
            }
        }
    }
    path.pop();
}

fn text(
    value: &str,
    min: Option<usize>,
    max: Option<usize>,
    pattern: Option<&Pattern>,
    path: &Path,
    out: &mut Vec<Violation>,
) {
    check_length(value, min, max, path, out);
    if let Some(pattern) = pattern {
        check_pattern(value, pattern, path, out);
    }
}

/// A numeric field: range.
#[doc(hidden)]
pub fn number<T>(
    path: &mut Path,
    out: &mut Vec<Violation>,
    name: &'static str,
    value: &Option<T>,
    required: bool,
    min: Option<T>,
    max: Option<T>,
) where
    T: PartialOrd + fmt::Display + Copy,
{
    path.push_field(name);
    match value {
        None => check_required(!required, path, out),
        Some(value) => check_range(*value, min, max, path, out),
    }
    path.pop();
}

/// A model (or map of models) with constraints inside it.
#[doc(hidden)]
pub fn nested<T: Validate>(
    path: &mut Path,
    out: &mut Vec<Violation>,
    name: &'static str,
    value: &Option<T>,
    required: bool,
) {
    path.push_field(name);
    match value {
        None => check_required(!required, path, out),
        Some(value) => value.validate_into(path, out),
    }
    path.pop();
}

/// A list: item count, and each item's own constraints.
#[doc(hidden)]
pub fn list<T: Validate>(
    path: &mut Path,
    out: &mut Vec<Violation>,
    name: &'static str,
    value: &Option<Vec<T>>,
    required: bool,
    items: (Option<usize>, Option<usize>),
) {
    path.push_field(name);
    match value {
        None => check_required(!required, path, out),
        Some(values) => {
            check_items(values.len(), items.0, items.1, path, out);
            values.validate_into(path, out);
        }
    }
    path.pop();
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

    static DIGITS: Pattern = Pattern {
        text: "^[0-9]+$",
        matches: |s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()),
    };

    #[test]
    fn pattern_uses_the_matcher() {
        assert!(run(|p, o| check_pattern("123", &DIGITS, p, o)).is_empty());
        assert_eq!(
            run(|p, o| check_pattern("12a", &DIGITS, p, o)),
            ["orderInformation.lineItems[2].productSku: must match the pattern ^[0-9]+$"]
        );
    }

    fn field(check: impl FnOnce(&mut Path, &mut Vec<Violation>)) -> Vec<String> {
        let mut path = Path::default();
        path.push_field("order");
        let mut out = Vec::new();
        check(&mut path, &mut out);
        out.into_iter().map(|v| v.to_string()).collect()
    }

    #[test]
    fn missing_fields_fail_only_when_required() {
        let none: Option<String> = None;
        assert!(field(|p, o| string(p, o, "code", &none, false, None, Some(3), None)).is_empty());
        assert_eq!(
            field(|p, o| string(p, o, "code", &none, true, None, Some(3), None)),
            ["order.code: is required"]
        );
        assert_eq!(
            field(|p, o| present(p, o, "id", &None::<bool>)),
            ["order.id: is required"]
        );
        assert!(field(|p, o| present(p, o, "id", &Some(true))).is_empty());
    }

    #[test]
    fn string_fields_check_length_and_pattern() {
        let value = Some("12a4".to_owned());
        assert_eq!(
            field(|p, o| string(p, o, "code", &value, false, None, Some(3), Some(&DIGITS))),
            [
                "order.code: must be at most 3 characters, not 4",
                "order.code: must match the pattern ^[0-9]+$",
            ]
        );
    }

    #[test]
    fn string_lists_check_count_and_each_item() {
        let value = Some(vec!["1".to_owned(), "x".to_owned()]);
        assert_eq!(
            field(|p, o| strings(
                p,
                o,
                "skus",
                &value,
                false,
                (None, Some(1)),
                None,
                None,
                Some(&DIGITS)
            )),
            [
                "order.skus: must have at most 1 items, not 2",
                "order.skus[1]: must match the pattern ^[0-9]+$",
            ]
        );
    }

    #[test]
    fn number_fields_check_range() {
        assert_eq!(
            field(|p, o| number(p, o, "qty", &Some(0), false, Some(1), None)),
            ["order.qty: must be at least 1, not 0"]
        );
    }

    #[test]
    fn nested_and_list_fields_recurse() {
        struct Code(&'static str);
        impl Validate for Code {
            fn validate_into(&self, path: &mut Path, out: &mut Vec<Violation>) {
                string(
                    path,
                    out,
                    "code",
                    &Some(self.0.to_owned()),
                    false,
                    None,
                    Some(2),
                    None,
                );
            }
        }
        assert_eq!(
            field(|p, o| nested(p, o, "ref", &Some(Code("abc")), false)),
            ["order.ref.code: must be at most 2 characters, not 3"]
        );
        assert_eq!(
            field(|p, o| list(
                p,
                o,
                "refs",
                &Some(vec![Code("a"), Code("abc")]),
                true,
                (None, None)
            )),
            ["order.refs[1].code: must be at most 2 characters, not 3"]
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
