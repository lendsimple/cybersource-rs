//! Round-trip checking for spec examples (used by the generated
//! `tests/spec_examples.rs`).

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

const DATA: &str = include_str!("examples.json");

pub type Check = fn(&Value, &[String]) -> Result<(), String>;

/// Deserializes `value` as `T`, serializes it back, and reports any field
/// that was dropped or changed, except at `ignore` paths (where the example
/// disagrees with its own schema; computed by the generator). Scalars
/// compare by their text, so lenient conversions (`100` read into a string
/// field) pass.
pub fn check<T: DeserializeOwned + Serialize>(
    value: &Value,
    ignore: &[String],
) -> Result<(), String> {
    let typed: T =
        serde_json::from_value(value.clone()).map_err(|e| format!("deserialize: {e}"))?;
    let back = serde_json::to_value(&typed).map_err(|e| format!("serialize: {e}"))?;
    let mut diffs = Vec::new();
    compare("$", value, &back, ignore, &mut diffs);
    if diffs.is_empty() {
        Ok(())
    } else {
        Err(diffs.join("; "))
    }
}

fn compare(path: &str, original: &Value, back: &Value, ignore: &[String], diffs: &mut Vec<String>) {
    if ignore.iter().any(|i| i == path) {
        return;
    }
    match (original, back) {
        (Value::Null, _) => {}
        (Value::Object(a), Value::Object(b)) => {
            for (key, va) in a {
                if va.is_null() {
                    continue;
                }
                let path = format!("{path}.{key}");
                match b.get(key) {
                    Some(vb) => compare(&path, va, vb, ignore, diffs),
                    None if ignore.contains(&path) => {}
                    None => diffs.push(format!("{path} dropped")),
                }
            }
        }
        (Value::Array(a), Value::Array(b)) if a.len() == b.len() => {
            for (i, (va, vb)) in a.iter().zip(b).enumerate() {
                compare(&format!("{path}[{i}]"), va, vb, ignore, diffs);
            }
        }
        (a, b) if scalar_eq(a, b) => {}
        (a, b) => diffs.push(format!("{path}: {a} became {b}")),
    }
}

fn scalar_eq(a: &Value, b: &Value) -> bool {
    fn text(v: &Value) -> Option<String> {
        match v {
            Value::String(s) => Some(s.clone()),
            Value::Number(n) => Some(n.to_string()),
            Value::Bool(b) => Some(b.to_string()),
            _ => None,
        }
    }
    match (text(a), text(b)) {
        (Some(x), Some(y)) if x == y => true,
        (Some(x), Some(y)) => matches!(
            (x.trim().parse::<f64>(), y.trim().parse::<f64>()),
            (Ok(p), Ok(q)) if p == q
        ),
        _ => false,
    }
}

/// Runs every case, failing with all problems not on the allowlist.
pub fn run(cases: &[(&str, Check)]) {
    let data: Value = serde_json::from_str(DATA).expect("examples.json");
    let mut failures = Vec::new();
    for (id, check) in cases {
        let case = &data["examples"][*id];
        if case["skip"].is_string() {
            continue; // the example contradicts its own schema
        }
        let ignore: Vec<String> =
            serde_json::from_value(case["ignore"].clone()).unwrap_or_default();
        let allowed = data["allowlist"].get(*id).is_some();
        match (check(&case["value"], &ignore), allowed) {
            (Ok(()), false) => {}
            (Ok(()), true) => failures.push(format!(
                "{id}: passes now; remove it from [example_allowlist] in spec/codegen.toml"
            )),
            (Err(e), false) => failures.push(format!("{id}: {e}")),
            (Err(_), true) => {}
        }
    }
    assert!(
        failures.is_empty(),
        "{} example(s) failed:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
}
