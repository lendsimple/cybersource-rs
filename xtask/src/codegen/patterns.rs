//! The spec's `pattern`s, made into regexes the `regex` crate accepts.
//!
//! The spec's patterns are written for Java and JavaScript. Two mechanical
//! repairs are made here: `/.../` delimiters are stripped and HTML entities
//! are unescaped. Anything else that does not compile needs an entry under
//! `[patterns]` in `spec/codegen.toml`, or codegen fails.

use std::collections::BTreeMap;

use super::config::PatternOverride;
use super::ir::Ir;

/// How a value is checked against a pattern.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Rule {
    /// The value must match this regex...
    pub regex: Option<String>,
    /// ...and none of these (what a negative lookahead excluded).
    pub reject: Vec<String>,
}

/// Every pattern used by a request model, resolved.
#[derive(Debug, Default)]
pub struct Patterns {
    /// Spec pattern -> its index and rule. Skipped patterns are absent.
    pub rules: BTreeMap<String, (usize, Rule)>,
}

impl Patterns {
    /// The index and rule for a spec pattern, unless it is skipped.
    pub fn get(&self, pattern: &str) -> Option<&(usize, Rule)> {
        self.rules.get(pattern)
    }
}

/// Resolves the patterns of every request model, reporting every pattern
/// that cannot be used.
pub fn resolve(
    ir: &Ir,
    overrides: &BTreeMap<String, PatternOverride>,
) -> Result<Patterns, Vec<String>> {
    let mut errors = Vec::new();
    let mut patterns = Patterns::default();
    let mut seen = std::collections::BTreeSet::new();
    for name in ir.request_models() {
        for field in &ir.models[&name].fields {
            let Some(raw) = &field.constraints.pattern else {
                continue;
            };
            if !seen.insert(raw.clone()) {
                continue;
            }
            match rule(raw, overrides.get(raw)) {
                Ok(Some(rule)) => {
                    let index = patterns.rules.len();
                    patterns.rules.insert(raw.clone(), (index, rule));
                }
                Ok(None) => {}
                Err(e) => {
                    let msg = format!(
                        "pattern {raw:?} (on {name}.{}) {e}; add it under [patterns] in codegen.toml",
                        field.json_name
                    );
                    errors.push(msg);
                }
            }
        }
    }
    for unused in overrides.keys().filter(|k| !seen.contains(*k)) {
        errors.push(format!(
            "[patterns] in codegen.toml has {unused:?}, which no request field uses; remove it"
        ));
    }
    // Indexes follow first use, which depends on model order; renumber by
    // pattern so the generated statics are stable.
    for (index, entry) in patterns.rules.values_mut().enumerate() {
        entry.0 = index;
    }
    if errors.is_empty() {
        Ok(patterns)
    } else {
        Err(errors)
    }
}

/// `None` when the pattern is skipped.
fn rule(raw: &str, over: Option<&PatternOverride>) -> Result<Option<Rule>, String> {
    let rule = match over {
        None => Rule {
            regex: Some(repair(raw)),
            reject: Vec::new(),
        },
        Some(PatternOverride {
            skip: Some(_),
            regex: None,
            reject: None,
        }) => return Ok(None),
        Some(PatternOverride {
            skip: None,
            regex,
            reject,
        }) if regex.is_some() || reject.as_ref().is_some_and(|r| !r.is_empty()) => Rule {
            regex: regex.clone(),
            reject: reject.clone().unwrap_or_default(),
        },
        Some(_) => return Err("needs a regex and/or reject list, or skip alone".into()),
    };
    for r in rule.regex.iter().chain(&rule.reject) {
        regex::Regex::new(r).map_err(|e| {
            let first = e.to_string().lines().last().unwrap_or_default().to_owned();
            format!("does not compile: {first}")
        })?;
    }
    Ok(Some(rule))
}

/// The mechanical repairs: JavaScript `/.../` delimiters and HTML entities.
fn repair(raw: &str) -> String {
    let inner = raw
        .strip_prefix('/')
        .and_then(|r| r.strip_suffix('/'))
        .filter(|r| !r.is_empty())
        .unwrap_or(raw);
    inner
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&amp;", "&")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn over(regex: Option<&str>, reject: Option<&[&str]>, skip: Option<&str>) -> PatternOverride {
        PatternOverride {
            regex: regex.map(str::to_owned),
            reject: reject.map(|r| r.iter().map(|s| s.to_string()).collect()),
            skip: skip.map(str::to_owned),
        }
    }

    fn matching(regex: &str) -> Rule {
        Rule {
            regex: Some(regex.into()),
            reject: Vec::new(),
        }
    }

    #[test]
    fn plain_patterns_are_kept() {
        assert_eq!(
            rule("^[0-9]{3,4}$", None),
            Ok(Some(matching("^[0-9]{3,4}$")))
        );
    }

    #[test]
    fn javascript_delimiters_are_stripped() {
        assert_eq!(
            rule(r"/^\d{0,8}(\.\d{0,2})?$/", None),
            Ok(Some(matching(r"^\d{0,8}(\.\d{0,2})?$")))
        );
    }

    #[test]
    fn html_entities_are_unescaped() {
        assert_eq!(repair("^[a-z&amp;&lt;]+$"), "^[a-z&<]+$");
    }

    #[test]
    fn lookarounds_need_an_override() {
        let raw = r"(?!^[*.,'#_/-]+$)(?!.*\./.*)^.*$";
        assert!(rule(raw, None).unwrap_err().starts_with("does not compile"));
        let reject: &[&str] = &[r"^[*.,'#_/-]+$", r"^.*\./"];
        assert_eq!(
            rule(raw, Some(&over(Some("^.*$"), Some(reject), None))),
            Ok(Some(Rule {
                regex: Some("^.*$".into()),
                reject: vec![r"^[*.,'#_/-]+$".into(), r"^.*\./".into()],
            }))
        );
    }

    #[test]
    fn reject_alone_is_enough() {
        let reject: &[&str] = &["^0+$"];
        assert_eq!(
            rule("x", Some(&over(None, Some(reject), None))),
            Ok(Some(Rule {
                regex: None,
                reject: vec!["^0+$".into()],
            }))
        );
    }

    #[test]
    fn skipped_patterns_resolve_to_none() {
        let skip = over(None, None, Some("a format, not a regex"));
        assert_eq!(rule("YYYY-MM-DDThh:mm:ssZ", Some(&skip)), Ok(None));
    }

    #[test]
    fn skip_cannot_be_combined() {
        let both = over(Some("a"), None, Some("why"));
        assert!(rule("x", Some(&both)).is_err());
        assert!(rule("x", Some(&over(None, None, None))).is_err());
    }

    #[test]
    fn overrides_must_compile() {
        assert!(rule("x", Some(&over(Some("(unclosed"), None, None))).is_err());
    }
}
