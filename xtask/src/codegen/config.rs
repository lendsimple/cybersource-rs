//! `spec/codegen.toml`: decisions the spec cannot make for us.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Feature group name -> spec tags.
    pub groups: BTreeMap<String, Vec<String>>,
    /// "METHOD /path" -> reason.
    #[serde(default)]
    pub skip_operations: BTreeMap<String, String>,
    /// "METHOD /path" -> operation id.
    #[serde(default)]
    pub operation_ids: BTreeMap<String, String>,
    /// "METHOD /path" entries that move money.
    #[serde(default)]
    pub money_movement: BTreeSet<String>,
    /// Lowercase header names the pipeline sets.
    #[serde(default)]
    pub pipeline_headers: BTreeSet<String>,
    /// "<Name>@<json pointer>" -> new name.
    #[serde(default)]
    pub model_renames: BTreeMap<String, String>,
    #[serde(default)]
    pub sensitive: Sensitive,
    /// Example ids allowed to fail the round-trip test -> reason.
    #[serde(default)]
    pub example_allowlist: BTreeMap<String, String>,
    /// Operation id -> how to read a page of its response.
    #[serde(default)]
    pub pagination: BTreeMap<String, PageSpec>,
}

/// Response fields (JSON names) that describe one page of a list.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageSpec {
    /// Integer field with the total number of items.
    pub total: String,
    /// Integer field with the number of items in this page...
    pub count: Option<String>,
    /// ...or the array field holding them.
    pub items: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sensitive {
    #[serde(default)]
    pub always: BTreeSet<String>,
    #[serde(default)]
    pub number_in_types_containing: Vec<String>,
}

impl Config {
    pub fn parse(text: &str) -> Result<Self, String> {
        toml::from_str(text).map_err(|e| format!("spec/codegen.toml: {e}"))
    }

    /// The feature group for a tag.
    pub fn group_of(&self, tag: &str) -> Option<&str> {
        self.groups
            .iter()
            .find(|(_, tags)| tags.iter().any(|t| t == tag))
            .map(|(group, _)| group.as_str())
    }

    /// Whether a JSON property on a type should be redacted in `Debug`.
    pub fn is_sensitive(&self, type_name: &str, json_name: &str) -> bool {
        self.sensitive.always.contains(json_name)
            || (json_name == "number"
                && self
                    .sensitive
                    .number_in_types_containing
                    .iter()
                    .any(|t| type_name.contains(t.as_str())))
    }
}
