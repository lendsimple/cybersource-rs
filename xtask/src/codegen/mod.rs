//! `cargo xtask codegen`: generates models and operations from the spec.

// The emitters that read the rest of the IR land in the next commit.
#![allow(dead_code)]

pub mod config;
pub mod docs;
pub mod ir;
pub mod naming;

use std::fs;

use crate::{Result, spec_source, workspace_root};

/// Loads the vendored spec and settings and builds the IR, reporting every
/// problem at once.
pub fn load() -> Result<ir::Ir> {
    let bytes = spec_source::verify()?;
    let spec: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| format!("spec is not JSON: {e}"))?;
    let config_text = fs::read_to_string(workspace_root().join("spec/codegen.toml"))
        .map_err(|e| format!("reading spec/codegen.toml: {e}"))?;
    let config = config::Config::parse(&config_text)?;
    ir::build(&spec, &config).map_err(|errors| {
        format!(
            "codegen found {} problem(s) in the spec:\n\n- {}",
            errors.len(),
            errors.join("\n- ")
        )
    })
}

/// `cargo xtask codegen --report`: prints what would be generated.
pub fn report() -> Result {
    let ir = load()?;
    let mut by_group = std::collections::BTreeMap::<&str, usize>::new();
    for op in &ir.operations {
        *by_group.entry(&op.group).or_default() += 1;
    }
    println!(
        "{} operations, {} models",
        ir.operations.len(),
        ir.models.len()
    );
    for (group, n) in by_group {
        let models = ir
            .models
            .values()
            .filter(|m| m.groups.contains(group))
            .count();
        println!("  {group:<24} {n:>3} ops  {models:>5} models");
    }
    let fields: usize = ir.models.values().map(|m| m.fields.len()).sum();
    println!("{fields} fields");
    Ok(())
}
