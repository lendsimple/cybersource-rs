//! `cargo xtask codegen`: generates models and operations from the spec.

pub mod config;
pub mod docs;
pub mod emit;
pub mod examples;
pub mod ir;
pub mod naming;

use std::fs;
use std::path::Path;
use std::process::Command;

use crate::{Result, run, spec_source, workspace_root};

/// Loads the vendored spec and settings and builds the IR, reporting every
/// problem at once.
pub fn load() -> Result<(ir::Ir, config::Config)> {
    let bytes = spec_source::verify()?;
    let spec: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| format!("spec is not JSON: {e}"))?;
    let config_text = fs::read_to_string(workspace_root().join("spec/codegen.toml"))
        .map_err(|e| format!("reading spec/codegen.toml: {e}"))?;
    let config = config::Config::parse(&config_text)?;
    let ir = ir::build(&spec, &config).map_err(problems)?;
    let errors = emit::validate(&ir);
    if !errors.is_empty() {
        return Err(problems(errors));
    }
    check_features(&ir)?;
    Ok((ir, config))
}

fn problems(errors: Vec<String>) -> String {
    format!(
        "codegen found {} problem(s) in the spec:\n\n- {}",
        errors.len(),
        errors.join("\n- ")
    )
}

/// Every feature group must exist in Cargo.toml (implying `server`) and be in `full`.
fn check_features(ir: &ir::Ir) -> Result {
    let manifest: toml::Table = fs::read_to_string(workspace_root().join("Cargo.toml"))
        .map_err(|e| e.to_string())?
        .parse()
        .map_err(|e| format!("Cargo.toml: {e}"))?;
    let features = manifest
        .get("features")
        .and_then(|f| f.as_table())
        .ok_or("Cargo.toml has no [features]")?;
    let list = |name: &str| -> Vec<String> {
        features
            .get(name)
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    };
    let full = list("full");
    let mut errors = Vec::new();
    let groups: std::collections::BTreeSet<_> =
        ir.operations.iter().map(|o| o.group.as_str()).collect();
    for group in groups {
        if !list(group).iter().any(|d| d == "server") {
            errors.push(format!(
                "Cargo.toml needs `{group} = [\"server\"]` under [features]"
            ));
        }
        if !full.iter().any(|d| d == group) {
            errors.push(format!("Cargo.toml feature `full` must include `{group}`"));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(problems(errors))
    }
}

/// Writes the generated files into `dir` (replacing it) and formats them.
pub fn write(dir: &Path, tests_dir: &Path) -> Result {
    let (ir, config) = load()?;
    let files = emit::generate(&ir);
    if dir.exists() {
        fs::remove_dir_all(dir).map_err(|e| format!("clearing {}: {e}", dir.display()))?;
    }
    let mut paths = Vec::new();
    for (rel, contents) in files {
        let path = dir.join(rel);
        fs::create_dir_all(path.parent().unwrap()).map_err(|e| e.to_string())?;
        fs::write(&path, contents).map_err(|e| e.to_string())?;
        paths.push(path);
    }

    let (test_rs, examples_json) = examples::generate(&ir, &config.example_allowlist);
    let test_path = tests_dir.join("spec_examples.rs");
    fs::create_dir_all(tests_dir.join("spec_examples")).map_err(|e| e.to_string())?;
    fs::write(&test_path, test_rs).map_err(|e| e.to_string())?;
    fs::write(tests_dir.join("spec_examples/examples.json"), examples_json)
        .map_err(|e| e.to_string())?;
    paths.push(test_path);

    run(Command::new("rustfmt")
        .args(["--edition", "2024"])
        .args(&paths))?;
    println!("generated {} files", paths.len());
    Ok(())
}

/// `cargo xtask codegen`: regenerates `src/generated`.
pub fn codegen() -> Result {
    let root = workspace_root();
    write(&root.join("src/generated"), &root.join("tests"))
}

/// `cargo xtask codegen --report`: prints what would be generated.
pub fn report() -> Result {
    let (ir, _) = load()?;
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
