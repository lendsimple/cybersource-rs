//! `cargo xtask codegen`: generates models and operations from the spec.

pub mod config;
pub mod docs;
pub mod emit;
pub mod examples;
pub mod ir;
pub mod naming;
pub mod patterns;

use std::fs;
use std::path::Path;
use std::process::Command;

use crate::{Result, spec_source, workspace_root};

/// Loads the vendored spec and settings and builds the IR, reporting every
/// problem at once.
pub fn load() -> Result<(ir::Ir, config::Config, patterns::Patterns)> {
    let bytes = spec_source::verify()?;
    let spec: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| format!("spec is not JSON: {e}"))?;
    let config_text = fs::read_to_string(workspace_root().join("spec/codegen.toml"))
        .map_err(|e| format!("reading spec/codegen.toml: {e}"))?;
    let config = config::Config::parse(&config_text)?;
    let mut ir = ir::build(&spec, &config).map_err(problems)?;
    ir.relax(&config.relax).map_err(problems)?;
    let errors = emit::validate(&ir);
    if !errors.is_empty() {
        return Err(problems(errors));
    }
    check_features(&ir)?;
    let patterns = patterns::resolve(&ir, &config.patterns).map_err(problems)?;
    Ok((ir, config, patterns))
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

/// Formats Rust source with rustfmt via stdin (so `#[path]` modules are
/// not followed and the result does not depend on where it is written).
fn rustfmt(source: &str) -> Result<String> {
    use std::io::Write as _;
    use std::process::Stdio;
    let mut child = Command::new("rustfmt")
        .args(["--edition", "2024", "--emit", "stdout"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("running rustfmt: {e}"))?;
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(source.as_bytes())
        .map_err(|e| e.to_string())?;
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(format!(
            "rustfmt failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    String::from_utf8(out.stdout).map_err(|e| e.to_string())
}

/// Writes the generated files into `dir` (replacing it), plus the example
/// corpus into `tests_dir`, all rustfmt-formatted.
pub fn write(dir: &Path, tests_dir: &Path) -> Result {
    let (ir, config, patterns) = load()?;
    let mut files: Vec<(std::path::PathBuf, String)> =
        emit::generate(&ir, &config.sensitive, &patterns)
            .into_iter()
            .map(|(rel, contents)| (dir.join(rel), contents))
            .collect();
    let (test_rs, examples_json) = examples::generate(&ir, &config.example_allowlist);
    files.push((tests_dir.join("spec_examples.rs"), test_rs));

    if dir.exists() {
        fs::remove_dir_all(dir).map_err(|e| format!("clearing {}: {e}", dir.display()))?;
    }
    for (path, contents) in &files {
        fs::create_dir_all(path.parent().unwrap()).map_err(|e| e.to_string())?;
        fs::write(path, rustfmt(contents)?).map_err(|e| e.to_string())?;
    }
    fs::create_dir_all(tests_dir.join("spec_examples")).map_err(|e| e.to_string())?;
    fs::write(tests_dir.join("spec_examples/examples.json"), examples_json)
        .map_err(|e| e.to_string())?;
    println!("generated {} files", files.len() + 1);
    Ok(())
}

/// `cargo xtask codegen`: regenerates `src/generated`.
pub fn codegen() -> Result {
    let root = workspace_root();
    write(&root.join("src/generated"), &root.join("tests"))
}

/// `cargo xtask check-codegen`: fails if the checked-in generated code
/// differs from what the generator produces now.
pub fn check() -> Result {
    let root = workspace_root();
    let scratch = root.join("target/xtask/check");
    if scratch.exists() {
        fs::remove_dir_all(&scratch).map_err(|e| e.to_string())?;
    }
    write(&scratch.join("generated"), &scratch.join("tests"))?;

    let mut stale = Vec::new();
    let mut compare = |checked_in: &Path, fresh: &Path, label: String| {
        let a = fs::read(checked_in).ok();
        let b = fs::read(fresh).ok();
        if a != b {
            stale.push(label);
        }
    };
    let mut names = std::collections::BTreeSet::new();
    for dir in [root.join("src/generated"), scratch.join("generated")] {
        for path in walk(&dir)? {
            names.insert(path.strip_prefix(&dir).unwrap().to_path_buf());
        }
    }
    for rel in names {
        compare(
            &root.join("src/generated").join(&rel),
            &scratch.join("generated").join(&rel),
            format!("src/generated/{}", rel.display()),
        );
    }
    for rel in ["spec_examples.rs", "spec_examples/examples.json"] {
        compare(
            &root.join("tests").join(rel),
            &scratch.join("tests").join(rel),
            format!("tests/{rel}"),
        );
    }
    if stale.is_empty() {
        println!("generated code is up to date");
        Ok(())
    } else {
        Err(format!(
            "generated code is out of date; run `cargo xtask codegen` and commit:\n  {}",
            stale.join("\n  ")
        ))
    }
}

fn walk(dir: &Path) -> Result<Vec<std::path::PathBuf>> {
    let mut out = Vec::new();
    if !dir.exists() {
        return Ok(out);
    }
    for entry in fs::read_dir(dir).map_err(|e| e.to_string())? {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path.is_dir() {
            out.extend(walk(&path)?);
        } else {
            out.push(path);
        }
    }
    Ok(out)
}

/// `cargo xtask codegen --report`: prints what would be generated.
pub fn report() -> Result {
    let (ir, _, _) = load()?;
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
