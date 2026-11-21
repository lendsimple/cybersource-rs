//! Vendoring the official spec: `cargo xtask update-spec <tag>` / `verify-spec`.
//!
//! The spec lives in every official SDK repo; we pin the Python SDK's copy so
//! the spec and the auth vectors come from the same release.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use sha2::{Digest, Sha256};

use crate::{Result, run, workspace_root};

const REPO: &str = "CyberSource/cybersource-rest-client-python";
const PATH_IN_REPO: &str = "generator/cybersource-rest-spec.json";

pub fn spec_path() -> PathBuf {
    workspace_root().join("spec/cybersource-rest-spec.json")
}

fn source_path() -> PathBuf {
    workspace_root().join("spec/SOURCE.md")
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The SDK tag the vendored spec came from, as recorded in `spec/SOURCE.md`.
pub fn current_tag() -> Result<String> {
    let source = fs::read_to_string(source_path()).map_err(|e| e.to_string())?;
    source
        .lines()
        .find_map(|line| line.strip_prefix("| Tag | `")?.strip_suffix("` |"))
        .map(str::to_owned)
        .ok_or_else(|| "spec/SOURCE.md has no `| Tag |` row".to_string())
}

/// The newest release of the Python SDK, from the GitHub API.
fn latest_tag() -> Result<String> {
    let output = Command::new("curl")
        .args(["-fsSL", "-H", "Accept: application/vnd.github+json"])
        .arg(format!(
            "https://api.github.com/repos/{REPO}/releases/latest"
        ))
        .output()
        .map_err(|e| format!("failed to run curl: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "fetching the latest release failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let release: serde_json::Value =
        serde_json::from_slice(&output.stdout).map_err(|e| e.to_string())?;
    release["tag_name"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| "the latest release has no tag_name".to_string())
}

/// `update-spec --latest`: vendors the newest SDK release's spec, if it is
/// newer than the one vendored.
pub fn update_latest() -> Result {
    let (current, latest) = (current_tag()?, latest_tag()?);
    if current == latest {
        println!("spec is current ({current})");
        return Ok(());
    }
    println!("updating spec {current} -> {latest}");
    update(&latest)
}

/// Downloads the spec at `tag`, checks it parses, and records its provenance.
pub fn update(tag: &str) -> Result {
    let url = format!("https://raw.githubusercontent.com/{REPO}/{tag}/{PATH_IN_REPO}");
    let tmp = workspace_root().join("target/xtask/spec-download.json");
    fs::create_dir_all(tmp.parent().unwrap()).map_err(|e| e.to_string())?;
    run(Command::new("curl")
        .args(["-fsSL", "-o"])
        .arg(&tmp)
        .arg(&url))?;

    let bytes = fs::read(&tmp).map_err(|e| e.to_string())?;
    let spec: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| format!("downloaded spec is not JSON: {e}"))?;
    if spec.get("swagger").and_then(|v| v.as_str()) != Some("2.0") {
        return Err("downloaded spec is not Swagger 2.0".into());
    }
    fs::rename(&tmp, spec_path()).map_err(|e| e.to_string())?;

    let source = format!(
        "# Vendored spec\n\n\
         `cybersource-rest-spec.json` is Cybersource's merged REST spec (Swagger 2.0), copied from\n\
         the official Python SDK so the spec and the auth vectors come from the same release.\n\n\
         | | |\n|---|---|\n\
         | Repository | `{REPO}` |\n\
         | Tag | `{tag}` |\n\
         | Path | `{PATH_IN_REPO}` |\n\
         | URL | <{url}> |\n\
         | Bytes | {} |\n\
         | SHA-256 | `{}` |\n\n\
         Update with `cargo xtask update-spec <tag>`, then `cargo xtask codegen`, and review the diff.\n\
         The spec's own `info.version` is always `0.0.1`, so the SDK tag is the version.\n",
        bytes.len(),
        sha256_hex(&bytes)
    );
    fs::write(source_path(), source).map_err(|e| e.to_string())?;
    println!("vendored spec from {REPO}@{tag} ({} bytes)", bytes.len());
    Ok(())
}

/// Checks the vendored spec matches the SHA-256 in `SOURCE.md`; returns its bytes.
pub fn verify() -> Result<Vec<u8>> {
    let bytes = fs::read(spec_path()).map_err(|e| format!("reading spec: {e}"))?;
    let source =
        fs::read_to_string(source_path()).map_err(|e| format!("reading SOURCE.md: {e}"))?;
    let actual = sha256_hex(&bytes);
    if !source.contains(&actual) {
        return Err(format!(
            "spec/cybersource-rest-spec.json (sha256 {actual}) does not match spec/SOURCE.md; \
             run `cargo xtask update-spec <tag>` instead of editing the spec by hand"
        ));
    }
    Ok(bytes)
}
