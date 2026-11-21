//! `cargo xtask vectors`: auth known-answer vectors from the official Python SDK.

use std::process::Command;

use crate::spec_source::current_tag;
use crate::{Result, run, workspace_root};

/// Installs the SDK release the spec was vendored from (`spec/SOURCE.md`)
/// into `target/xtask/venv` and runs the generator, so the spec and the
/// vectors always come from the same release.
pub fn vectors() -> Result {
    let version = current_tag()?;
    let root = workspace_root();
    let venv = root.join("target/xtask/venv");
    let python = venv.join("bin/python");

    if !python.exists() {
        run(Command::new("python3").arg("-m").arg("venv").arg(&venv))?;
    }
    let installed = Command::new(&python)
        .args(["-m", "pip", "show", "cybersource-rest-client-python"])
        .output()
        .map_err(|e| format!("failed to run pip: {e}"))?;
    let wanted = format!("Version: {version}");
    if !String::from_utf8_lossy(&installed.stdout).contains(&wanted) {
        run(Command::new(&python).args([
            "-m",
            "pip",
            "install",
            "--quiet",
            &format!("cybersource-rest-client-python=={version}"),
        ]))?;
    }

    run(Command::new(&python)
        .arg("-I")
        .arg(root.join("xtask/vectors/gen_vectors.py"))
        .arg(root.join("tests/fixtures"))
        .arg(root.join("tests/vectors")))?;
    println!("wrote tests/vectors/*.json from cybersource-rest-client-python {version}");
    Ok(())
}
