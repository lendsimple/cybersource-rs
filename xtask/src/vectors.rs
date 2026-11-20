//! `cargo xtask vectors`: auth known-answer vectors from the official Python SDK.

use std::process::Command;

use crate::{Result, run, workspace_root};

/// Official Python SDK release the auth vectors are generated from.
/// Bump deliberately, then re-run `cargo xtask vectors` and review the diff.
const PYTHON_SDK_VERSION: &str = "0.0.81";

/// Installs the pinned SDK into `target/xtask/venv` and runs the generator.
pub fn vectors() -> Result {
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
    let wanted = format!("Version: {PYTHON_SDK_VERSION}");
    if !String::from_utf8_lossy(&installed.stdout).contains(&wanted) {
        run(Command::new(&python).args([
            "-m",
            "pip",
            "install",
            "--quiet",
            &format!("cybersource-rest-client-python=={PYTHON_SDK_VERSION}"),
        ]))?;
    }

    run(Command::new(&python)
        .arg("-I")
        .arg(root.join("xtask/vectors/gen_vectors.py"))
        .arg(root.join("tests/fixtures"))
        .arg(root.join("tests/vectors")))?;
    println!("wrote tests/vectors/*.json from cybersource-rest-client-python {PYTHON_SDK_VERSION}");
    Ok(())
}
