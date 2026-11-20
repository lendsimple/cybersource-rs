//! Development tasks for the `cybersource` crate. Run with `cargo xtask <task>`.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

/// Official Python SDK release the auth vectors are generated from.
/// Bump deliberately, then re-run `cargo xtask vectors` and review the diff.
const PYTHON_SDK_VERSION: &str = "0.0.81";

const USAGE: &str = "usage: cargo xtask <task>

tasks:
  vectors   regenerate tests/vectors/*.json from the official Python SDK";

type Result<T = ()> = std::result::Result<T, String>;

fn main() -> ExitCode {
    let result = match std::env::args().nth(1).as_deref() {
        Some("vectors") => vectors(),
        Some(task) => Err(format!("unknown task: {task}\n\n{USAGE}")),
        None => Err(USAGE.to_string()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask lives inside the workspace")
        .to_path_buf()
}

/// Installs the pinned SDK into `target/xtask/venv` and runs the generator.
fn vectors() -> Result {
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

fn run(cmd: &mut Command) -> Result {
    let status = cmd
        .status()
        .map_err(|e| format!("failed to run {cmd:?}: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{cmd:?} exited with {status}"))
    }
}
