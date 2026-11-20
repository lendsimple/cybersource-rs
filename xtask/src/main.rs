//! Development tasks for the `cybersource` crate. Run with `cargo xtask <task>`.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

mod codegen;
mod spec_source;
mod vectors;

const USAGE: &str = "usage: cargo xtask <task>

tasks:
  vectors               regenerate tests/vectors/*.json from the official Python SDK
  update-spec <tag>     vendor the spec from cybersource-rest-client-python at <tag>
  verify-spec           check spec/cybersource-rest-spec.json matches spec/SOURCE.md
  codegen               regenerate src/generated from the spec
  codegen --report      build the IR from the spec and print a summary";

type Result<T = ()> = std::result::Result<T, String>;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["vectors"] => vectors::vectors(),
        ["update-spec", tag] => spec_source::update(tag),
        ["verify-spec"] => spec_source::verify().map(|_| ()),
        ["codegen"] => codegen::codegen(),
        ["codegen", "--report"] => codegen::report(),
        [] => Err(USAGE.to_string()),
        other => Err(format!("unknown task: {}\n\n{USAGE}", other.join(" "))),
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
