//! Development tasks for the `cybersource` crate. Run with `cargo xtask <task>`.

use std::process::ExitCode;

const USAGE: &str = "usage: cargo xtask <task>\n\ntasks:\n  (none yet)";

fn main() -> ExitCode {
    let task = std::env::args().nth(1);
    if let Some(task) = task {
        eprintln!("unknown task: {task}");
    }
    eprintln!("{USAGE}");
    ExitCode::FAILURE
}
