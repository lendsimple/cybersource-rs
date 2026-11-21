//! `cargo xtask sandbox-keys`: downloads Cybersource's public sandbox sample
//! keys (for live and P12 tests) into `target/sandbox-keys/`.
//!
//! The files are not committed: they belong to Cybersource's sample repos
//! (no stated licence) and some expire. They are pinned to a commit and
//! checked by SHA-256.

use std::fs;
use std::process::Command;

use sha2::{Digest, Sha256};

use crate::{Result, run, workspace_root};

const REPO: &str = "CyberSource/cybersource-rest-samples-python";
const COMMIT: &str = "b154f7ca25d3c80cc51ce28415afced193159e58";

/// (file under `resources/`, SHA-256)
const FILES: &[(&str, &str)] = &[
    (
        "agentic_mid_091225001.p12",
        "80e504384331c8786fd18f3394e1397d3427076498af7f7d8b3d4b0fb4e38b01",
    ),
    (
        "agentic_mid_091225001_mle.p12",
        "85f365f2ad4a0858192abd40dce50494c2591671eadd61f487a901d08b406b21",
    ),
    (
        "agentic_mid_091225001_new_generated_mle_private_key.p8",
        "a677c9c52052f8b8a2297f7086ab1a99a7e34386d078866c3271d11d1b06987f",
    ),
    (
        "agentic_mid_091225001_new_generated_mle_private_key.pem",
        "64d5ff2884d246ce4e94f5cfb080f159b6786807542c7c12c024f54030e950e1",
    ),
    (
        "agentic_mid_091225001_new_generated_mle_private_key_encrypted.p8",
        "11d8c4e8f4fc0ca8606bd81a03db8f11f91c3c8187b67154830ee11e70f46644",
    ),
];

pub fn fetch() -> Result {
    let dir = workspace_root().join("target/sandbox-keys");
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    for (file, sha) in FILES {
        let path = dir.join(file);
        let up_to_date = fs::read(&path).is_ok_and(|b| hex(&Sha256::digest(&b)) == *sha);
        if !up_to_date {
            let url = format!("https://raw.githubusercontent.com/{REPO}/{COMMIT}/resources/{file}");
            run(Command::new("curl")
                .args(["-fsSL", "-o"])
                .arg(&path)
                .arg(&url))?;
            let actual = hex(&Sha256::digest(fs::read(&path).map_err(|e| e.to_string())?));
            if actual != *sha {
                fs::remove_file(&path).ok();
                return Err(format!(
                    "{file}: SHA-256 {actual} does not match the pinned {sha}"
                ));
            }
        }
    }
    println!(
        "sandbox keys in {} ({REPO}@{}):\n\
         - merchant agentic_mid_091225001, P12 password `Ap!C38tp12@` (valid to 2028-11-28)\n\
         - response MLE P12 password `Ap!C38tp12@ML3`, kid 1764300612804157241592 (expires 2026-11-28)",
        dir.display(),
        &COMMIT[..12]
    );
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
