//! PKCS#12 loading against Cybersource's real sample files.
//!
//! Run `cargo xtask sandbox-keys` first; these tests are ignored otherwise.

#![cfg(all(not(target_family = "wasm"), feature = "p12"))]

use cybersource::Credentials;
use cybersource::keys::p12::P12;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/target/sandbox-keys/");
const MERCHANT: &str = "agentic_mid_091225001";

fn read(file: &str) -> Vec<u8> {
    std::fs::read(format!("{DIR}{file}"))
        .unwrap_or_else(|e| panic!("{file}: {e}; run `cargo xtask sandbox-keys`"))
}

#[test]
#[ignore = "needs `cargo xtask sandbox-keys`"]
fn sample_auth_p12_has_signing_identity_and_mle_cert() {
    let p12 = P12::parse(&read("agentic_mid_091225001.p12"), "Ap!C38tp12@").unwrap();
    let (_, cert) = p12.identity(MERCHANT).unwrap();
    assert_eq!(
        cert.subject_serial_number().unwrap(),
        "1764300477485036947162"
    );
    let mle = p12.mle_certificate().expect("CyberSource_SJC_US");
    assert_eq!(
        mle.subject_serial_number().unwrap(),
        "1763424170787064972884"
    );
    Credentials::jwt_p12(&read("agentic_mid_091225001.p12"), "Ap!C38tp12@", MERCHANT).unwrap();
}

#[test]
#[ignore = "needs `cargo xtask sandbox-keys`"]
fn sample_response_mle_p12_and_keys_parse() {
    let p12 = P12::parse(&read("agentic_mid_091225001_mle.p12"), "Ap!C38tp12@ML3").unwrap();
    let (_, cert) = p12.identity(MERCHANT).unwrap();
    assert_eq!(
        cert.subject_serial_number().unwrap(),
        "1764300612804157241592"
    );

    let pem = String::from_utf8(read(
        "agentic_mid_091225001_new_generated_mle_private_key.pem",
    ))
    .unwrap();
    let p8 = String::from_utf8(read(
        "agentic_mid_091225001_new_generated_mle_private_key.p8",
    ))
    .unwrap();
    let encrypted = String::from_utf8(read(
        "agentic_mid_091225001_new_generated_mle_private_key_encrypted.p8",
    ))
    .unwrap();
    let a = cybersource::keys::pem::rsa_private_key_from_pem(&pem).unwrap();
    let b = cybersource::keys::pem::rsa_private_key_from_pem(&p8).unwrap();
    let c = cybersource::keys::pem::rsa_private_key_from_encrypted_pem(&encrypted, "Changeit@123")
        .unwrap();
    assert!(a == b && b == c);
}
