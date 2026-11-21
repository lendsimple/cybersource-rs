//! Decrypting JWE tokens produced by the official Python SDK and its JOSE
//! library (see `tests/vectors/PROVENANCE.md`).

#![cfg(all(not(target_family = "wasm"), feature = "server"))]

use cybersource::jose::jwe::{self, KeyAlg};
use cybersource::keys::pem::rsa_private_key_from_pem;
use serde::Deserialize;

#[derive(Deserialize)]
struct Vector {
    name: String,
    token: String,
    plaintext: String,
    wrapper: Option<String>,
}

fn vectors() -> Vec<Vector> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/jwe.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn decrypts_sdk_and_jwcrypto_tokens() {
    let key = rsa_private_key_from_pem(include_str!("fixtures/sjc_test_key.pem")).unwrap();
    let vectors = vectors();
    assert_eq!(vectors.len(), 4);
    for v in vectors {
        let out = jwe::decrypt(&key, &v.token, &[KeyAlg::RsaOaep, KeyAlg::RsaOaep256])
            .unwrap_or_else(|e| panic!("{}: {e}", v.name));
        assert_eq!(
            String::from_utf8(out.plaintext).unwrap(),
            v.plaintext,
            "{}",
            v.name
        );
    }
}

#[test]
fn sdk_request_header_and_wrapper_shape() {
    let key = rsa_private_key_from_pem(include_str!("fixtures/sjc_test_key.pem")).unwrap();
    let v = vectors()
        .into_iter()
        .find(|v| v.name == "sdk_mle_request")
        .unwrap();
    let out = jwe::decrypt(&key, &v.token, &[KeyAlg::RsaOaep256]).unwrap();
    assert_eq!(out.header["alg"], "RSA-OAEP-256");
    assert_eq!(out.header["enc"], "A256GCM");
    assert_eq!(out.header["kid"], "SJC0000000001");
    assert_eq!(out.header["cty"], "application/json");
    assert_eq!(out.header["iat"], 1_793_865_600);
    let wrapper: serde_json::Value = serde_json::from_str(&v.wrapper.unwrap()).unwrap();
    assert_eq!(wrapper.as_object().unwrap().len(), 1);
    assert_eq!(wrapper["encryptedRequest"], v.token);
}
