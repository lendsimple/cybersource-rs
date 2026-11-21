//! Capture context and transient token verification.

#![cfg(all(not(target_family = "wasm"), feature = "server"))]

use cybersource::capture_context::CaptureContextVerifier;
use cybersource::clock::FixedClock;
use cybersource::jose::jwk::RsaJwk;
use cybersource::jose::jws::{self, JwsKey};
use cybersource::keys::pem::rsa_private_key_from_pem;
use cybersource::transport::MockTransport;
use cybersource::{Client, Config, Credentials, Environment, Error};
use rsa::PrivateKey;
use serde::Deserialize;
use serde_json::json;

const NOW: i64 = 1_793_865_600;

fn key(file: &str) -> PrivateKey {
    let path = format!("{}/tests/fixtures/{file}", env!("CARGO_MANIFEST_DIR"));
    rsa_private_key_from_pem(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// Cybersource's long-term signer stand-in.
fn signer() -> PrivateKey {
    key("rsa_test_key.pem")
}

/// The one-time key a capture context carries.
fn one_time() -> PrivateKey {
    key("sjc_test_key.pem")
}

fn capture_context(exp: i64) -> String {
    let jwk = RsaJwk::from_public_key(&one_time().to_public_key(), Some("one-time-kid".into()));
    jws::sign(
        JwsKey::Rs256(&signer()),
        "signer-kid",
        &json!({
            "iss": "Flex API", "iat": exp - 900, "exp": exp, "jti": "abc",
            "flx": { "path": "/flex/v2/tokens", "data": "opaque", "origin": "https://testflex.cybersource.com", "jwk": jwk },
            "ctx": [{ "type": "mf-2.1.0", "data": {
                "clientLibrary": "https://testflex.cybersource.com/microform/bundle/v2.5.1/flex-microform.min.js",
                "clientLibraryIntegrity": "sha256-xyz", "targetOrigins": ["https://shop.example"]
            }}],
            "someFutureClaim": true
        }),
    )
    .unwrap()
}

fn transient_token(kid: &str, key: &PrivateKey, exp: i64) -> String {
    jws::sign(
        JwsKey::Rs256(key),
        kid,
        &json!({
            "iss": "Flex/08", "iat": exp - 900, "exp": exp, "type": "mf-2.0.0", "jti": "tt-1",
            "content": { "paymentInformation": { "card": { "number": { "maskedValue": "XXXXXXXXXXXX1111", "bin": "411111" } } } }
        }),
    )
    .unwrap()
}

#[derive(Deserialize)]
struct Example {
    source: String,
    jwt: String,
}

#[test]
fn real_cybersource_capture_contexts_verify_with_the_published_key() {
    let jwk: RsaJwk = serde_json::from_str(include_str!("fixtures/flex_zu_jwk.json")).unwrap();
    let key = jwk.to_public_key().unwrap();
    let examples: Vec<Example> =
        serde_json::from_str(include_str!("fixtures/capture_context_examples.json")).unwrap();
    assert_eq!(examples.len(), 4);
    let verifier = CaptureContextVerifier::new();
    for e in examples {
        // These spec examples expired long ago; check them as of when they were issued.
        let iat = jws::decode_unverified(&e.jwt).unwrap().claims["iat"]
            .as_i64()
            .unwrap();
        let context = verifier
            .verify_with_key(&e.jwt, &key, iat)
            .unwrap_or_else(|err| panic!("{}: {err}", e.source));
        assert_eq!(context.iss.as_deref(), Some("Flex API"), "{}", e.source);
        assert!(context.flx.is_some(), "{}", e.source);

        let mut tampered: Vec<String> = e.jwt.split('.').map(str::to_owned).collect();
        tampered[1].pop();
        assert!(
            verifier
                .verify_with_key(&tampered.join("."), &key, iat)
                .is_err()
        );
    }
}

#[test]
fn capture_context_claims_are_exposed() {
    let jwt = capture_context(NOW + 600);
    let context = CaptureContextVerifier::new()
        .verify_with_key(&jwt, &signer().to_public_key(), NOW)
        .unwrap();
    assert_eq!(
        context.flx.as_ref().unwrap().jwk.kid.as_deref(),
        Some("one-time-kid")
    );
    assert_eq!(context.ctx[0].kind, "mf-2.1.0");
    assert!(
        context
            .client_library()
            .unwrap()
            .ends_with("flex-microform.min.js")
    );
    assert_eq!(context.client_library_integrity(), Some("sha256-xyz"));
    assert_eq!(context.claims["someFutureClaim"], true);
    assert_eq!(context.jwt, jwt);
}

#[test]
fn expired_capture_context_is_rejected() {
    let err = CaptureContextVerifier::new()
        .verify_with_key(&capture_context(NOW - 100), &signer().to_public_key(), NOW)
        .unwrap_err();
    assert!(matches!(err, Error::Verification(m) if m.contains("expired")));
}

#[test]
fn transient_token_verifies_with_the_contexts_one_time_key() {
    let context = CaptureContextVerifier::new()
        .verify_with_key(&capture_context(NOW + 600), &signer().to_public_key(), NOW)
        .unwrap();

    let token = context
        .verify_transient_token(
            &transient_token("one-time-kid", &one_time(), NOW + 900),
            NOW,
        )
        .unwrap();
    assert_eq!(token.jti.as_deref(), Some("tt-1"));
    assert_eq!(token.kind.as_deref(), Some("mf-2.0.0"));
    assert_eq!(
        token.content.unwrap()["paymentInformation"]["card"]["number"]["bin"],
        "411111"
    );

    let expired = context
        .verify_transient_token(&transient_token("one-time-kid", &one_time(), NOW - 60), NOW);
    assert!(matches!(expired, Err(Error::Verification(m)) if m.contains("expired")));

    let other_kid = context.verify_transient_token(
        &transient_token("someone-else", &one_time(), NOW + 900),
        NOW,
    );
    assert!(matches!(other_kid, Err(Error::Verification(m)) if m.contains("kid mismatch")));

    let forged =
        context.verify_transient_token(&transient_token("one-time-kid", &signer(), NOW + 900), NOW);
    assert!(matches!(forged, Err(Error::Verification(m)) if m.contains("signature")));
}

#[test]
fn non_rs256_capture_contexts_are_rejected() {
    let hs = jws::sign(JwsKey::Hs256(b"secret"), "k", &json!({"exp": NOW + 600})).unwrap();
    let err = CaptureContextVerifier::new()
        .verify_with_key(&hs, &signer().to_public_key(), NOW)
        .unwrap_err();
    assert!(matches!(err, Error::Verification(m) if m.contains("HS256")));
}

fn client(mock: &MockTransport) -> Client<MockTransport> {
    let config = Config::builder()
        .environment(Environment::Sandbox)
        .merchant_id("testrest")
        .credentials(
            Credentials::jwt_shared_secret(
                "08c94330-f618-42a3-b09d-e1e43be5efda",
                "yBJxy6LjM2TmcPGu+GaJrHtkke25fPpUX+UY6/L/1tE=",
            )
            .unwrap(),
        )
        .build()
        .unwrap();
    Client::with_transport(config, mock.clone()).with_clock(FixedClock::from_secs(NOW as u64))
}

fn jwk_body(key: &PrivateKey) -> String {
    serde_json::to_string(&RsaJwk::from_public_key(
        &key.to_public_key(),
        Some("signer-kid".into()),
    ))
    .unwrap()
}

#[tokio::test]
async fn verifier_fetches_and_caches_signing_keys() {
    let mock = MockTransport::new();
    mock.push_json(200, jwk_body(&signer()));
    let client = client(&mock);
    let verifier = CaptureContextVerifier::new();

    verifier
        .verify(&client, &capture_context(NOW + 600))
        .await
        .unwrap();
    verifier
        .verify(&client, &capture_context(NOW + 600))
        .await
        .unwrap();

    let requests = mock.requests();
    assert_eq!(requests.len(), 1, "the second verification uses the cache");
    assert_eq!(requests[0].uri().path(), "/flex/v2/public-keys/signer-kid");
    assert!(
        requests[0].headers().get("authorization").is_none(),
        "the key endpoint is unauthenticated"
    );
}

#[tokio::test]
async fn verifier_refetches_a_rotated_key_once() {
    let mock = MockTransport::new();
    // First fetch returns the wrong key (as if it had since been rotated).
    mock.push_json(200, jwk_body(&one_time()))
        .push_json(200, jwk_body(&signer()));
    let client = client(&mock);
    let verifier = CaptureContextVerifier::new();

    assert!(
        verifier
            .verify(&client, &capture_context(NOW + 600))
            .await
            .is_err()
    );
    verifier
        .verify(&client, &capture_context(NOW + 600))
        .await
        .unwrap();
    assert_eq!(mock.requests().len(), 2);
}

#[tokio::test]
async fn unknown_kid_is_an_api_error() {
    let mock = MockTransport::new();
    mock.push_json(
        404,
        r#"{"message":"No keystore entry exists for supplied keyId: x","reason":"NOT_FOUND"}"#,
    );
    let err = CaptureContextVerifier::new()
        .verify(&client(&mock), &capture_context(NOW + 600))
        .await
        .unwrap_err();
    assert_eq!(err.as_api().unwrap().status, 404);
}
