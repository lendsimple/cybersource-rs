//! Core behaviour on WebAssembly runtimes: run with
//!
//! ```text
//! cargo test --target wasm32-unknown-unknown --no-default-features \
//!     --features server,payments,http-signature --test wasm   # Node, via wasm-bindgen-test-runner
//! cargo test --target wasm32-wasip2 --no-default-features \
//!     --features server,payments,http-signature --test wasm   # wasmtime
//! ```
//!
//! It also runs natively, so a failure here is easy to compare. Fixtures are
//! compiled in (`include_str!`): wasm32-unknown-unknown has no filesystem.

#![cfg(all(feature = "server", feature = "payments", feature = "http-signature"))]

use std::time::Duration;

use cybersource::auth::{SigningInput, authenticate};
use cybersource::clock::{Clock, FixedClock, SystemClock};
use cybersource::entropy::{Entropy, FixedEntropy, OsEntropy};
use cybersource::jose::jwe::{self, Enc, KeyAlg};
use cybersource::keys::pem::rsa_private_key_from_pem;
use cybersource::mle::{MleConfig, RequestMleCert, ResponseMleKey};
use cybersource::transport::MockTransport;
use cybersource::webhook::WebhookVerifier;
use cybersource::{Client, Config, Credentials, Environment, payment};
use futures_executor::block_on;
use http::Method;
use serde_json::Value;

const KEY_ID: &str = "08c94330-f618-42a3-b09d-e1e43be5efda";
const SECRET: &str = "yBJxy6LjM2TmcPGu+GaJrHtkke25fPpUX+UY6/L/1tE=";
const SJC_CERT: &str = include_str!("fixtures/sjc_cert.pem");
const SJC_KEY: &str = include_str!("fixtures/sjc_test_key.pem");
const RESPONSE_KEY: &str = include_str!("fixtures/response_mle_key.pem");

macro_rules! wasm_test {
    ($(#[$meta:meta])* fn $name:ident() $body:block) => {
        $(#[$meta])*
        #[cfg_attr(all(target_arch = "wasm32", target_os = "unknown"), wasm_bindgen_test::wasm_bindgen_test)]
        #[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), test)]
        fn $name() $body
    };
}

fn config(credentials: Credentials, mle: Option<MleConfig>) -> Config {
    Config::builder()
        .environment(Environment::Test)
        .merchant_id("testmerchant")
        .credentials(credentials)
        .maybe_mle(mle)
        .build()
        .unwrap()
}

wasm_test! {
    fn clock_and_entropy_work_at_runtime() {
        assert!(SystemClock.now().as_secs() > 1_735_689_600, "web-time must read the real clock");
        let (mut a, mut b) = ([0u8; 16], [0u8; 16]);
        OsEntropy.fill(&mut a).unwrap();
        OsEntropy.fill(&mut b).unwrap();
        assert_ne!(a, b, "getrandom must produce random bytes");
    }
}

wasm_test! {
    fn jwt_and_http_signature_match_the_sdk_vectors() {
        let jwt: Vec<Value> = serde_json::from_str(include_str!("vectors/jwt.json")).unwrap();
        let hs256 = jwt.iter().find(|v| v["name"] == "hs256_post").unwrap();
        let method: Method = "POST".parse().unwrap();
        let input = SigningInput {
            method: &method,
            target: hs256["target"].as_str().unwrap(),
            body: hs256["body"].as_str().unwrap().as_bytes(),
            response_mle_kid: None,
        };
        let headers = authenticate(
            &config(Credentials::jwt_shared_secret(KEY_ID, SECRET).unwrap(), None),
            &input,
            &FixedClock::from_secs(hs256["epoch"].as_u64().unwrap()),
            &FixedEntropy(vec![0x11]),
        )
        .unwrap();
        assert_eq!(
            headers["authorization"].to_str().unwrap(),
            format!("Bearer {}", hs256["expected_token"].as_str().unwrap())
        );

        let sig: Vec<Value> = serde_json::from_str(include_str!("vectors/http_signature.json")).unwrap();
        let post = sig.iter().find(|v| v["name"] == "post").unwrap();
        let input = SigningInput {
            method: &method,
            target: post["target"].as_str().unwrap(),
            body: post["body"].as_str().unwrap().as_bytes(),
            response_mle_kid: None,
        };
        let headers = authenticate(
            &config(Credentials::http_signature(KEY_ID, SECRET).unwrap(), None),
            &input,
            &FixedClock::from_secs(post["epoch"].as_u64().unwrap()),
            &OsEntropy,
        )
        .unwrap();
        assert_eq!(headers["signature"], post["expected_signature"].as_str().unwrap());
    }
}

wasm_test! {
    fn pipeline_with_message_level_encryption() {
        let mle = MleConfig::new()
            .request_cert(RequestMleCert::from_pem(SJC_CERT).unwrap())
            .optional_globally(true)
            .response_key(ResponseMleKey::from_pem(RESPONSE_KEY, "RESPMLE0000001").unwrap())
            .response_globally(true);
        let mock = MockTransport::new();
        let response_key = rsa_private_key_from_pem(RESPONSE_KEY).unwrap().to_public_key();
        let token = jwe::encrypt(
            &response_key,
            KeyAlg::RsaOaep256,
            Enc::A256Gcm,
            &serde_json::Map::new(),
            br#"{"id":"1","status":"AUTHORIZED"}"#,
            &OsEntropy,
        )
        .unwrap();
        mock.push_json(201, serde_json::json!({ "encryptedResponse": token }).to_string());
        let client = Client::new(
            config(Credentials::jwt_shared_secret(KEY_ID, SECRET).unwrap(), Some(mle)),
            mock.clone(),
        );

        let resp = block_on(
            client.payments().create_payment(payment! { code: "wasm", amount: "1.00" USD }).send(),
        )
        .unwrap();
        assert_eq!(resp.status.as_deref(), Some("AUTHORIZED"));

        let sent: Value = serde_json::from_slice(mock.last_request().body()).unwrap();
        let sjc = rsa_private_key_from_pem(SJC_KEY).unwrap();
        let plaintext = jwe::decrypt(&sjc, sent["encryptedRequest"].as_str().unwrap(), &[KeyAlg::RsaOaep256])
            .unwrap()
            .plaintext;
        let body: Value = serde_json::from_slice(&plaintext).unwrap();
        assert_eq!(body["clientReferenceInformation"]["code"], "wasm");
    }
}

wasm_test! {
    fn webhook_documentation_example_verifies() {
        let verifier = WebhookVerifier::new()
            .key("bf44c857-b182-bb05-e053-34b8d30a7a72", "dGVzdF9rZXk=")
            .unwrap();
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "v-c-signature",
            "t=1617830804768;keyId=bf44c857-b182-bb05-e053-34b8d30a7a72;sig=CzHY47nzJgCSD/BREtSIb+9l/vfkaaL4qf9n8MNJ4CY="
                .parse()
                .unwrap(),
        );
        verifier
            .verify(&headers, b"this is a decrypted payload", Duration::from_millis(1_617_830_804_768))
            .unwrap();
    }
}

// ---------------------------------------------------------------------------
// Live: real requests from inside the wasm runtime. wasm has no environment
// variables, so these are enabled at compile time with `CYBS_LIVE=1`.
// ---------------------------------------------------------------------------

#[cfg(any(
    all(feature = "fetch", target_arch = "wasm32", target_os = "unknown"),
    all(feature = "wasi", target_os = "wasi", target_env = "p2")
))]
async fn live_round_trip<T: cybersource::transport::HttpTransport>(transport: T) {
    use cybersource::capture_context::GetFlexPublicKey;
    use cybersource::types::PaymentStatus;

    let client = Client::new(
        Config::builder()
            .environment(Environment::Test)
            .merchant_id("testrest")
            .credentials(Credentials::jwt_shared_secret(KEY_ID, SECRET).unwrap())
            .build()
            .unwrap(),
        transport,
    );

    // Unauthenticated GET.
    let jwk = client
        .execute(&GetFlexPublicKey { kid: "zu".into() })
        .await
        .unwrap();
    assert_eq!(jwk.kid.as_deref(), Some("zu"));

    // JWT-signed POST.
    let resp = client
        .payments()
        .create_payment(payment! {
            code: "cybersource-rs-wasm",
            amount: "10.00" USD,
            card: { number: "4111111111111111", expiration_month: "12", expiration_year: "2031" },
            bill_to: {
                first_name: "John", last_name: "Doe", address1: "1 Market St",
                locality: "San Francisco", administrative_area: "CA", postal_code: "94105",
                country: "US", email: "test@cybs.com", phone_number: "4158880000",
            },
        })
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.payment_status(),
        Some(PaymentStatus::Authorized),
        "{resp:?}"
    );
}

#[cfg(all(feature = "fetch", target_arch = "wasm32", target_os = "unknown"))]
#[wasm_bindgen_test::wasm_bindgen_test]
async fn fetch_transport_live() {
    if option_env!("CYBS_LIVE") != Some("1") {
        return;
    }
    live_round_trip(cybersource::transport::FetchTransport::new()).await;
}

#[cfg(all(feature = "wasi", target_os = "wasi", target_env = "p2"))]
#[test]
fn wasi_transport_live() {
    if option_env!("CYBS_LIVE") != Some("1") {
        return;
    }
    wstd::runtime::block_on(live_round_trip(cybersource::transport::WasiTransport::new()));
}
