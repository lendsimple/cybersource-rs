//! Message-level encryption: configuration, validation and the pipeline.

#![cfg(all(not(target_family = "wasm"), feature = "p12", feature = "payments"))]

use cybersource::config::CertificateRole;
use cybersource::mle::{MleConfig, MleOverride, RequestMleCert, ResponseMleKey};
use cybersource::{Config, Credentials, Environment};

const KEY_ID: &str = "08c94330-f618-42a3-b09d-e1e43be5efda";
const SECRET: &str = "yBJxy6LjM2TmcPGu+GaJrHtkke25fPpUX+UY6/L/1tE=";

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn fixture_str(name: &str) -> String {
    String::from_utf8(fixture(name)).unwrap()
}

fn p12_credentials() -> Credentials {
    Credentials::jwt_p12(&fixture("cybs_shaped.p12"), "testmerchant", "testmerchant").unwrap()
}

fn response_key() -> ResponseMleKey {
    ResponseMleKey::from_p12(
        &fixture("response_mle.p12"),
        "testmerchant-mle",
        "testmerchant",
    )
    .unwrap()
}

fn build(credentials: Credentials, mle: Option<MleConfig>) -> cybersource::Result<Config> {
    Config::builder()
        .environment(Environment::Sandbox)
        .merchant_id("testmerchant")
        .credentials(credentials)
        .maybe_mle(mle)
        .build()
}

#[test]
fn p12_credentials_supply_the_request_certificate() {
    let config = build(p12_credentials(), None).unwrap();
    assert_eq!(config.mle().request_cert_kid(), Some("SJC0000000001"));
}

#[test]
fn response_key_id_comes_from_the_p12_certificate() {
    assert_eq!(response_key().key_id(), Some("RESPMLE0000001"));
    let overridden = response_key().kid("OTHER");
    assert_eq!(overridden.key_id(), Some("OTHER"));
    let config = build(
        p12_credentials(),
        Some(
            MleConfig::new()
                .response_key(overridden)
                .response_globally(true),
        ),
    )
    .unwrap();
    assert!(config.mle().warnings()[0].contains("overrides \"RESPMLE0000001\""));
}

#[test]
fn pem_and_encrypted_pem_response_keys_need_their_kid() {
    let key = ResponseMleKey::from_encrypted_pem(
        &fixture_str("response_mle_key_encrypted.pem"),
        "secret-pw",
        "RESPMLE0000001",
    )
    .unwrap();
    assert_eq!(key.key_id(), Some("RESPMLE0000001"));
    ResponseMleKey::from_pem(&fixture_str("response_mle_key_with_preamble.pem"), "k").unwrap();
}

#[test]
fn request_certificate_from_pem() {
    let cert = RequestMleCert::from_pem(&fixture_str("sjc_cert.pem")).unwrap();
    assert_eq!(cert.kid(), "SJC0000000001");
    assert!(RequestMleCert::from_p12(&fixture("testmerchant.p12"), "testmerchant").is_err());
}

#[test]
fn enabling_request_encryption_without_a_certificate_is_rejected() {
    let shared = Credentials::jwt_shared_secret(KEY_ID, SECRET).unwrap();
    let err = build(shared, Some(MleConfig::new().optional_globally(true))).unwrap_err();
    assert!(
        err.to_string().contains("no request MLE certificate"),
        "{err}"
    );
}

#[test]
fn enabling_encrypted_responses_without_a_key_is_rejected() {
    let err = build(
        p12_credentials(),
        Some(MleConfig::new().response_globally(true)),
    )
    .unwrap_err();
    assert!(err.to_string().contains("no response MLE key"), "{err}");
    let err = build(
        p12_credentials(),
        Some(MleConfig::new().override_op(
            "createPayment",
            MleOverride {
                request: None,
                response: Some(true),
            },
        )),
    )
    .unwrap_err();
    assert!(err.to_string().contains("no response MLE key"), "{err}");
}

#[cfg(feature = "http-signature")]
#[test]
fn mle_with_http_signature_is_rejected() {
    let http = Credentials::http_signature(KEY_ID, SECRET).unwrap();
    let cert = RequestMleCert::from_pem(&fixture_str("sjc_cert.pem")).unwrap();
    let err = build(
        http,
        Some(MleConfig::new().request_cert(cert).optional_globally(true)),
    )
    .unwrap_err();
    assert!(err.to_string().contains("requires JWT"), "{err}");
}

#[test]
fn certificate_expiries_cover_every_role() {
    let config = build(
        p12_credentials(),
        Some(MleConfig::new().response_key(response_key())),
    )
    .unwrap();
    let roles: Vec<_> = config
        .certificate_expiries()
        .iter()
        .map(|e| e.role)
        .collect();
    assert_eq!(
        roles,
        [
            CertificateRole::Signing,
            CertificateRole::RequestMle,
            CertificateRole::ResponseMle
        ]
    );
    assert!(
        config
            .certificate_expiries()
            .iter()
            .all(|e| e.not_after_unix > 4_000_000_000)
    );
}

// ---------------------------------------------------------------------------
// The pipeline, on MockTransport
// ---------------------------------------------------------------------------

mod common;

use std::borrow::Cow;

use bytes::Bytes;
use cybersource::auth::digest;
use cybersource::clock::FixedClock;
use cybersource::entropy::OsEntropy;
use cybersource::error::ErrorBody;
use cybersource::jose::b64;
use cybersource::jose::jwe::{self, Enc, KeyAlg};
use cybersource::keys::pem::rsa_private_key_from_pem;
use cybersource::operation::{MlePolicy, Operation, OperationMeta, json_body, json_decode};
use cybersource::transport::MockTransport;
use cybersource::{Client, Error};
use http::{Method, StatusCode};

const AUTHORIZED: &str = r#"{"id":"7000000000000000000001","status":"AUTHORIZED"}"#;

fn client(config: Config, mock: &MockTransport) -> Client<MockTransport> {
    Client::with_transport(config, mock.clone()).with_clock(FixedClock::from_secs(1_793_865_600))
}

fn claims(request: &http::Request<Bytes>) -> serde_json::Value {
    let auth = request.headers()["authorization"].to_str().unwrap();
    let payload = auth
        .strip_prefix("Bearer ")
        .unwrap()
        .split('.')
        .nth(1)
        .unwrap();
    serde_json::from_slice(&b64::url_decode(payload).unwrap()).unwrap()
}

/// An `{"encryptedResponse": ...}` body encrypted to the response-MLE key.
fn encrypted_body(json: &str) -> String {
    let public = rsa_private_key_from_pem(&fixture_str("response_mle_key.pem"))
        .unwrap()
        .to_public_key();
    let token = jwe::encrypt(
        &public,
        KeyAlg::RsaOaep256,
        Enc::A256Gcm,
        &serde_json::Map::new(),
        json.as_bytes(),
        &OsEntropy,
    )
    .unwrap();
    serde_json::json!({ "encryptedResponse": token }).to_string()
}

#[tokio::test]
async fn encrypted_request_body_is_the_wrapper_and_is_signed() {
    let mock = MockTransport::new();
    mock.push_json(201, AUTHORIZED);
    let config = build(
        p12_credentials(),
        Some(MleConfig::new().optional_globally(true)),
    )
    .unwrap();
    let payment = common::payment("mle", "10.00");

    client(config, &mock)
        .payments()
        .create_payment(payment.clone())
        .await
        .unwrap();

    let req = mock.last_request();
    let wrapper: serde_json::Value = serde_json::from_slice(req.body()).unwrap();
    let obj = wrapper.as_object().unwrap();
    assert_eq!(obj.len(), 1);
    let token = obj["encryptedRequest"].as_str().unwrap();
    let sjc = rsa_private_key_from_pem(&fixture_str("sjc_test_key.pem")).unwrap();
    let decrypted = jwe::decrypt(&sjc, token, &[KeyAlg::RsaOaep256]).unwrap();
    assert_eq!(decrypted.header["kid"], "SJC0000000001");
    assert_eq!(decrypted.header["iat"], 1_793_865_600);
    assert_eq!(decrypted.header["cty"], "application/json");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&decrypted.plaintext).unwrap(),
        serde_json::to_value(&payment).unwrap()
    );
    assert_eq!(claims(&req)["digest"], digest::sha256_b64(req.body()));
}

#[tokio::test]
async fn response_mle_claims_only_when_requested() {
    let mock = MockTransport::new();
    mock.push_json(201, AUTHORIZED).push_json(201, AUTHORIZED);

    let plain = build(
        p12_credentials(),
        Some(MleConfig::new().response_key(response_key())),
    )
    .unwrap();
    client(plain, &mock)
        .payments()
        .create_payment(common::payment("a", "1.00"))
        .await
        .unwrap();
    let c = claims(&mock.last_request());
    assert!(c.get("v-c-response-mle-kid").is_none());

    let asking = build(
        p12_credentials(),
        Some(
            MleConfig::new()
                .response_key(response_key())
                .response_globally(true),
        ),
    )
    .unwrap();
    client(asking, &mock)
        .payments()
        .create_payment(common::payment("b", "1.00"))
        .await
        .unwrap();
    let c = claims(&mock.last_request());
    assert_eq!(c["v-c-response-mle-kid"], "RESPMLE0000001");
    assert_eq!(c["v-c-response-mle-algo"], "RSA-OAEP-256");
}

#[tokio::test]
async fn encrypted_success_response_is_decrypted_and_decoded() {
    let mock = MockTransport::new();
    mock.push_json(201, encrypted_body(AUTHORIZED));
    let config = build(
        p12_credentials(),
        Some(
            MleConfig::new()
                .response_key(response_key())
                .response_globally(true),
        ),
    )
    .unwrap();

    let resp = client(config, &mock)
        .payments()
        .create_payment(common::payment("c", "1.00"))
        .await
        .unwrap();

    assert_eq!(resp.status.as_deref(), Some("AUTHORIZED"));
}

#[tokio::test]
async fn encrypted_error_response_is_decrypted_into_the_api_error() {
    let mock = MockTransport::new();
    mock.push_json(
        400,
        encrypted_body(r#"{"status":"INVALID_REQUEST","reason":"MISSING_FIELD","message":"x"}"#),
    );
    let config = build(
        p12_credentials(),
        Some(
            MleConfig::new()
                .response_key(response_key())
                .response_globally(true),
        ),
    )
    .unwrap();

    let err = client(config, &mock)
        .payments()
        .create_payment(common::payment("d", "1.00"))
        .await
        .unwrap_err();

    let ErrorBody::Pts(body) = &err.as_api().unwrap().body else {
        panic!("expected a PTS error, got {err:?}");
    };
    assert_eq!(body.reason.as_deref(), Some("MISSING_FIELD"));
}

#[tokio::test]
async fn encrypted_response_without_a_key_is_an_mle_error() {
    let mock = MockTransport::new();
    mock.push_json(201, encrypted_body(AUTHORIZED));

    let err = client(build(p12_credentials(), None).unwrap(), &mock)
        .payments()
        .create_payment(common::payment("e", "1.00"))
        .await
        .unwrap_err();

    assert!(matches!(err, Error::Mle(_)), "{err:?}");
}

/// An operation for which Cybersource requires request encryption.
#[derive(Clone)]
struct Mandatory;

static MANDATORY: OperationMeta = OperationMeta::new("mandatoryOp", Method::POST, "/mandatory")
    .mle(MlePolicy::Mandatory, MlePolicy::Never);

impl Operation for Mandatory {
    type Output = serde_json::Value;
    fn meta(&self) -> &'static OperationMeta {
        &MANDATORY
    }
    fn path(&self) -> Cow<'_, str> {
        "/mandatory".into()
    }
    fn body(&self) -> cybersource::Result<Option<Bytes>> {
        json_body(&serde_json::json!({"card": "4111111111111111"}))
    }
    fn decode(&self, _: StatusCode, body: &Bytes) -> cybersource::Result<Self::Output> {
        json_decode(body)
    }
}

#[tokio::test]
async fn mandatory_operations_are_encrypted_by_default_with_a_p12() {
    let mock = MockTransport::new();
    mock.push_json(200, "{}");
    client(build(p12_credentials(), None).unwrap(), &mock)
        .execute(&Mandatory)
        .await
        .unwrap();
    let body = String::from_utf8(mock.last_request().body().to_vec()).unwrap();
    assert!(body.starts_with(r#"{"encryptedRequest":"#), "{body}");
    assert!(!body.contains("4111"));
}

#[tokio::test]
async fn mandatory_operation_without_a_certificate_is_never_sent_in_plaintext() {
    let mock = MockTransport::new();
    mock.push_json(200, "{}");
    let shared = Credentials::jwt_shared_secret(KEY_ID, SECRET).unwrap();

    let err = client(build(shared, None).unwrap(), &mock)
        .execute(&Mandatory)
        .await
        .unwrap_err();

    assert!(
        matches!(&err, Error::Mle(m) if m.contains("mandatoryOp")),
        "{err:?}"
    );
    assert!(mock.requests().is_empty(), "nothing may be sent");
}

#[cfg(feature = "http-signature")]
#[tokio::test]
async fn mandatory_operation_under_http_signature_is_refused() {
    let mock = MockTransport::new();
    let http = Credentials::http_signature(KEY_ID, SECRET).unwrap();

    let err = client(build(http, None).unwrap(), &mock)
        .execute(&Mandatory)
        .await
        .unwrap_err();

    assert!(matches!(err, Error::Mle(_)), "{err:?}");
    assert!(mock.requests().is_empty());
}
