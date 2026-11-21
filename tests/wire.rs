//! Real HTTP round trips through the reqwest and ureq transports against a
//! local wiremock server.

#![cfg(all(
    not(target_family = "wasm"),
    feature = "reqwest",
    feature = "ureq",
    feature = "payments"
))]

mod common;

use cybersource::auth::digest;
use cybersource::jose::b64;
use cybersource::models::CreatePaymentRequest;
use cybersource::transport::{ReqwestTransport, UreqTransport};
use cybersource::{BlockingClient, Client, Config, Credentials, Environment, Error};
use wiremock::matchers::{header, header_exists, method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const KEY_ID: &str = "08c94330-f618-42a3-b09d-e1e43be5efda";
const SECRET: &str = "yBJxy6LjM2TmcPGu+GaJrHtkke25fPpUX+UY6/L/1tE=";
const AUTHORIZED: &str = r#"{"id":"7000000000000000000001","status":"AUTHORIZED"}"#;

fn config() -> Config {
    Config::builder()
        .environment(Environment::Sandbox)
        .merchant_id("testrest")
        .credentials(Credentials::jwt_shared_secret(KEY_ID, SECRET).unwrap())
        .build()
        .unwrap()
}

fn payment() -> CreatePaymentRequest {
    common::payment("wire", "100.00")
}

async fn payments_server(status: u16, body: &str) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/pts/v2/payments"))
        .and(header("v-c-merchant-id", "testrest"))
        .and(header("content-type", "application/json;charset=utf-8"))
        .and(header_exists("authorization"))
        .respond_with(
            ResponseTemplate::new(status)
                .insert_header("v-c-correlation-id", "corr-wire")
                .set_body_raw(body.to_owned(), "application/hal+json;charset=utf-8"),
        )
        .expect(1)
        .mount(&server)
        .await;
    server
}

/// The JWT on the wire must carry the digest of the body on the wire.
fn assert_signed_over_received_body(request: &Request) {
    let auth = request.headers["authorization"].to_str().unwrap();
    let token = auth.strip_prefix("Bearer ").unwrap();
    let claims: serde_json::Value =
        serde_json::from_slice(&b64::url_decode(token.split('.').nth(1).unwrap()).unwrap())
            .unwrap();
    assert_eq!(claims["digest"], digest::sha256_b64(&request.body));
    assert_eq!(claims["request-host"], "apitest.cybersource.com");
}

#[tokio::test]
async fn reqwest_round_trip() {
    let server = payments_server(201, AUTHORIZED).await;
    let transport = ReqwestTransport::new()
        .with_base_url(&server.uri())
        .unwrap();
    let client = Client::with_transport(config(), transport);

    let resp = client.payments().create_payment(payment()).await.unwrap();

    assert_eq!(resp.status.as_deref(), Some("AUTHORIZED"));
    let received = server.received_requests().await.unwrap();
    assert_signed_over_received_body(&received[0]);
}

#[tokio::test]
async fn ureq_round_trip() {
    let server = payments_server(201, AUTHORIZED).await;
    let base_url = server.uri();

    let resp = tokio::task::spawn_blocking(move || {
        let transport = UreqTransport::new().with_base_url(&base_url).unwrap();
        BlockingClient::with_transport(config(), transport)
            .payments()
            .create_payment(payment())
            .send()
    })
    .await
    .unwrap()
    .unwrap();

    assert_eq!(resp.id.as_deref(), Some("7000000000000000000001"));
    let received = server.received_requests().await.unwrap();
    assert_signed_over_received_body(&received[0]);
}

const BAD_REQUEST: &str = r#"{"status":"INVALID_REQUEST","reason":"INVALID_DATA","message":"Declined - One or more fields in the request contains invalid data"}"#;

#[tokio::test]
async fn reqwest_maps_error_status_to_api_error() {
    let server = payments_server(400, BAD_REQUEST).await;
    let transport = ReqwestTransport::new()
        .with_base_url(&server.uri())
        .unwrap();

    let err = Client::with_transport(config(), transport)
        .payments()
        .create_payment(payment())
        .await
        .unwrap_err();

    let api = err.as_api().expect("API error");
    assert_eq!(api.status, 400);
    assert_eq!(api.correlation_id.as_deref(), Some("corr-wire"));
}

#[tokio::test]
async fn ureq_maps_error_status_to_api_error_not_transport_error() {
    let server = payments_server(400, BAD_REQUEST).await;
    let base_url = server.uri();

    let err = tokio::task::spawn_blocking(move || {
        let transport = UreqTransport::new().with_base_url(&base_url).unwrap();
        BlockingClient::with_transport(config(), transport)
            .payments()
            .create_payment(payment())
            .send()
    })
    .await
    .unwrap()
    .unwrap_err();

    assert_eq!(err.as_api().expect("API error").status, 400);
}

#[tokio::test]
async fn connection_failure_is_a_transport_error() {
    // Bind then drop a listener so the port is very likely closed.
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let transport = ReqwestTransport::new()
        .with_base_url(&format!("http://127.0.0.1:{port}"))
        .unwrap();

    let err = Client::with_transport(config(), transport)
        .payments()
        .create_payment(payment())
        .await
        .unwrap_err();

    assert!(matches!(err, Error::Transport(_)));
    assert!(err.outcome_unknown());
}
