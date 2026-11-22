//! End-to-end pipeline tests through both clients, using `MockTransport`.

#![cfg(all(not(target_family = "wasm"), feature = "payments"))]

mod common;

use std::borrow::Cow;

use bytes::Bytes;
use cybersource::auth::digest;
use cybersource::clock::FixedClock;
use cybersource::entropy::FixedEntropy;
use cybersource::error::ErrorBody;
use cybersource::jose::b64;
use cybersource::models::CreatePaymentRequest;
use cybersource::operation::{Operation, OperationMeta, json_decode};
use cybersource::transport::MockTransport;
use cybersource::validate::{self, Validate, ValidationError};
use cybersource::{BlockingClient, Call, Client, Config, Credentials, Environment, Error};
use http::{HeaderMap, Method, StatusCode};

const KEY_ID: &str = "08c94330-f618-42a3-b09d-e1e43be5efda";
const SECRET: &str = "yBJxy6LjM2TmcPGu+GaJrHtkke25fPpUX+UY6/L/1tE=";

fn config(credentials: Credentials) -> Config {
    Config::builder()
        .environment(Environment::Sandbox)
        .merchant_id("testrest")
        .credentials(credentials)
        .build()
        .unwrap()
}

fn jwt_client(mock: &MockTransport) -> Client<MockTransport> {
    Client::with_transport(
        config(Credentials::jwt_shared_secret(KEY_ID, SECRET).unwrap()),
        mock.clone(),
    )
    .with_clock(FixedClock::from_secs(1_793_865_600))
    .with_entropy(FixedEntropy(vec![0x11]))
}

fn payment() -> CreatePaymentRequest {
    common::payment("TC50171_3", "100.00")
}

fn jwt_claims(request: &http::Request<Bytes>) -> serde_json::Value {
    let auth = request.headers()["authorization"].to_str().unwrap();
    let token = auth.strip_prefix("Bearer ").unwrap();
    let payload = token.split('.').nth(1).unwrap();
    serde_json::from_slice(&b64::url_decode(payload).unwrap()).unwrap()
}

const AUTHORIZED: &str = r#"{"id":"7000000000000000000001","status":"AUTHORIZED","submitTimeUtc":"2026-11-20T00:00:00Z","processorInformation":{"approvalCode":"888888"}}"#;

#[tokio::test]
async fn jwt_request_is_signed_over_the_exact_body() {
    let mock = MockTransport::new();
    mock.push_json(201, AUTHORIZED);

    let resp = jwt_client(&mock)
        .payments()
        .create_payment(payment())
        .await
        .unwrap();
    assert_eq!(resp.status.as_deref(), Some("AUTHORIZED"));

    let req = mock.last_request();
    assert_eq!(req.method(), Method::POST);
    assert_eq!(
        req.uri().to_string(),
        "https://apitest.cybersource.com/pts/v2/payments"
    );
    let headers = req.headers();
    assert_eq!(headers["v-c-merchant-id"], "testrest");
    assert_eq!(headers["content-type"], "application/json;charset=utf-8");
    assert!(
        headers["v-c-client-id"]
            .to_str()
            .unwrap()
            .starts_with("cybersource-rs-")
    );
    assert!(
        headers["user-agent"]
            .to_str()
            .unwrap()
            .starts_with("cybersource-rust/")
    );
    assert!(headers.get("signature").is_none());

    let claims = jwt_claims(&req);
    assert_eq!(claims["digest"], digest::sha256_b64(req.body()));
    assert_eq!(claims["request-resource-path"], "/pts/v2/payments");
    assert_eq!(claims["request-method"], "POST");
    let sent: serde_json::Value = serde_json::from_slice(req.body()).unwrap();
    assert_eq!(
        sent["paymentInformation"]["card"]["number"],
        "4111111111111111"
    );
    assert!(
        sent.get("buyerInformation").is_none(),
        "None fields are omitted"
    );
}

#[test]
fn blocking_client_runs_the_same_pipeline() {
    let mock = MockTransport::new();
    mock.push_json(201, AUTHORIZED);
    let client = BlockingClient::with_transport(
        config(Credentials::jwt_shared_secret(KEY_ID, SECRET).unwrap()),
        mock.clone(),
    );

    let resp = client.payments().create_payment(payment()).send().unwrap();

    assert_eq!(resp.id.as_deref(), Some("7000000000000000000001"));
    assert!(mock.last_request().headers().contains_key("authorization"));
}

#[cfg(feature = "http-signature")]
#[test]
fn http_signature_request_carries_digest_of_sent_body() {
    let mock = MockTransport::new();
    mock.push_json(201, AUTHORIZED);
    let client = BlockingClient::with_transport(
        config(Credentials::http_signature(KEY_ID, SECRET).unwrap()),
        mock.clone(),
    )
    .with_clock(FixedClock::from_secs(1_793_865_600));

    client.payments().create_payment(payment()).send().unwrap();

    let req = mock.last_request();
    assert_eq!(req.headers()["date"], "Thu, 05 Nov 2026 08:00:00 GMT");
    assert_eq!(
        req.headers()["digest"].to_str().unwrap(),
        digest::http_digest_header(req.body())
    );
    assert!(
        req.headers()["signature"]
            .to_str()
            .unwrap()
            .contains("headers=\"host date request-target digest v-c-merchant-id\"")
    );
    assert!(req.headers().get("authorization").is_none());
}

/// A test-only operation exercising query strings, bodies, headers and metadata.
#[derive(Clone)]
struct Probe {
    meta: &'static OperationMeta,
    query: Vec<(&'static str, String)>,
    headers: HeaderMap,
    body: Option<Bytes>,
    accept: Option<&'static str>,
    /// Makes `validate` fail, as a body with a too-long field would.
    invalid: bool,
}

static PROBE_GET: OperationMeta = OperationMeta::new("probe", Method::GET, "/probe/v1/items");
static PROBE_POST: OperationMeta = OperationMeta::new("probe", Method::POST, "/probe/v1/items");
static PROBE_NO_AUTH: OperationMeta =
    OperationMeta::new("probe", Method::GET, "/probe/v1/items").no_auth();

impl Operation for Probe {
    type Output = serde_json::Value;

    fn meta(&self) -> &'static OperationMeta {
        self.meta
    }
    fn body(&self) -> cybersource::Result<Option<Bytes>> {
        Ok(self.body.clone())
    }
    fn accept(&self) -> Option<&'static str> {
        self.accept
    }
    fn validate(&self) -> Result<(), ValidationError> {
        struct Currency(&'static str);
        impl Validate for Currency {
            fn validate_into(&self, path: &mut validate::Path, out: &mut Vec<validate::Violation>) {
                path.push_field("currency");
                validate::check_length(self.0, None, Some(3), path, out);
                path.pop();
            }
        }
        Currency(if self.invalid { "US dollars" } else { "USD" }).validate()
    }
    fn path(&self) -> Cow<'_, str> {
        "/probe/v1/items".into()
    }
    fn query(&self) -> Vec<(&'static str, String)> {
        self.query.clone()
    }
    fn headers(&self) -> cybersource::Result<HeaderMap> {
        Ok(self.headers.clone())
    }
    fn decode(&self, _: StatusCode, body: &Bytes) -> cybersource::Result<Self::Output> {
        json_decode(body)
    }
}

fn probe(meta: &'static OperationMeta) -> Probe {
    Probe {
        meta,
        query: Vec::new(),
        headers: HeaderMap::new(),
        body: None,
        accept: None,
        invalid: false,
    }
}

#[tokio::test]
async fn query_is_rfc3986_encoded_and_signed_as_sent() {
    let mock = MockTransport::new();
    mock.push_json(200, "{}");
    let mut op = probe(&PROBE_GET);
    op.query = vec![
        ("name", "My Report".into()),
        ("startTime", "2026-11-01T00:00:00Z".into()),
    ];

    jwt_client(&mock).execute(&op).await.unwrap();

    let req = mock.last_request();
    let target = "/probe/v1/items?name=My%20Report&startTime=2026-11-01T00%3A00%3A00Z";
    assert_eq!(req.uri().path_and_query().unwrap().as_str(), target);
    let claims = jwt_claims(&req);
    assert_eq!(claims["request-resource-path"], target);
    assert!(claims.get("digest").is_none(), "GET has no digest");
    assert!(req.body().is_empty());
    assert!(req.headers().get("content-type").is_none());
}

#[tokio::test]
async fn empty_post_sends_an_empty_json_object() {
    let mock = MockTransport::new();
    mock.push_json(200, "{}");

    jwt_client(&mock)
        .execute(&probe(&PROBE_POST))
        .await
        .unwrap();

    let req = mock.last_request();
    assert_eq!(req.body().as_ref(), b"{}");
    assert_eq!(jwt_claims(&req)["digest"], digest::sha256_b64(b"{}"));
}

#[tokio::test]
async fn invalid_request_is_not_sent() {
    let mock = MockTransport::new();
    let mut op = probe(&PROBE_POST);
    op.invalid = true;

    let err = jwt_client(&mock).execute(&op).await.unwrap_err();

    let Error::Validation(err) = err else {
        panic!("expected Validation, got {err:?}");
    };
    assert_eq!(
        err.to_string(),
        "currency: must be at most 3 characters, not 10"
    );
    assert!(mock.requests().is_empty());
}

#[test]
fn blocking_client_does_not_send_an_invalid_request() {
    let mock = MockTransport::new();
    let client = BlockingClient::with_transport(
        config(Credentials::jwt_shared_secret(KEY_ID, SECRET).unwrap()),
        mock.clone(),
    );
    let mut op = probe(&PROBE_POST);
    op.invalid = true;

    assert!(matches!(client.execute(&op), Err(Error::Validation(_))));
    assert!(mock.requests().is_empty());
}

#[tokio::test]
async fn validation_can_be_turned_off() {
    let mock = MockTransport::new();
    mock.push_json(200, "{}");
    let config = Config::builder()
        .merchant_id("testrest")
        .credentials(Credentials::jwt_shared_secret(KEY_ID, SECRET).unwrap())
        .validate_requests(false)
        .build()
        .unwrap();
    let mut op = probe(&PROBE_POST);
    op.invalid = true;

    Client::with_transport(config, mock.clone())
        .execute(&op)
        .await
        .unwrap();

    assert_eq!(mock.requests().len(), 1);
}

#[tokio::test]
async fn operation_headers_cannot_override_authentication() {
    let mock = MockTransport::new();
    mock.push_json(200, "{}");
    let mut op = probe(&PROBE_GET);
    op.headers
        .insert("authorization", "Bearer forged".parse().unwrap());
    op.headers
        .insert("v-c-merchant-id", "someone-else".parse().unwrap());
    op.headers.insert("profile-id", "abc".parse().unwrap());

    jwt_client(&mock).execute(&op).await.unwrap();

    let req = mock.last_request();
    assert_ne!(req.headers()["authorization"], "Bearer forged");
    assert_eq!(req.headers()["v-c-merchant-id"], "testrest");
    assert_eq!(req.headers()["profile-id"], "abc");
}

#[tokio::test]
async fn declined_payment_is_ok_not_an_error() {
    let mock = MockTransport::new();
    mock.push_json(
        201,
        r#"{"id":"1","status":"DECLINED","errorInformation":{"reason":"PROCESSOR_DECLINED","message":"Decline - General decline of the card."}}"#,
    );

    let resp = jwt_client(&mock)
        .payments()
        .create_payment(payment())
        .await
        .unwrap();

    assert_eq!(resp.status.as_deref(), Some("DECLINED"));
    assert_eq!(
        resp.error_information.unwrap().reason.as_deref(),
        Some("PROCESSOR_DECLINED")
    );
}

#[tokio::test]
async fn bad_request_is_a_typed_api_error() {
    let mock = MockTransport::new();
    mock.push_response(
        http::Response::builder()
            .status(400)
            .header("v-c-correlation-id", "corr-1")
            .body(Bytes::from_static(br#"{"submitTimeUtc":"2026-11-20T00:00:00Z","status":"INVALID_REQUEST","reason":"MISSING_FIELD","message":"Declined - The request is missing one or more fields","details":[{"field":"orderInformation.billTo.country","reason":"MISSING_FIELD"}]}"#))
            .unwrap(),
    );

    let err = jwt_client(&mock)
        .payments()
        .create_payment(payment())
        .await
        .unwrap_err();

    assert!(!err.outcome_unknown());
    let api = err.as_api().expect("API error");
    assert_eq!(api.status, 400);
    assert_eq!(api.correlation_id.as_deref(), Some("corr-1"));
    let ErrorBody::Pts(body) = &api.body else {
        panic!("expected PTS error body, got {:?}", api.body);
    };
    assert_eq!(body.reason.as_deref(), Some("MISSING_FIELD"));
    assert_eq!(
        body.details[0].field.as_deref(),
        Some("orderInformation.billTo.country")
    );
}

#[tokio::test]
async fn bad_gateway_on_payment_means_outcome_unknown_and_not_retry_safe() {
    let mock = MockTransport::new();
    mock.push_json(
        502,
        r#"{"submitTimeUtc":"2026-11-20T00:00:00Z","status":"SERVER_ERROR","reason":"SERVER_TIMEOUT","message":"Error - General system failure."}"#,
    );

    let err = jwt_client(&mock)
        .payments()
        .create_payment(payment())
        .await
        .unwrap_err();

    assert!(err.outcome_unknown());
    assert!(!err.as_api().unwrap().is_retry_safe());
}

#[tokio::test]
async fn transport_failure_means_outcome_unknown() {
    let mock = MockTransport::new();
    mock.push_error("connection reset");

    let err = jwt_client(&mock)
        .payments()
        .create_payment(payment())
        .await
        .unwrap_err();

    assert!(matches!(err, Error::Transport(_)));
    assert!(err.outcome_unknown());
}

#[tokio::test]
async fn correlation_id_is_exposed_on_success() {
    let mock = MockTransport::new();
    mock.push_response(
        http::Response::builder()
            .status(201)
            .header("v-c-correlationid", "corr-2")
            .body(Bytes::from_static(AUTHORIZED.as_bytes()))
            .unwrap(),
    );
    let client = jwt_client(&mock);
    let body = payment();

    let resp = client
        .execute_with_response(&cybersource::operations::CreatePayment::new(body))
        .await
        .unwrap();

    assert_eq!(resp.status, 201);
    assert_eq!(resp.correlation_id(), Some("corr-2"));
}

#[test]
fn debug_output_redacts_card_data_and_secrets() {
    let request = format!("{:?}", payment());
    assert!(!request.contains("4111111111111111"));
    assert!(!request.contains("\"123\""));
    let client = format!("{:?}", jwt_client(&MockTransport::new()));
    assert!(!client.contains(SECRET));
}

#[test]
fn client_futures_are_send_on_native_targets() {
    fn assert_send<T: Send>(_: &T) {}
    let client = jwt_client(&MockTransport::new());
    let fut = std::future::IntoFuture::into_future(client.payments().create_payment(payment()));
    assert_send(&fut);
}

#[tokio::test]
async fn no_auth_operations_are_not_signed() {
    let mock = MockTransport::new();
    mock.push_json(200, "{}");

    jwt_client(&mock)
        .execute(&probe(&PROBE_NO_AUTH))
        .await
        .unwrap();

    let req = mock.last_request();
    assert!(req.headers().get("authorization").is_none());
    assert_eq!(req.headers()["v-c-merchant-id"], "testrest");
}

#[tokio::test]
async fn accept_header_follows_the_operation() {
    let mock = MockTransport::new();
    mock.push_json(200, "{}").push_json(200, "{}");
    let client = jwt_client(&mock);

    client.execute(&probe(&PROBE_GET)).await.unwrap();
    assert!(
        mock.last_request().headers()["accept"]
            .to_str()
            .unwrap()
            .contains("json")
    );

    let mut csv = probe(&PROBE_GET);
    csv.accept = Some("text/csv");
    client.execute(&csv).await.unwrap();
    assert_eq!(mock.last_request().headers()["accept"], "text/csv");
}

#[tokio::test]
async fn get_with_a_body_sends_it_without_a_digest() {
    let mock = MockTransport::new();
    mock.push_json(200, "{}");
    let mut op = probe(&PROBE_GET);
    op.body = Some(Bytes::from_static(br#"{"q":1}"#));

    jwt_client(&mock).execute(&op).await.unwrap();

    let req = mock.last_request();
    assert_eq!(req.body().as_ref(), br#"{"q":1}"#);
    assert_eq!(
        req.headers()["content-type"],
        "application/json;charset=utf-8"
    );
    assert!(jwt_claims(&req).get("digest").is_none());
}

#[tokio::test]
async fn calls_can_be_awaited_or_sent() {
    let mock = MockTransport::new();
    mock.push_json(200, r#"{"n":1}"#)
        .push_json(200, r#"{"n":2}"#);
    let client = jwt_client(&mock);

    let first = Call::new(&client, probe(&PROBE_GET))
        .map_op(|op| op.query.push(("limit", "5".into())))
        .await
        .unwrap();
    assert_eq!(first["n"], 1);
    assert_eq!(mock.last_request().uri().query(), Some("limit=5"));

    let second = Call::new(&client, probe(&PROBE_GET))
        .send_with_response()
        .await
        .unwrap();
    assert_eq!(second.body["n"], 2);
}

#[test]
fn blocking_calls_are_sent() {
    let mock = MockTransport::new();
    mock.push_json(200, r#"{"n":3}"#);
    let client = BlockingClient::with_transport(
        config(Credentials::jwt_shared_secret(KEY_ID, SECRET).unwrap()),
        mock.clone(),
    );

    let out = Call::new(&client, probe(&PROBE_GET)).send().unwrap();

    assert_eq!(out["n"], 3);
}

#[test]
fn awaited_calls_are_send() {
    fn assert_send<T: Send>(_: &T) {}
    let client = jwt_client(&MockTransport::new());
    let fut = std::future::IntoFuture::into_future(Call::new(&client, probe(&PROBE_GET)));
    assert_send(&fut);
}
