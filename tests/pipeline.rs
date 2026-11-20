//! End-to-end pipeline tests through both clients, using `MockTransport`.

#![cfg(feature = "server")]

use std::borrow::Cow;

use bytes::Bytes;
use cybersource::auth::digest;
use cybersource::clock::FixedClock;
use cybersource::entropy::FixedEntropy;
use cybersource::error::ErrorBody;
use cybersource::jose::b64;
use cybersource::models::{
    AmountDetails, Card, ClientReferenceInformation, CreatePaymentRequest, OrderInformation,
    PaymentInformation,
};
use cybersource::operation::{Operation, OperationMeta, json_decode};
use cybersource::transport::MockTransport;
use cybersource::{BlockingClient, Client, Config, Credentials, Environment, Error};
use http::{HeaderMap, Method, StatusCode};

const KEY_ID: &str = "08c94330-f618-42a3-b09d-e1e43be5efda";
const SECRET: &str = "yBJxy6LjM2TmcPGu+GaJrHtkke25fPpUX+UY6/L/1tE=";

fn config(credentials: Credentials) -> Config {
    Config::builder()
        .environment(Environment::Test)
        .merchant_id("testrest")
        .credentials(credentials)
        .build()
        .unwrap()
}

fn jwt_client(mock: &MockTransport) -> Client<MockTransport> {
    Client::new(
        config(Credentials::jwt_shared_secret(KEY_ID, SECRET).unwrap()),
        mock.clone(),
    )
    .with_clock(FixedClock::from_secs(1_793_865_600))
    .with_entropy(FixedEntropy(vec![0x11]))
}

fn payment() -> CreatePaymentRequest {
    CreatePaymentRequest {
        client_reference_information: Some(ClientReferenceInformation {
            code: Some("TC50171_3".into()),
        }),
        payment_information: Some(PaymentInformation {
            card: Some(Card {
                number: Some("4111111111111111".into()),
                expiration_month: Some("12".into()),
                expiration_year: Some("2031".into()),
                security_code: Some("123".into()),
            }),
        }),
        order_information: Some(OrderInformation {
            amount_details: Some(AmountDetails {
                total_amount: Some("100.00".into()),
                currency: Some("USD".into()),
            }),
            bill_to: None,
        }),
        ..Default::default()
    }
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
        .create_payment(&payment())
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
        sent.get("processingInformation").is_none(),
        "None fields are omitted"
    );
}

#[test]
fn blocking_client_runs_the_same_pipeline() {
    let mock = MockTransport::new();
    mock.push_json(201, AUTHORIZED);
    let client = BlockingClient::new(
        config(Credentials::jwt_shared_secret(KEY_ID, SECRET).unwrap()),
        mock.clone(),
    );

    let resp = client.payments().create_payment(&payment()).unwrap();

    assert_eq!(resp.id.as_deref(), Some("7000000000000000000001"));
    assert!(mock.last_request().headers().contains_key("authorization"));
}

#[cfg(feature = "http-signature")]
#[test]
fn http_signature_request_carries_digest_of_sent_body() {
    let mock = MockTransport::new();
    mock.push_json(201, AUTHORIZED);
    let client = BlockingClient::new(
        config(Credentials::http_signature(KEY_ID, SECRET).unwrap()),
        mock.clone(),
    )
    .with_clock(FixedClock::from_secs(1_793_865_600));

    client.payments().create_payment(&payment()).unwrap();

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

/// A test-only operation exercising query strings, empty bodies and headers.
struct Probe {
    method: Method,
    query: Vec<(&'static str, String)>,
    headers: HeaderMap,
}

static PROBE_GET: OperationMeta = OperationMeta::new("probe", Method::GET, "/probe/v1/items");
static PROBE_POST: OperationMeta = OperationMeta::new("probe", Method::POST, "/probe/v1/items");

impl Operation for Probe {
    type Output = serde_json::Value;

    fn meta(&self) -> &'static OperationMeta {
        if self.method == Method::GET {
            &PROBE_GET
        } else {
            &PROBE_POST
        }
    }
    fn path(&self) -> Cow<'_, str> {
        "/probe/v1/items".into()
    }
    fn query(&self) -> Vec<(&'static str, String)> {
        self.query.clone()
    }
    fn headers(&self) -> HeaderMap {
        self.headers.clone()
    }
    fn decode(&self, _: StatusCode, body: &Bytes) -> cybersource::Result<Self::Output> {
        json_decode(body)
    }
}

fn probe(method: Method) -> Probe {
    Probe {
        method,
        query: Vec::new(),
        headers: HeaderMap::new(),
    }
}

#[tokio::test]
async fn query_is_rfc3986_encoded_and_signed_as_sent() {
    let mock = MockTransport::new();
    mock.push_json(200, "{}");
    let mut op = probe(Method::GET);
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
        .execute(&probe(Method::POST))
        .await
        .unwrap();

    let req = mock.last_request();
    assert_eq!(req.body().as_ref(), b"{}");
    assert_eq!(jwt_claims(&req)["digest"], digest::sha256_b64(b"{}"));
}

#[tokio::test]
async fn operation_headers_cannot_override_authentication() {
    let mock = MockTransport::new();
    mock.push_json(200, "{}");
    let mut op = probe(Method::GET);
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
        .create_payment(&payment())
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
        .create_payment(&payment())
        .await
        .unwrap_err();

    assert!(!err.outcome_unknown());
    let api = err.api().expect("API error");
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
        .create_payment(&payment())
        .await
        .unwrap_err();

    assert!(err.outcome_unknown());
    assert!(!err.api().unwrap().is_retry_safe());
}

#[tokio::test]
async fn transport_failure_means_outcome_unknown() {
    let mock = MockTransport::new();
    mock.push_error("connection reset");

    let err = jwt_client(&mock)
        .payments()
        .create_payment(&payment())
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
        .execute_with_response(&cybersource::operations::CreatePayment { body: &body })
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
    let body = payment();
    let payments = client.payments();
    let fut = payments.create_payment(&body);
    assert_send(&fut);
}
