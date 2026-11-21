//! Pagination, ETags and the opt-in partner developer id.

#![cfg(all(not(target_family = "wasm"), feature = "tms", feature = "payments"))]

mod common;

use bytes::Bytes;
use cybersource::jose::b64;
use cybersource::transport::MockTransport;
use cybersource::{BlockingClient, Client, Config, Credentials, Environment};

const KEY_ID: &str = "08c94330-f618-42a3-b09d-e1e43be5efda";
const SECRET: &str = "yBJxy6LjM2TmcPGu+GaJrHtkke25fPpUX+UY6/L/1tE=";

fn config(developer_id: Option<&str>) -> Config {
    Config::builder()
        .environment(Environment::Sandbox)
        .merchant_id("testrest")
        .credentials(Credentials::jwt_shared_secret(KEY_ID, SECRET).unwrap())
        .maybe_developer_id(developer_id)
        .build()
        .unwrap()
}

fn page(offset: i64, count: i64, total: i64) -> String {
    format!(r#"{{"offset":{offset},"limit":2,"count":{count},"total":{total},"_embedded":{{}}}}"#)
}

fn offsets(mock: &MockTransport) -> Vec<String> {
    mock.requests()
        .iter()
        .map(|r| r.uri().query().unwrap_or_default().to_owned())
        .collect()
}

#[tokio::test]
async fn walks_pages_until_the_total() {
    let mock = MockTransport::new();
    mock.push_json(200, page(0, 2, 5))
        .push_json(200, page(2, 2, 5))
        .push_json(200, page(4, 1, 5));
    let client = Client::with_transport(config(None), mock.clone());

    let mut pages = client
        .tms()
        .get_customer_payment_instruments_list("cust-1")
        .limit(2)
        .pages();
    let mut counts = Vec::new();
    while let Some(page) = pages.next().await {
        counts.push(page.unwrap().count.unwrap());
    }

    assert_eq!(counts, [2, 2, 1]);
    assert_eq!(
        offsets(&mock),
        ["limit=2", "offset=2&limit=2", "offset=4&limit=2"]
    );
}

#[tokio::test]
async fn stops_on_a_short_page_even_without_a_total() {
    let mock = MockTransport::new();
    mock.push_json(200, r#"{"count":2}"#)
        .push_json(200, r#"{"count":1}"#);
    let client = Client::with_transport(config(None), mock.clone());

    let mut pages = client
        .tms()
        .get_customer_payment_instruments_list("c")
        .limit(2)
        .pages();
    let mut n = 0;
    while let Some(page) = pages.next().await {
        page.unwrap();
        n += 1;
    }

    assert_eq!(n, 2);
}

#[tokio::test]
async fn an_error_ends_the_walk_after_being_reported() {
    let mock = MockTransport::new();
    mock.push_json(200, page(0, 2, 10)).push_json(500, "{}");
    let client = Client::with_transport(config(None), mock.clone());

    let mut pages = client
        .tms()
        .get_customer_payment_instruments_list("c")
        .limit(2)
        .pages();
    assert!(pages.next().await.unwrap().is_ok());
    assert!(pages.next().await.unwrap().is_err());
    assert!(pages.next().await.is_none());
    assert_eq!(mock.requests().len(), 2);
}

#[test]
fn blocking_pages_are_an_iterator() {
    let mock = MockTransport::new();
    mock.push_json(200, page(0, 2, 3))
        .push_json(200, page(2, 1, 3));
    let client = BlockingClient::with_transport(config(None), mock.clone());

    let counts: Vec<i64> = client
        .tms()
        .get_customer_payment_instruments_list("c")
        .limit(2)
        .pages()
        .map(|p| p.unwrap().count.unwrap())
        .collect();

    assert_eq!(counts, [2, 1]);
}

#[tokio::test]
async fn etag_is_exposed_for_conditional_updates() {
    let mock = MockTransport::new();
    mock.push_response(
        http::Response::builder()
            .status(200)
            .header("etag", "\"abc123\"")
            .body(Bytes::from_static(b"{}"))
            .unwrap(),
    );
    let client = Client::with_transport(config(None), mock.clone());

    let resp = client
        .tms()
        .get_customer("cust-1")
        .send_with_response()
        .await
        .unwrap();

    assert_eq!(resp.etag(), Some("\"abc123\""));
}

fn sent_json(mock: &MockTransport) -> serde_json::Value {
    serde_json::from_slice(mock.last_request().body()).unwrap()
}

#[tokio::test]
async fn developer_id_is_added_only_when_configured_and_absent() {
    let mock = MockTransport::new();
    for _ in 0..3 {
        mock.push_json(201, r#"{"status":"AUTHORIZED"}"#);
    }

    let without = Client::with_transport(config(None), mock.clone());
    without
        .payments()
        .create_payment(common::payment("a", "1.00"))
        .await
        .unwrap();
    assert!(
        sent_json(&mock)["clientReferenceInformation"]
            .get("partner")
            .is_none()
    );

    let with = Client::with_transport(config(Some("DEV123")), mock.clone());
    let original = common::payment("b", "1.00");
    with.payments()
        .create_payment(original.clone())
        .await
        .unwrap();
    let sent = sent_json(&mock);
    assert_eq!(
        sent["clientReferenceInformation"]["partner"]["developerId"],
        "DEV123"
    );
    assert_eq!(sent["clientReferenceInformation"]["code"], "b");
    // The JWT digest covers the body actually sent.
    let auth = mock.last_request().headers()["authorization"]
        .to_str()
        .unwrap()
        .to_owned();
    let claims: serde_json::Value =
        serde_json::from_slice(&b64::url_decode(auth.split('.').nth(1).unwrap()).unwrap()).unwrap();
    assert_eq!(
        claims["digest"],
        cybersource::auth::digest::sha256_b64(mock.last_request().body())
    );

    let mut own = common::payment("c", "1.00");
    cybersource::patch!(own, { client_reference_information: { partner: { developer_id: "MINE" } } });
    with.payments().create_payment(own).await.unwrap();
    assert_eq!(
        sent_json(&mock)["clientReferenceInformation"]["partner"]["developerId"],
        "MINE"
    );
}

#[tokio::test]
async fn developer_id_is_not_added_to_bodies_without_the_field() {
    let mock = MockTransport::new();
    mock.push_json(201, "{}");
    let client = Client::with_transport(config(Some("DEV123")), mock.clone());

    let customer = cybersource::build!(cybersource::models::PostCustomerRequest {
        buyer_information: { email: "a@b.example" },
    });
    client.tms().post_customer(customer).await.unwrap();

    assert!(sent_json(&mock).get("clientReferenceInformation").is_none());
}
