//! Live tests against the Cybersource sandbox (`apitest.cybersource.com`).
//!
//! Ignored by default. Run with:
//!
//! ```sh
//! CYBS_LIVE=1 cargo nextest run --all-features --test live_sandbox --run-ignored only
//! ```
//!
//! Credentials default to Cybersource's public `testrest` sample merchant
//! (from `CyberSource/cybersource-rest-samples-*`). Override with
//! `CYBS_MERCHANT_ID`, `CYBS_KEY_ID` and `CYBS_SHARED_SECRET`.

#![cfg(all(
    not(target_family = "wasm"),
    feature = "reqwest",
    feature = "ureq",
    feature = "http-signature",
    feature = "payments",
    feature = "transactions",
    feature = "capture-context"
))]

mod common;

use cybersource::models::PtsV2PaymentsPost201Response;
use cybersource::transport::{ReqwestTransport, UreqTransport};
use cybersource::{BlockingClient, Client, Config, Credentials, Environment};

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_owned())
}

fn live_config(credentials: fn(&str, &str) -> cybersource::Result<Credentials>) -> Option<Config> {
    if std::env::var("CYBS_LIVE").as_deref() != Ok("1") {
        eprintln!("skipping: set CYBS_LIVE=1 to run live sandbox tests");
        return None;
    }
    let key_id = env_or("CYBS_KEY_ID", "08c94330-f618-42a3-b09d-e1e43be5efda");
    let secret = env_or(
        "CYBS_SHARED_SECRET",
        "yBJxy6LjM2TmcPGu+GaJrHtkke25fPpUX+UY6/L/1tE=",
    );
    Some(
        Config::builder()
            .environment(Environment::Test)
            .merchant_id(env_or("CYBS_MERCHANT_ID", "testrest"))
            .credentials(credentials(&key_id, &secret).unwrap())
            .build()
            .unwrap(),
    )
}

fn jwt(key_id: &str, secret: &str) -> cybersource::Result<Credentials> {
    Credentials::jwt_shared_secret(key_id, secret)
}

fn http_signature(key_id: &str, secret: &str) -> cybersource::Result<Credentials> {
    Credentials::http_signature(key_id, secret)
}

fn assert_authorized(label: &str, resp: &PtsV2PaymentsPost201Response) {
    eprintln!("{label}: id={:?} status={:?}", resp.id, resp.status);
    assert_eq!(
        resp.status.as_deref(),
        Some("AUTHORIZED"),
        "{label}: {resp:?}"
    );
}

async fn authorize_async(
    label: &str,
    credentials: fn(&str, &str) -> cybersource::Result<Credentials>,
) {
    let Some(config) = live_config(credentials) else {
        return;
    };
    let client = Client::new(config, ReqwestTransport::new());
    let resp = client
        .payments()
        .create_payment(common::payment(
            &format!("cybersource-rs-{label}"),
            "100.00",
        ))
        .send_with_response()
        .await
        .unwrap_or_else(|e| panic!("{label}: {e}"));
    eprintln!("{label}: correlation id {:?}", resp.correlation_id());
    assert_authorized(label, &resp.body);
}

fn authorize_blocking(
    label: &str,
    credentials: fn(&str, &str) -> cybersource::Result<Credentials>,
) {
    let Some(config) = live_config(credentials) else {
        return;
    };
    let client = BlockingClient::new(config, UreqTransport::new());
    let resp = client
        .payments()
        .create_payment(common::payment(
            &format!("cybersource-rs-{label}"),
            "100.00",
        ))
        .send()
        .unwrap_or_else(|e| panic!("{label}: {e}"));
    assert_authorized(label, &resp);
}

#[tokio::test]
#[ignore = "hits the Cybersource sandbox; run with CYBS_LIVE=1"]
async fn jwt_hs256_async_authorizes() {
    authorize_async("jwt-async", jwt).await;
}

#[test]
#[ignore = "hits the Cybersource sandbox; run with CYBS_LIVE=1"]
fn jwt_hs256_blocking_authorizes() {
    authorize_blocking("jwt-blocking", jwt);
}

#[tokio::test]
#[ignore = "hits the Cybersource sandbox; run with CYBS_LIVE=1"]
async fn http_signature_async_authorizes() {
    authorize_async("httpsig-async", http_signature).await;
}

#[test]
#[ignore = "hits the Cybersource sandbox; run with CYBS_LIVE=1"]
fn http_signature_blocking_authorizes() {
    authorize_blocking("httpsig-blocking", http_signature);
}

/// Exercises generated operations beyond createPayment: a path parameter
/// (capture), a GET with a JSON body (transaction details) and a text/JWT
/// response (capture context).
#[tokio::test]
#[ignore = "hits the Cybersource sandbox; run with CYBS_LIVE=1"]
async fn generated_operations_round_trip() {
    use cybersource::models::{
        CapturePaymentRequest, GenerateCaptureContextRequest,
        Ptsv2paymentsidcapturesOrderInformation,
        Ptsv2paymentsidcapturesOrderInformationAmountDetails,
    };

    let Some(config) = live_config(jwt) else {
        return;
    };
    let client = Client::new(config, ReqwestTransport::new());

    let auth = client
        .payments()
        .create_payment(common::payment("cybersource-rs-generated", "10.00"))
        .await
        .expect("authorize");
    assert_authorized("generated-auth", &auth);
    let id = auth.id.expect("payment id");

    let capture = client
        .payments()
        .capture_payment(
            id.clone(),
            CapturePaymentRequest {
                order_information: Some(Ptsv2paymentsidcapturesOrderInformation {
                    amount_details: Some(Ptsv2paymentsidcapturesOrderInformationAmountDetails {
                        total_amount: Some("10.00".into()),
                        currency: Some("USD".into()),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .await
        .expect("capture");
    eprintln!("capture: id={:?} status={:?}", capture.id, capture.status);
    assert_eq!(capture.status.as_deref(), Some("PENDING"));

    // Transaction details are indexed asynchronously; allow a short delay.
    let mut details = None;
    for _ in 0..10 {
        match client.transactions().get_transaction(id.clone()).await {
            Ok(d) => {
                details = Some(d);
                break;
            }
            Err(e) if e.api().is_some_and(|a| a.status == 404) => {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
            Err(e) => panic!("get_transaction: {e}"),
        }
    }
    let details = details.expect("transaction details never became available");
    assert_eq!(details.id.as_deref(), Some(id.as_str()));

    let context = client
        .capture_context()
        .generate_capture_context(GenerateCaptureContextRequest {
            client_version: Some("v2".into()),
            target_origins: Some(vec!["https://www.example.com".into()]),
            allowed_card_networks: Some(vec!["VISA".into(), "MASTERCARD".into()]),
            allowed_payment_types: Some(vec!["CARD".into()]),
            ..Default::default()
        })
        .await
        .expect("capture context");
    assert_eq!(
        context.split('.').count(),
        3,
        "capture context is a compact JWT"
    );

    // Verify it against Cybersource's published signing key (fetched live).
    let verified = cybersource::capture_context::CaptureContextVerifier::new()
        .verify(&client, &context)
        .await
        .expect("capture context verifies");
    assert_eq!(verified.iss.as_deref(), Some("Flex API"));
    assert!(verified.client_library().is_some());
}

// ---------------------------------------------------------------------------
// P12 (RS256) and message-level encryption, with Cybersource's public
// `agentic_mid_091225001` sandbox merchant. Needs `cargo xtask sandbox-keys`.
// ---------------------------------------------------------------------------

#[cfg(feature = "p12")]
mod p12_and_mle {
    use std::sync::Mutex;

    use bytes::Bytes;
    use cybersource::config::CertificateRole;
    use cybersource::error::BoxError;
    use cybersource::mle::{MleConfig, ResponseMleKey};
    use cybersource::transport::{HttpTransport, ReqwestTransport};
    use cybersource::{Client, Config, Credentials, Environment};

    const MERCHANT: &str = "agentic_mid_091225001";

    fn key_file(name: &str) -> Vec<u8> {
        let path = format!("{}/target/sandbox-keys/{name}", env!("CARGO_MANIFEST_DIR"));
        std::fs::read(&path)
            .unwrap_or_else(|e| panic!("{path}: {e}; run `cargo xtask sandbox-keys` first"))
    }

    fn live() -> bool {
        let on = std::env::var("CYBS_LIVE").as_deref() == Ok("1");
        if !on {
            eprintln!("skipping: set CYBS_LIVE=1 to run live sandbox tests");
        }
        on
    }

    fn config(mle: Option<MleConfig>) -> Config {
        Config::builder()
            .environment(Environment::Test)
            .merchant_id(MERCHANT)
            .credentials(
                Credentials::jwt_p12(
                    &key_file("agentic_mid_091225001.p12"),
                    "Ap!C38tp12@",
                    MERCHANT,
                )
                .unwrap(),
            )
            .maybe_mle(mle)
            .build()
            .unwrap()
    }

    /// Wraps a transport and keeps the last request and response bodies, to
    /// prove what actually went over the wire.
    #[derive(Default)]
    struct Recording {
        inner: ReqwestTransport,
        sent: Mutex<Option<Bytes>>,
        received: Mutex<Option<Bytes>>,
    }

    impl HttpTransport for Recording {
        async fn send(
            &self,
            request: http::Request<Bytes>,
        ) -> Result<http::Response<Bytes>, BoxError> {
            *self.sent.lock().unwrap() = Some(request.body().clone());
            let response = self.inner.send(request).await?;
            *self.received.lock().unwrap() = Some(response.body().clone());
            Ok(response)
        }
    }

    /// A transaction search: read-only, with a request body (so it can be
    /// encrypted) and optional request and response MLE. Card payments are
    /// not used because the sample merchant is not set up to process them
    /// (the sandbox answers 502 SYSTEM_ERROR, before and after MLE).
    async fn search(client: &Client<Recording>, label: &str) {
        let body = cybersource::models::CreateSearchRequest {
            name: Some(format!("cybersource-rs-{label}")),
            save: Some(false),
            timezone: Some("UTC".into()),
            query: Some("submitTimeUtc:[NOW/DAY-7DAYS TO NOW/DAY+1DAY}".into()),
            offset: Some(0),
            limit: Some(10),
            sort: Some("id:asc,submitTimeUtc:asc".into()),
        };
        let resp = client
            .transactions()
            .create_search(body)
            .await
            .unwrap_or_else(|e| panic!("{label}: {e}"));
        eprintln!(
            "{label}: search {:?} found {:?}",
            resp.name, resp.total_count
        );
        assert_eq!(
            resp.name.as_deref(),
            Some(format!("cybersource-rs-{label}").as_str())
        );
    }

    fn starts_with(body: &Mutex<Option<Bytes>>, prefix: &str) -> bool {
        body.lock()
            .unwrap()
            .as_ref()
            .is_some_and(|b| b.starts_with(prefix.as_bytes()))
    }

    #[tokio::test]
    #[ignore = "hits the Cybersource sandbox; run with CYBS_LIVE=1"]
    async fn jwt_rs256_from_p12_searches() {
        if !live() {
            return;
        }
        let client = Client::new(config(None), Recording::default());
        search(&client, "p12-rs256").await;
        assert!(starts_with(&client.transport().sent, "{\"limit\""));
    }

    #[tokio::test]
    #[ignore = "hits the Cybersource sandbox; run with CYBS_LIVE=1"]
    async fn encrypted_request_searches() {
        if !live() {
            return;
        }
        let client = Client::new(
            config(Some(MleConfig::new().optional_globally(true))),
            Recording::default(),
        );
        search(&client, "request-mle").await;
        assert!(starts_with(
            &client.transport().sent,
            "{\"encryptedRequest\""
        ));
    }

    #[tokio::test]
    #[ignore = "hits the Cybersource sandbox; run with CYBS_LIVE=1"]
    async fn encrypted_request_and_response_search() {
        if !live() {
            return;
        }
        let key = ResponseMleKey::from_p12(
            &key_file("agentic_mid_091225001_mle.p12"),
            "Ap!C38tp12@ML3",
            MERCHANT,
        )
        .unwrap();
        let config = config(Some(
            MleConfig::new()
                .optional_globally(true)
                .response_key(key)
                .response_globally(true),
        ));
        let expiry = config
            .certificate_expiries()
            .into_iter()
            .find(|e| e.role == CertificateRole::ResponseMle)
            .unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if now > expiry.not_after_unix {
            eprintln!("skipping: Cybersource's sample response-MLE certificate has expired");
            return;
        }
        let client = Client::new(config, Recording::default());
        search(&client, "response-mle").await;
        assert!(starts_with(
            &client.transport().sent,
            "{\"encryptedRequest\""
        ));
        assert!(
            starts_with(&client.transport().received, "{\"encryptedResponse\""),
            "the sandbox did not encrypt the response: {:?}",
            client.transport().received.lock().unwrap()
        );
    }
}
