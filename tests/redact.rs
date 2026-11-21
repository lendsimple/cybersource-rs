//! Redaction, and what the `tracing` instrumentation actually logs.

#![cfg(all(not(target_family = "wasm"), feature = "payments", feature = "tms"))]

mod common;

use cybersource::redact::redact_json;

#[test]
fn redacted_payment_request() {
    let payment = serde_json::to_value(common::payment("order-1", "10.00")).unwrap();
    insta::assert_json_snapshot!(redact_json(&payment));
}

#[test]
fn redacted_tms_customer() {
    let customer = cybersource::build!(cybersource::models::PostCustomerRequest {
        buyer_information: { email: "jane@example.com", merchant_customer_id: "c-1" },
        client_reference_information: { code: "tms" },
        default_payment_instrument: { id: "PI-1" },
    });
    insta::assert_json_snapshot!(redact_json(&serde_json::to_value(customer).unwrap()));
}

#[cfg(feature = "tracing")]
mod tracing_output {
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    use cybersource::transport::MockTransport;
    use cybersource::{Config, Credentials, Environment};
    use tracing_subscriber::fmt::MakeWriter;

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl Write for Capture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for Capture {
        type Writer = Capture;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    #[test]
    fn logs_metadata_and_redacted_bodies_never_secrets() {
        let capture = Capture::default();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(capture.clone())
            .with_ansi(false)
            .finish();

        let mock = MockTransport::new();
        mock.push_response(
            http::Response::builder()
                .status(201)
                .header("v-c-correlation-id", "corr-xyz")
                .body(bytes::Bytes::from_static(
                    br#"{"id":"1","status":"AUTHORIZED","paymentInformation":{"card":{"number":"411111XXXXXX1111"}}}"#,
                ))
                .unwrap(),
        );
        let config = Config::builder()
            .environment(Environment::Test)
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
        let client = cybersource::BlockingClient::new(config, mock.clone());

        tracing::subscriber::with_default(subscriber, || {
            client
                .payments()
                .create_payment(super::common::payment("order-1", "10.00"))
                .send()
                .unwrap();
        });

        let log = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
        for expected in [
            "createPayment",
            "corr-xyz",
            "status=201",
            "request body",
            "response body",
            "[REDACTED]",
        ] {
            assert!(log.contains(expected), "log lacks {expected:?}:\n{log}");
        }
        for secret in [
            "4111111111111111",
            "\"securityCode\":\"123\"",
            "John",
            "test@cybs.com",
            "Bearer",
            "eyJ",
        ] {
            assert!(!log.contains(secret), "log leaks {secret:?}:\n{log}");
        }
    }
}
