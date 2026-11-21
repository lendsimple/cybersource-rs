//! Verify a webhook notification, framework-free: give it the request's
//! headers and exact body bytes.
//!
//! `cargo run --example webhook`

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cybersource::webhook::{WebhookError, WebhookVerifier};

/// What your HTTP handler would do with an incoming request.
fn handle(
    verifier: &WebhookVerifier,
    request: &http::Request<Vec<u8>>,
    now: Duration,
) -> Result<(), WebhookError> {
    let notification = verifier.verify_and_parse(request.headers(), request.body(), now)?;
    println!(
        "verified {:?} from webhook {:?}",
        notification.event_type, notification.webhook_id
    );
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The key id and base64 secret from `POST /kms/egress/v2/keys-sym`.
    let verifier = WebhookVerifier::new()
        .key("bf44c857-b182-bb05-e053-34b8d30a7a72", "dGVzdF9rZXk=")?
        .tolerance(Duration::from_secs(300));

    // Cybersource's documented example (signed over a non-JSON payload).
    let documented = http::Request::builder()
        .header(
            "v-c-signature",
            "t=1617830804768;keyId=bf44c857-b182-bb05-e053-34b8d30a7a72;sig=CzHY47nzJgCSD/BREtSIb+9l/vfkaaL4qf9n8MNJ4CY=",
        )
        .body(b"this is a decrypted payload".to_vec())?;
    verifier.verify(
        documented.headers(),
        documented.body(),
        Duration::from_millis(1_617_830_804_768),
    )?;
    println!("documented example verifies");

    // A forged request fails.
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
    let forged = http::Request::builder()
        .header(
            "v-c-signature",
            format!(
                "t={};keyId=bf44c857-b182-bb05-e053-34b8d30a7a72;sig=AAAA",
                now.as_millis()
            ),
        )
        .body(br#"{"eventType":"payments.payments.accept","payload":{}}"#.to_vec())?;
    match handle(&verifier, &forged, now) {
        Err(WebhookError::BadSignature) => println!("forged notification rejected"),
        other => println!("unexpected: {other:?}"),
    }
    Ok(())
}
