//! Authorize a card payment, interpret the outcome, then capture it.
//!
//! `cargo run --example authorize_and_capture`

#[path = "common/mod.rs"]
mod common;

use cybersource::flows::PaymentOutcome;
use cybersource::{Client, capture, payment};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new(common::config()?);

    let request = payment! {
        code: "example-order-1",
        amount: "49.99" USD,
        card: { number: "4111111111111111", expiration_month: "12", expiration_year: "2031" },
        bill_to: {
            first_name: "John", last_name: "Doe", address1: "1 Market St",
            locality: "San Francisco", administrative_area: "CA", postal_code: "94105",
            country: "US", email: "test@cybs.com", phone_number: "4158880000",
        },
    };

    // Declines are HTTP 201 too: the outcome is in the body.
    let response = client
        .payments()
        .create_payment(request)
        .send_with_response()
        .await?;
    let outcome = PaymentOutcome::from(&response.body);
    println!(
        "status {:?}, correlation id {:?}",
        outcome.status,
        response.correlation_id()
    );

    if outcome.is_declined() {
        println!("declined: {:?} {:?}", outcome.reason, outcome.message);
        return Ok(());
    }
    if outcome.needs_review() {
        println!("held for review; capture later");
        return Ok(());
    }

    let id = response.body.id.expect("an approved payment has an id");
    let captured = client
        .payments()
        .capture_payment(
            id,
            capture! { code: "example-order-1", amount: "49.99" USD },
        )
        .await?;
    println!("capture {:?}: {:?}", captured.id, captured.capture_status());
    Ok(())
}
