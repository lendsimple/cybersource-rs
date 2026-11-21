//! The same authorization with the blocking client (no async runtime).
//!
//! `cargo run --example blocking --features ureq`

#[path = "common/mod.rs"]
mod common;

use cybersource::transport::UreqTransport;
use cybersource::{BlockingClient, payment};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = BlockingClient::new(common::config()?, UreqTransport::new());
    let response = client
        .payments()
        .create_payment(payment! {
            code: "example-blocking",
            amount: "10.00" USD,
            card: { number: "4111111111111111", expiration_month: "12", expiration_year: "2031" },
            bill_to: {
                first_name: "John", last_name: "Doe", address1: "1 Market St",
                locality: "San Francisco", administrative_area: "CA", postal_code: "94105",
                country: "US", email: "test@cybs.com", phone_number: "4158880000",
            },
        })
        .send()?;
    println!("{:?}: {:?}", response.id, response.payment_status());
    Ok(())
}
