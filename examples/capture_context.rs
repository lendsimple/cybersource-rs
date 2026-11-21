//! Microform: create a capture context for the browser and verify it.
//!
//! `cargo run --example capture_context`

#[path = "common/mod.rs"]
mod common;

use cybersource::capture_context::CaptureContextVerifier;
use cybersource::transport::ReqwestTransport;
use cybersource::{Client, build, models};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new(common::config()?, ReqwestTransport::new());

    let jwt = client
        .capture_context()
        .generate_capture_context(build!(models::GenerateCaptureContextRequest {
            client_version: "v2",
            target_origins: ["https://www.example.com"],
            allowed_card_networks: ["VISA", "MASTERCARD", "AMEX"],
            allowed_payment_types: ["CARD"],
        }))
        .await?;

    // Keep one verifier for the application: it caches Cybersource's keys.
    let verifier = CaptureContextVerifier::new();
    let context = verifier.verify(&client, &jwt).await?;
    println!("capture context expires at {}", context.exp);
    println!("load {:?}", context.client_library());
    println!("integrity {:?}", context.client_library_integrity());

    // When the browser posts back its transient token:
    //   let token = context.verify_transient_token(&transient_jwt, now_secs)?;
    //   ...then pay with tokenInformation.transientTokenJwt = token.jwt
    Ok(())
}
