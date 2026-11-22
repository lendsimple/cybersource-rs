//! Idiomatic Rust client for the [Cybersource REST API](https://developer.cybersource.com/api-reference-assets/index.html):
//! all 220 operations, generated from Cybersource's own spec, with async,
//! blocking and WebAssembly support.
//!
//! - **Auth:** JWT (shared secret, RSA key or P12) and legacy HTTP Signature,
//!   byte-for-byte compatible with the official SDKs.
//! - **Message-level encryption** (JWE) of requests and responses.
//! - **Macros** for request bodies: [`build!`], [`payment!`], [`capture!`],
//!   [`refund!`], plus compile-time checked [`amount!`]s and [`currency!`]s.
//! - **Helpers:** payment outcomes, pagination, ETags, capture contexts,
//!   webhook signatures, redacted `tracing`.
//! - **Runs on** tokio (or any executor), blocking threads, Cloudflare
//!   Workers, Deno, Node and WASI 0.2.
//!
//! # Quick start
//!
//! ```no_run
//! use cybersource::flows::PaymentOutcome;
//! use cybersource::{Client, Config, Credentials, Environment, payment};
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let config = Config::builder()
//!     .environment(Environment::Sandbox)
//!     .merchant_id("your_merchant_id")
//!     .credentials(Credentials::jwt_shared_secret("key-id", "base64-shared-secret")?)
//!     .build()?;
//! let client = Client::new(config);
//!
//! let response = client
//!     .payments()
//!     .create_payment(payment! {
//!         code: "order-1",
//!         amount: "49.99" USD,
//!         card: { number: "4111111111111111", expiration_month: "12", expiration_year: "2031" },
//!         bill_to: {
//!             first_name: "John", last_name: "Doe", address1: "1 Market St",
//!             locality: "San Francisco", administrative_area: "CA", postal_code: "94105",
//!             country: "US", email: "test@cybs.com", phone_number: "4158880000",
//!         },
//!     })
//!     .await?;
//!
//! // Declines are HTTP 201 too: read the outcome from the body.
//! let outcome = PaymentOutcome::from(&response);
//! if outcome.is_approved() {
//!     println!("authorized: {:?}", response.id);
//! }
//! # Ok(()) }
//! ```
//!
//! Operations are grouped by API area (`client.payments()`, `client.tms()`,
//! `client.reporting()`, ...). Each call takes its required parameters as
//! arguments and optional ones as setters (`.limit(50)`). `.await` it for the
//! body, or use `.send_with_response()` for the status, headers and
//! [`correlation_id`](response::Response::correlation_id) as well. Request
//! and response types live in [`models`].
//!
//! The blocking client has the same API with `.send()` (feature `ureq`):
//!
//! ```no_run
//! # #[cfg(all(feature = "ureq", feature = "transactions"))]
//! # fn run(config: cybersource::Config) -> cybersource::Result<()> {
//! use cybersource::BlockingClient;
//!
//! let client = BlockingClient::new(config);
//! let transaction = client.transactions().get_transaction("7952374019946681903813").send()?;
//! # Ok(()) }
//! ```
//!
//! # Authentication
//!
//! | Credentials | Use |
//! |---|---|
//! | [`Credentials::jwt_shared_secret`] | **Default.** A shared-secret key from the Business Center (HS256 JWT). |
//! | [`Credentials::jwt_p12`] | A P12 key file from the Business Center (RS256 JWT). Needs feature `p12` (default). |
//! | [`Credentials::jwt_rsa_pem`] | The same key as PEM, with its certificate. |
//! | `Credentials::http_signature` | Legacy HTTP Signature (feature `http-signature`). Cybersource is retiring it: switch to JWT by changing only this line, the key ID and secret stay the same. |
//!
//! Signatures cover the exact bytes sent, so bodies are serialized once and
//! never re-encoded. Certificates near expiry can be listed with
//! [`Config::certificate_expiries`].
//!
//! # Message-level encryption
//!
//! Some operations require MLE, and any can opt in. Give the config Cybersource's
//! MLE certificate (and your response key, for encrypted responses):
//!
//! ```no_run
//! # fn run(p12: &[u8]) -> cybersource::Result<()> {
//! use cybersource::mle::{MleConfig, RequestMleCert};
//!
//! let mle = MleConfig::new()
//!     .request_cert(RequestMleCert::from_p12(p12, "password")?)
//!     .optional_globally(true);
//! # let _ = mle; Ok(()) }
//! ```
//!
//! An operation that requires MLE is never sent in plaintext: without a
//! certificate it fails before anything is sent.
//!
//! # Building requests
//!
//! Generated models are plain structs with all-`Option` fields. [`build!`]
//! fills them without the nesting:
//!
//! ```
//! use cybersource::build;
//! use cybersource::models::CreatePaymentRequest;
//!
//! let request = build!(CreatePaymentRequest {
//!     client_reference_information: { code: "order-1" },
//!     order_information: { amount_details: { total_amount: "10.00", currency: "USD" } },
//!     token_information: { transient_token_jwt: "eyJ..." },
//! });
//! assert_eq!(request.client_reference_information.unwrap().code.as_deref(), Some("order-1"));
//! ```
//!
//! [`patch!`] updates an existing value the same way. [`payment!`],
//! [`capture!`], [`refund!`], [`reversal!`] and [`void!`] cover the common
//! payment flows in fewer lines.
//!
//! # Errors and retries
//!
//! [`Error`] separates API errors (with Cybersource's parsed error body and
//! correlation ID) from transport, auth and decoding failures. Two rules
//! matter for money:
//!
//! - A declined payment is **not** an error: it is a 201 with a status. Use
//!   [`flows::PaymentOutcome`].
//! - When [`Error::outcome_unknown`] is true (a timeout, or a 502), the
//!   payment may have gone through. Look it up before retrying. The client
//!   never retries money-moving operations by itself.
//!
//! ```no_run
//! # async fn run(client: cybersource::Client, request: cybersource::models::CreatePaymentRequest) {
//! match client.payments().create_payment(request).await {
//!     Ok(response) => { /* check the outcome */ }
//!     Err(e) if e.outcome_unknown() => { /* look the payment up; do not resend blindly */ }
//!     Err(e) => eprintln!("failed: {e} (correlation id {:?})", e.as_api().and_then(|a| a.correlation_id.as_deref())),
//! }
//! # }
//! ```
//!
//! # More
//!
//! - [`flows`]: payment outcomes, and [`pages()`](flows::Paged) to walk list
//!   operations.
//! - [`capture_context`]: verify Microform, Unified Checkout and Flex API
//!   capture contexts and the transient tokens they produce.
//! - [`webhook`]: verify webhook signatures.
//! - [`flex`]: client-side Flex API tokenization for native clients (no
//!   features, no credentials). Not for web pages: Cybersource rejects
//!   browser callers; web checkouts use Microform or Unified Checkout.
//! - Feature `tracing`: one span per request, with card data and personal
//!   data redacted ([`redact`]).
//!
//! # Targets and features
//!
//! | Target | Transport | Features |
//! |---|---|---|
//! | Native, async | [`ReqwestTransport`](transport::ReqwestTransport) | `reqwest` (default) |
//! | Native, blocking | `UreqTransport` | `ureq` |
//! | Cloudflare Workers, Deno, Node (wasm32) | `FetchTransport` | `fetch` |
//! | WASI 0.2 (wasm32-wasip2) | `WasiTransport` | `wasi` (Rust 1.91.1+) |
//! | Anything else | your own [`HttpTransport`](transport::HttpTransport) | |
//!
//! API groups are features too, so you only compile what you use. The
//! default set is `payments`, `tms` and `capture-context`; `full` enables
//! all of them. TLS is `rustls` (default) or `native-tls`. `rust_decimal`
//! adds conversions for amounts.
//!
//! MSRV: Rust 1.88.

#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(feature = "server")]
pub mod auth;
#[cfg(feature = "server")]
pub mod call;
#[cfg(feature = "server")]
pub mod capture_context;
#[cfg(feature = "server")]
pub mod client;
pub mod clock;
#[cfg(feature = "server")]
pub mod config;
#[cfg(feature = "server")]
pub mod dsl;
pub mod entropy;
pub mod error;
pub mod flex;
#[cfg(feature = "server")]
pub mod flows;
#[cfg(feature = "server")]
mod generated;
pub mod jose;
#[cfg(all(feature = "fetch", target_arch = "wasm32"))]
mod js_fetch;
#[cfg(feature = "server")]
pub mod keys;
#[cfg(feature = "server")]
pub mod mle;
#[cfg(feature = "server")]
pub mod operation;
#[cfg(feature = "server")]
pub mod pipeline;
#[cfg(feature = "server")]
pub mod redact;
#[cfg(feature = "server")]
pub mod response;
#[cfg(feature = "tracing")]
mod telemetry;
#[cfg(feature = "server")]
pub mod transport;
pub mod types;
pub mod validate;
pub mod webhook;

#[cfg(feature = "server")]
pub use call::Call;
#[cfg(all(feature = "server", not(target_family = "wasm")))]
pub use client::BlockingClient;
#[cfg(feature = "server")]
pub use client::Client;
#[cfg(feature = "server")]
pub use config::{Config, Credentials, Environment};
pub use error::{Error, Result};

#[doc(hidden)]
pub mod __private {
    pub use serde;
}
#[cfg(feature = "server")]
pub use generated::{apis, models, operations};

/// Compiles the README's example as a doc test.
#[cfg(all(doctest, feature = "reqwest", feature = "payments"))]
#[doc = include_str!("../README.md")]
pub struct ReadmeDoctests;
