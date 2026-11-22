# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Request validation. Request bodies are checked against the spec before
  they are sent: string lengths, patterns, numeric ranges, list sizes and
  required fields. A body that breaks them fails with the new
  `Error::Validation`, whose `ValidationError::violations()` gives every
  problem with its JSON field path, and nothing is sent. It is on by
  default; `Config::builder().validate_requests(false)` turns it off.
  Every generated request model implements `cybersource::validate::Validate`,
  so a body can also be checked by hand with `.validate()`.
- `Operation::validate`, which the pipeline runs before serializing the
  body. Hand-written operations inherit a default that accepts anything.

### Notes

- Patterns are compiled with the `regex` crate, now a dependency of the
  `server` feature. The spec's patterns are written for Java and
  JavaScript; those Rust cannot compile as written are repaired or skipped
  in `spec/codegen.toml`.
- Constraints that Cybersource's own request examples break (for example
  2-character `administrativeArea` against "NSW", or 30-character sender
  names against 35-character ones) are not enforced, so validation does not
  reject requests Cybersource documents as valid.

## [0.1.0] - 2026-11-21

First release.

### Added

- The whole Cybersource REST API: 220 operations and 2,068 models,
  generated from the spec in the official Python SDK 0.0.81. Each API area
  has a feature flag.
- `Client` (async) and `BlockingClient`. `Client::new(config)` sends
  through reqwest and `BlockingClient::new(config)` through ureq;
  `with_transport` takes any other transport. The environment defaults to
  `Environment::Sandbox`, so production is always chosen explicitly.
  Operations are called through `Call` builders: await them, or call
  `.send()`. `send_with_response` adds the status, headers, correlation ID
  and ETag.
- Authentication: JWT with a shared secret (HS256), or with an RSA key or
  P12 file (RS256). Legacy HTTP Signature is behind `http-signature`. All
  of them are checked against vectors from the official SDK.
- Message-level encryption (RSA-OAEP-256 and A256GCM) of requests and
  responses, configurable per operation. Operations that require it are
  never sent in plaintext.
- Macros for request bodies: `build!` and `patch!`. Shortcuts for payment
  flows: `payment!`, `capture!`, `refund!`, `reversal!` and `void!`.
  Compile-time checked `amount!` and `currency!`.
- Typed payment statuses and `PaymentOutcome`. `Error::as_api` gives the
  API error with its status and body. `Error::outcome_unknown`
  flags timeouts and 5xx responses, and `ApiError::is_retry_safe`
  identifies operations that move money.
- Pagination (`Paged`/`Pager`), ETags, and opt-in `developerId`.
- Capture-context and transient-token verification (Microform, Unified
  Checkout and Flex API), with RS256 pinned and `exp` checked.
- Client-side Flex API tokenization (`flex`), which needs no features and
  no credentials. It is for native clients, because Cybersource rejects
  browser callers.
- Webhook signature verification.
- `tracing` spans, with card data, personal data and credentials redacted.
- Transports: `reqwest` (async; native and wasm), `ureq` (blocking),
  `fetch` (Cloudflare Workers, Deno and Node) and `wasi` (WASI 0.2).

[Unreleased]: https://github.com/lendsimple/cybersource-rs/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/lendsimple/cybersource-rs/releases/tag/v0.1.0
