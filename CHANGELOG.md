# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
