# Cybersource Rust Client: Implementation Plan

## Context

No Rust SDK for the Cybersource REST API exists. A crates.io search for "cybersource" returns nothing. The only Rust code found is juspay/hyperswitch's hand-written connector, which supports HTTP Signature only and has bugs.

We are building `cybersource`, an idiomatic Rust client with these properties:
- It covers the **full API surface**, generated from Cybersource's official spec.
- It supports **async, blocking and WebAssembly**: edge runtimes (Cloudflare Workers) and WASI p2 get the full client. The **browser gets client-side features only**: parsing a capture context and tokenizing card data into a transient token. No merchant credentials are ever compiled into a browser build.
- **JWT is the default auth**, plus **Message-Level Encryption (MLE)**. HTTP Signature is kept as a deprecated legacy option, because Cybersource sunsets it in March 2027.
- It has a **declarative DSL** for building requests, plus macros, open enums and typed helpers.

Decisions already confirmed with the user:
- Full-spec codegen.
- Auth: HTTP Signature, JWT and MLE. OAuth and mutual TLS are out of scope.
- WASM targets: edge and WASI (full client), and the browser (client-side tokenization only; see §1.9).
- A **single published crate** with feature flags.
- JWT-first, HTTP Signature legacy.
- A full declarative DSL.
- developerId injection is opt-in.
- Crate name `cybersource`, MIT/Apache-2.0, edition 2024. MSRV is 1.88: it was planned as 1.85, but `rsa` 0.10 needs 1.87 and current `sha2` needs 1.88.

---

## 1. Research findings that drive the design

### 1.1 The spec

The official spec is `generator/cybersource-rest-spec.json` in each official SDK repo (Java/C#/Python/Node/PHP), for example `CyberSource/cybersource-rest-client-java`.
- **Format.** Swagger **2.0**, about 21.6 MB, titled "CyberSource Merged Spec". `info.version` is always `0.0.1`, so we track releases by SDK tag.
- **Size.** 176 paths, 221 operations, about 80 tags.
- **Every schema is inline.** It has **zero `definitions` and zero `$ref`**. There are about 8,088 inline object schemas; 7,069 have a `title`, which gives about 2,207 unique titles. The official SDKs generate about 2,165 models.
- **Title collisions.** A few titles map to *different* shapes, for example `ptsV2CreditsPost400Response`, `ptsV2CreditsPost502Response`, `reportingV3PaymentBatchSummariesGet200Response` and `PtsV2PaymentsPost201ResponseLinksSelf`. About 1,019 objects have no title.
- **Almost no enums.** There are only 13 `enum` keywords. Statuses such as `AUTHORIZED` and `DECLINED` are documented only in `description` text.
- **Constraints and quirks.** No `allOf`, `oneOf` or discriminators. 299 `additionalProperties` (maps). Amounts are **strings** (max length 19). Non-standard `format` values appear (`currency`, `decimal`, `ISO 3166-1-alpha2`).
- **Per-operation metadata** lives in `x-devcenter-metaData`:
  - `mleForRequest` / `mleForResponse` take the values `mandatory`, `optional` or `false`. Request MLE: 32 mandatory, 77 optional.
  - Other fields: `authorizationType`, `noAuth`, `disableDefaultMerchantCreds`.
  - Other extensions: `x-streaming`, `x-custom-headers`, `x-queryParameterDefaults`, `x-depends`.
- **Operation naming problems.** `createSubscription`, `getAllSubscriptions` and `getSubscription` are duplicated between Recurring Billing and Reporting. `PUT …/webhooks/{id}/status` has no `operationId`. Five `/icc` GET operations declare request bodies.
- **Mixed media types**:
  - JSON and HAL JSON (about a dozen spellings).
  - `application/jwt` for capture-context sessions, where the body is a bare JWT string.
  - `application/jose` for the TMS payment-credentials JWE.
  - CSV, XML and PDF downloads (report downloads, batch details, Secure File Share).
  - Some operations declare no `produces` or `consumes`.
- **No off-the-shelf generator fits.** progenitor is OpenAPI-3 only. openapi-generator's Rust output can't name inline schemas properly and has no auth or MLE hooks. **We will write a custom `xtask` generator.**

### 1.2 Hosts
- `apitest.cybersource.com` (test) and `api.cybersource.com` (production). India production is `api.in.cybersource.com`.
- Flex public keys are at `https://{host}/flex/v2/public-keys/{kid}`. This endpoint is unauthenticated and not in the spec.
- An optional "intermediate host" can be the URL actually dialled, but the signed `request-host` is still the real Cybersource host.
- The webhook product-list path differs between test and production.

### 1.3 HTTP Signature (legacy)

Every SDK produces the same bytes.

**Signing string.** Lines are joined with `\n`, with no trailing newline:
```
host: {host}
date: {IMF-fixdate, e.g. Thu, 05 Nov 2026 08:00:00 GMT}
request-target: {lowercase method} {path?query exactly as sent}
digest: SHA-256={b64(sha256(body))}          ← POST/PUT/PATCH only
v-c-merchant-id: {portfolio_id if meta-key else merchant_id}
```

**Header.**
```
signature: keyid="{key_id}", algorithm="HmacSHA256", headers="host date request-target[ digest] v-c-merchant-id", signature="{b64(HMAC-SHA256(b64decode(secret), signing_string))}"
```
- The pseudo-header is `request-target`, **without parentheses**. Cybersource issued a 2024 notice saying `(request-target)` fails.
- With a **meta key**, the *signed* `v-c-merchant-id` is the portfolio ID, but the `v-c-merchant-id` *header* actually sent is the transacting merchant ID.
- Headers sent: `host`, `date`, `v-c-merchant-id`, `digest` (on requests with a body) and `signature`.
- Where the SDKs disagree, we take the safe option:
  - **Query encoding:** RFC 3986 with `%20` for spaces. Sign the exact query from the same `http::Uri` that goes on the wire.
  - **Date:** pad single-digit days to two digits.
  - **Empty POST bodies:** never send them; serialize as `{}`.

### 1.4 JWT v2 (the default)

**Header.** `{"alg":"RS256"|"HS256","kid":…,"typ":"JWT"}`.
- **HS256 (shared secret, the recommended migration path).** The key is `b64decode(secret)` and `kid` is the key id.
- **RS256 from a P12.**
  - `kid` is the **`serialNumber` attribute (OID 2.5.4.5) of the subject DN**, *not* the X.509 serial number. The Java and C# fallbacks disagree here, so we error instead of falling back.
  - The certificate whose CN equals the merchant ID (or the portfolio ID with a meta key) holds the key.
  - The password defaults to the merchant ID.

**Claims.**
- Always: `iat`, `exp = iat + 120`, `iss` (merchant ID, or portfolio ID with a meta key), `jti` (UUIDv4 format from 16 random bytes), `v-c-jwt-version: "2"`, `v-c-merchant-id`, `request-host`, `request-method` (uppercase, matching the majority of SDKs) and `request-resource-path` (path plus query).
- On requests with a body: `digest` (plain b64 of SHA-256, **no** `SHA-256=` prefix) and `digestAlgorithm: "SHA-256"`.
- With response MLE: `v-c-response-mle-kid` and `v-c-response-mle-algo: "RSA-OAEP-256"`.

Sent as `Authorization: Bearer <jws>`. A fresh JWT is generated per request, with no caching. The JWT signs the body **after** MLE wrapping.

### 1.5 Message-Level Encryption (JWE)

**Request.**
- Compact JWE with header `{"alg":"RSA-OAEP-256","enc":"A256GCM","kid":<CYBS cert DN serialNumber>,"iat":<secs>,"cty":"application/json"}`.
- The body becomes `{"encryptedRequest":"<jwe>"}`.
- The encryption certificate is alias `CyberSource_SJC_US` inside the merchant P12. With a shared secret it must be supplied separately as PEM.

**Response.**
- The JWT carries `v-c-response-mle-kid`. The body comes back as `{"encryptedResponse":"<jwe>"}` on **both success and error** responses.
- It is decrypted with the merchant's response-MLE private key, from a P12, PKCS#8 or PEM.

**Policy for each operation.**
- Mandatory operations encrypt unless explicitly disabled.
- Optional operations encrypt only if enabled globally.
- A per-operation override map beats both. Reject any configuration in which MLE would be needed under HTTP Signature, instead of silently sending plaintext the way the SDKs do.

### 1.6 Response semantics
- **Declines are 201s.** `POST /pts/v2/payments` returns **201 for declines**, with `status` such as `DECLINED`, `AUTHORIZED_PENDING_REVIEW`, `AUTHORIZED_RISK_DECLINED` or `INVALID_REQUEST`, and `errorInformation.reason`. These are *successful* HTTP responses. Decision Manager's 202 with `REJECT` behaves the same way.
- **Error-body shapes differ by API.**
  - **PTS:** `{submitTimeUtc,status,reason,message,details[{field,reason}]}`.
  - **TMS:** `{errors:[{type,message,details[{name,location}]}]}`.
  - Reporting and webhooks have their own shapes.
- **A 502 means the outcome is unknown.** Its body is `SERVER_ERROR` with reason `SYSTEM_ERROR`, `SERVER_TIMEOUT` or `SERVICE_TIMEOUT`. It must not be treated as a failed payment.
- **Never auto-retry money-moving POSTs.** The Java SDK keeps a list of these paths: payments, captures, refunds, reversals, credits, payouts and push/pull funds.
- **TMS conventions.**
  - Optional `profile-id` header (36 characters).
  - `ETag` / `if-match` on its 5 PATCH operations, with 412 on mismatch.
  - Pagination is `offset`/`limit` with HAL `_links.next` and `X-Total-Count`.
- **Response headers.** `v-c-correlation-id`, which some APIs spell `v-c-correlationid`, and `uniqueTransactionID`.
- **Lenient decoding.** The API sometimes sends numbers or booleans where the spec says string, and the C# SDK added lenient converters for exactly this. We decode leniently too.
- **Duplicate requests.** Payments have no idempotency header. Duplicates are caught through `clientReferenceInformation.code`, which gives a `DUPLICATE_REQUEST` 400.

### 1.7 Extras outside the spec
- **Capture context (Microform / Unified Checkout).**
  - The response is a JWT. Verify it with RS256 using the JWK from `/flex/v2/public-keys/{kid}`, then cache the key.
  - **The SDKs do not check `exp` or pin the algorithm. We do both.**
- **Webhooks.**
  - The header is `v-c-signature: t=<ms>;keyId=<uuid>;sig=<b64>`.
  - The signature is `HMAC-SHA256(b64decode(key), t + "." + raw_body)`, compared in constant time.
  - No official SDK implements this. We will.
- **Logging.** Redact PII using the SDKs' field lists: securityCode, number, cardNumber, account, routingNumber, expiration fields, email, names, phoneNumber, token, encryptedRequest/encryptedResponse and others. Also redact the `Authorization` and `Signature` headers; Java leaks both.

### 1.8 SDK design flaws to avoid
- **Global state.** Static key caches keyed only by merchant ID let one merchant's keys collide with another's. A shared `Configuration` led to requests signed with the wrong headers. Mutable status fields on the API object are not thread-safe.
- **Silent failures.** Auth or certificate failures are logged and swallowed, which leaves a null `Authorization` header. MLE quietly falls back to plaintext.
- **Hidden mutation.** The SDKs inject developerId into the caller's request object.
- **Hard limits and dead options.** Timeouts can't go below 10 s. Config keys such as `solutionId` and `retryEnabled` do nothing. All configuration is stringly-typed.
- **Fragile key matching.** Certificates are matched by CN equality but private keys by `contains`. Charset depends on the platform.
- **No cancellation** (C#), and sync calls blocking on async internally.

### 1.9 Client-side tokenization (Flex API direct, for the browser)

Sources: the Digital Accept / Flex guide (revision 26.11.01), the official spec, Cybersource's own iOS SDK (`CyberSource/flex-api-ios-sdk`, the only official direct client), the Microform JS bundles, and live unauthenticated probes. **Confirmed** facts come from those sources; **inferred** facts are marked.

**Support status. Read this first.**
- The guide says twice: *"Flex API is not designed to be used from the browser. For securing payment information from the browser, please see the Microform Integration product."* The direct protocol works from a browser, but **Cybersource does not support that use**. The only official direct client is native iOS.
- **PCI scope (inferred).** Microform and Unified Checkout qualify merchants for SAQ A because their iframes are hosted by Cybersource. A merchant page whose own JS or wasm touches the card number is at least **SAQ A-EP**.
- So the browser feature is opt-in and clearly labelled. The docs recommend Microform for typical web checkouts, and position this feature for merchants who knowingly accept A-EP scope, and for IoT/kiosk/embedded webviews where Microform doesn't fit.

**Flow.**
1. **Server, authenticated.** The merchant server calls `POST /flex/v2/sessions` with the full client. It lists the fields to capture as `{"required": bool}` flags: card `number`, `securityCode`, `expirationMonth`, `expirationYear`, `type`; optional `amountDetails`; optional `billTo` and `shipTo` addresses. The response is a capture-context JWT, valid for 15 minutes. This endpoint has no bank/ACH fields.
2. **Browser.** Parse the capture context. Build the plaintext, encrypt it to the one-time key embedded in the context, and POST it to the tokens endpoint with **no auth header**. The response is a transient-token JWT.
3. **Server.** Verify the transient token, then use it in `tokenInformation.transientTokenJwt` (or `.jti`) on a payment.

**Capture-context JWT (confirmed).**
- Header: `{"kid":"<short long-term key id, e.g. zu, 3g>","alg":"RS256"}`.
- Claims:
  - `iss: "Flex API"`, plus `iat`, `exp` (iat + 900) and `jti`.
  - `flx`: `{ path: "/flex/v2/tokens", origin, data: <opaque>, jwk: {kty:"RSA", e, n, use:"enc", kid:<32-char one-time kid>} }`.
  - `ctx`: `[{type, data}]`. The type tells you which product made the context:
    - `api-0.1.0` from `/flex/v2/sessions`; its data is `{requiredFields, optionalFields}`.
    - `mf-2.1.0` from Microform.
    - `gda-*` from Unified Checkout.
- The guide warns twice that the JWT "can expand to contain additional data elements", so **parse permissively**.

**Tokens request.**
- **URL (confirmed):** `flx.origin + flx.path`, for example `https://testflex.cybersource.com/flex/v2/tokens`. Use the values from the context; never hardcode them.
- **Method:** `POST`, unauthenticated.
- **Body.** The endpoint accepts two encodings (confirmed live):
  - the iOS SDK's `{"keyId":"<compact JWE>"}` with `Content-Type: application/json; charset=utf-8`;
  - the raw JWE with `Content-Type: application/jwt`.

  **We use the iOS SDK's format**, because it is the only official client.
- **JWE (confirmed).** Header exactly `{"kid":"<flx.jwk.kid>","enc":"A256GCM","alg":"RSA-OAEP"}`.
  - **The key wrap is RSA-OAEP with SHA-1, not the SHA-256 that MLE uses.** The JWE code therefore supports both algorithms.
  - Standard compact JWE, with the base64url header as the AAD.
- **Plaintext (confirmed in the guide):**
  ```json
  {"data":{"paymentInformation":{"card":{"number":"…","expirationMonth":"12","expirationYear":"2031","securityCode":"…","type":"001"}},
           "orderInformation":{…optional…}},
   "context":"<the whole capture-context JWT>","index":0}
  ```
  - `index` must be 0.
  - The fields must match what the session asked for.
  - The iOS SDK also adds `iat` and a random 32-character `jti`; we do the same.
- **CORS (confirmed live).** Preflight returns 204, and both the preflight and the POST echo any `Origin`. No `Access-Control-Expose-Headers` is sent, so browser code **cannot read the `Digest` response header**. Native callers can, so we verify it only where it is readable.

**Response.**
- **Success.** The body is the raw transient-token JWT (RS256).
  - Header: `kid` is the same one-time kid.
  - Claims: `iss: "Flex/NN"`, `iat`, `exp` (iat + 900), a 64-character `jti`, and `type`.
  - Newer tokens also carry `content.paymentInformation.card.{number:{maskedValue,bin,detectedCardTypes}, expirationMonth, expirationYear, type}`.
  - (Inferred) the content type is `application/jwt`.
- **Errors.** HTTP 400, `application/json`. The JSON-request format returns `{"responseStatus":{status, reason:"VALIDATION_ERROR", message, correlationId, details[{location,message}]}, "_links"}`. Reasons also include `CAPTURE_CONTEXT_INVALID` and `CAPTURE_CONTEXT_EXPIRED`.

**Verification limits in the browser.**
- `GET /flex/v2/public-keys/{kid}` returns **no CORS headers**, so the browser can't fetch the long-term keys.
- The capture-context signature can only be checked in the browser against embedded long-term public keys, as the iOS SDK does (kids `3g`, `zu`, `ln`, `wf`). That set is incomplete; live contexts also use `j4` and `sn`.
- **The browser therefore checks `exp` and the context structure only, and signature verification is optional and best-effort.**
- **The authoritative check of the transient token always happens on the server**, through `capture_context.rs`, which fetches the key from `/public-keys`.

**Scope.**
- **v0.1 tokenizes only `api-*` contexts**, the ones from `/flex/v2/sessions`, whose plaintext format is documented.
- `mf-*` (Microform) and `gda-*` (Unified Checkout) contexts are **rejected** with a clear error. Their plaintext formats (`{"data":{"CARD":{…}}}`, and `CHECK` for eCheck) are known only from third-party reverse engineering, and those products are meant to be used through their own JS.

**Unconfirmed; verify against the sandbox in Stage 5.**
- The success content type.
- Whether the flat dotted-key `data` shape from the iOS README is also accepted. We send the nested shape the guide documents.
- Whether `flx.jwk` can verify the transient token, as the guide implies even though the key is marked `use:"enc"`.

---

## 2. Architecture

### 2.1 Principles
1. **Sans-IO core.** Building, signing, encrypting, decrypting and parsing a request are pure functions over `http::Request<Bytes>` and `http::Response<Bytes>`. Time and randomness are injected. There is no filesystem access in the core.
2. **Pluggable transports.** An async trait and a blocking trait. **No `maybe-async`**, because its features are non-additive. **No hidden tokio runtime.**
3. **Immutable, per-client configuration.** `Arc<ClientInner>` holds parsed keys. There are no globals, and every client is `Clone + Send + Sync` (except on WASM).
4. **Fail fast.** Configuration is validated at build time. Every crypto, auth or MLE failure is a typed error.
5. **Generated code is checked in** and reviewable. CI checks that regenerating produces no diff.
6. **Credentials stay server-side.** Everything that holds merchant secrets sits behind the `server` feature: `Client`, auth, keys, MLE and generated operations. A browser build uses `default-features = false, features = ["browser"]`, so secrets, signing code and the 2,200 generated models are absent from it, not just unused. Shared JOSE primitives live in `jose/` and need neither feature.

### 2.2 Crate layout

The published library is one crate. `xtask` is an unpublished workspace member.
```
cybersource-rs/
├── Cargo.toml                 # [workspace] members = [".", "xtask"]; package `cybersource`
├── spec/
│   ├── cybersource-rest-spec.json      # vendored, with spec/SOURCE.md (repo, tag, sha256)
│   └── codegen.toml                    # overrides: renames, collisions, enums, groups, sensitive fields
├── xtask/                     # `cargo xtask codegen | check-codegen | vectors`
│   └── src/{main.rs, spec.rs, hoist.rs, naming.rs, types.rs, enums.rs, emit_models.rs, emit_ops.rs, groups.rs}
├── src/
│   ├── lib.rs                 # re-exports, prelude, feature docs
│   ├── config.rs              # Config, ConfigBuilder, Environment, Credentials, MetaKey, MleConfig
│   ├── error.rs               # Error, ApiError, ErrorBody variants
│   ├── clock.rs               # Clock trait + SystemClock (web-time) + FixedClock (tests)
│   ├── jose/{mod.rs, b64.rs, jws.rs, jwe.rs, jwk.rs} # shared: compact JWS (HS256/RS256), JWE (RSA-OAEP & RSA-OAEP-256 + AxxxGCM), RSA JWK
│   ├── auth/{mod.rs, digest.rs, jwt.rs, http_signature.rs}   # [server]
│   ├── keys/{mod.rs, pem.rs, p12.rs, x509.rs}       # [server] DN serialNumber/CN extraction, key store
│   ├── mle/{mod.rs, policy.rs}                      # [server] uses jose::jwe
│   ├── flex/                                        # [browser] client-side tokenization (§1.9)
│   │   ├── context.rs         # CaptureContext::parse (permissive), exp check, ctx type, optional sig check
│   │   ├── long_term_keys.rs  # embedded Flex long-term public keys (best-effort verification)
│   │   ├── tokenize.rs        # CardData → plaintext → JWE → POST flx.origin+flx.path → TransientToken
│   │   ├── token.rs           # TransientToken (raw JWT + decoded, unverified claims)
│   │   └── bindings.rs        # [browser-bindings] wasm-bindgen exports for JS callers
│   ├── operation.rs           # Operation trait, OperationMeta, MlePolicy, BodyKind, ResponseKind
│   ├── pipeline.rs            # prepare(op) → Request; finish(op, Response) → Output (pure)
│   ├── client.rs              # Client<T: HttpTransport>, BlockingClient<T: BlockingHttpTransport>
│   ├── response.rs            # Response<T> { status, headers, correlation_id, body }
│   ├── transport/{mod.rs, reqwest.rs, ureq.rs, worker.rs, wasi.rs, mock.rs}
│   ├── types/{mod.rs, amount.rs, currency.rs, open_enum.rs, status.rs, link.rs, lenient.rs}
│   ├── dsl.rs                 # build!/patch!/build_with! macros + per-flow sugar macros
│   ├── flows/                 # hand-written helpers: payment outcome, pagination, TMS etag
│   ├── capture_context.rs     # [server] authoritative verification of capture-context / transient-token JWTs (JWK fetch + cache)
│   ├── webhook.rs             # v-c-signature verification
│   ├── redact.rs              # PII-redacting JSON walker + header redaction (tracing feature)
│   └── generated/             # @generated — DO NOT EDIT
│       ├── mod.rs
│       ├── models/{mod.rs, <group>.rs …}     # structs cfg-gated by owning feature(s)
│       ├── operations/<group>.rs             # one struct per operation implementing Operation
│       └── apis/<group>.rs                   # api_group! invocations → client.payments().create_payment(..)
├── tests/{auth_vectors.rs, jwe.rs, pipeline.rs, dsl.rs, codegen_snapshots.rs, live_sandbox.rs, wasm.rs}
├── tests/vectors/*.json       # known-answer vectors produced from official SDKs (with provenance)
└── examples/{authorize_and_capture.rs, blocking.rs, tms_customer.rs, capture_context.rs, webhook.rs, worker/, browser_tokenize/}
```

### 2.3 Core types (sketch)
```rust
pub struct OperationMeta {
    pub id: &'static str,                // "createPayment" (deduped: "rbs_createSubscription")
    pub method: http::Method,
    pub path_template: &'static str,
    pub mle_request: MlePolicy,          // Mandatory | Optional | Never  (from x-devcenter-metaData)
    pub mle_response: MlePolicy,
    pub retry_safe: bool,                // false for money-movement POSTs
    pub response: ResponseKind,          // Json | Jwt | Jose | Text | Bytes
    pub error_body: ErrorFlavor,         // Pts | Tms | Reporting | Generic
    pub no_auth: bool,
}

pub trait Operation {                                       // as built in Stage 1
    type Output;
    fn meta(&self) -> &'static OperationMeta;               // a `static` per operation
    fn path(&self) -> Cow<'_, str>;                         // path params percent-encoded (RFC 3986)
    fn query(&self) -> Vec<(&'static str, String)> { vec![] }
    fn headers(&self) -> HeaderMap { HeaderMap::new() }     // profile-id, if-match, …
    fn body(&self) -> Result<Option<Bytes>> { Ok(None) }    // serde_json::to_vec once
    fn decode(&self, status: StatusCode, body: &Bytes) -> Result<Self::Output>;
}

#[cfg(not(target_family = "wasm"))] pub trait MaybeSend: Send {}
#[cfg(target_family = "wasm")]      pub trait MaybeSend {}

pub trait HttpTransport {
    type Error: std::error::Error + MaybeSend + Sync + 'static;
    fn send(&self, req: http::Request<Bytes>)
        -> impl Future<Output = Result<http::Response<Bytes>, Self::Error>> + MaybeSend;
}
pub trait BlockingHttpTransport { /* same, synchronous */ }
```

**Pipeline** (`pipeline.rs`, pure, and shared by both clients):
1. Build the URI from host, path and query, once.
2. Serialize the body to bytes, and apply opt-in developerId injection on a *copy*.
3. Resolve the MLE policy. If request MLE applies, wrap the body as `{"encryptedRequest": JWE}`.
4. Sign the request with JWT or HTTP Signature over those exact bytes and that exact target. Set `v-c-merchant-id`, `v-c-client-id: cybersource-rs-{ver}` (not `cybs-rest-sdk-…`, which would pass this crate off as an official SDK) and `User-Agent`.
5. Send it through the transport.
6. Decrypt the response if its body is exactly `{"encryptedResponse": "<string>"}`. Then classify the status:
   - A 2xx is passed to `Op::decode`.
   - Anything else becomes `Error::Api { status, body: ErrorBody, correlation_id, raw }`.

### 2.4 Public API shape
```rust
let client = cybersource::Client::builder()
    .environment(Environment::Test)
    .merchant_id("testrest")
    .jwt_shared_secret(key_id, SecretString::from(secret))   // or .jwt_p12(bytes, password) / .http_signature(..)
    .mle(MleConfig::request_optional_globally().response(resp_key))
    .transport(ReqwestTransport::default())
    .build()?;                                               // validates everything up front

let resp = client.payments().create_payment(&req).await?;       // -> PtsV2PaymentsPost201Response
let full = client.execute_with_response(ops::CreatePayment::new(&req)).await?; // Response<T> w/ headers
let blocking = cybersource::BlockingClient::builder()/* … */.transport(UreqTransport::default()).build()?;
blocking.payments().create_payment(&req)?;
```
- **Per-tag accessors.** `client.payments()`, `.tms()`, `.reporting()` and the rest are generated through one macro, `api_group!`, which emits the async methods for `Client` and the blocking methods for `BlockingClient` from a single list.
- **Errors.** `Error` is `#[non_exhaustive]` with these variants: `Config`, `Auth`, `Mle`, `Transport(Box<dyn Error+Send+Sync>)`, `Api(ApiError)`, `Decode { body_snippet, source }` and `CaptureContext`. Helper methods include `is_retry_safe()` and `outcome_unknown()`, which is true for a 502 or a timeout on a money-movement POST.
- **Payment outcomes.** `PaymentOutcome::from(&resp)` gives a typed open-enum `PaymentStatus`, the `errorInformation.reason`, and `.is_approved()` / `.needs_review()` / `.is_declined()`.

### 2.4a Browser API (the `browser` feature)
```rust
use cybersource::flex::{CaptureContext, CardData, FlexError};

// context_jwt was minted server-side by client.capture_context().generate_flex_api_capture_context(..)
let ctx = CaptureContext::parse(&context_jwt)?;   // permissive claims; rejects non-`api-*` ctx types
ctx.ensure_fresh(now)?;                            // exp/iat check with leeway; optional ctx.verify_embedded()?
let card = CardData::builder()
    .number(SecretString::from(pan))              // zeroized after encryption; Debug is redacted
    .expiration_month("12").expiration_year("2031")
    .security_code(SecretString::from(cvv))
    .build();
let token = ctx.tokenize(&card).await?;            // POST flx.origin+flx.path; returns TransientToken
send_to_merchant_server(token.as_str());           // server verifies it, then pays with it
```
- **Card data.** `CardData` covers the card fields plus optional `bill_to`, `ship_to` and `amount`. Before sending anything, `tokenize` checks it against the context's `requiredFields` and `optionalFields`, so a missing required field fails locally instead of returning a 400.
- **Errors.** `FlexError` is `#[non_exhaustive]` with these variants: `InvalidContext`, `UnsupportedContextType(String)`, `Expired`, `MissingRequiredField(&'static str)`, `Encryption`, `Network`, and `Rejected { reason, message, correlation_id, details }`.
- **JavaScript bindings.** With `browser-bindings`, `bindings.rs` exports `tokenize(contextJwt: string, card: object): Promise<string>`, so plain JS pages can use it without writing Rust.
- **Tokenization is not split into a separate `Operation`.** It is one hand-written request (encrypt, POST, read a JWT) that would only use the server pipeline's URI building. The shared pieces are `jose::jwe` and the claim parsing.

### 2.5 Generated models
- **Struct shape.**
  - Plain `pub` fields; all fields are `Option<T>`, as in every SDK, because the spec's `required` lists are unreliable.
  - Derives: `Default, Clone, PartialEq, Serialize, Deserialize`, with `#[serde(rename_all = "camelCase")]` plus explicit renames such as `_links` → `links` and keywords such as `r#type`.
  - `skip_serializing_if = "Option::is_none"`.
  - **No** `deny_unknown_fields`, `flatten` or `#[non_exhaustive]` on structs, because that would break struct literals and the DSL.
- **Type mapping.**
  - Strings use the `lenient::string` deserializer, which accepts a number or bool.
  - Integers become `i64`, using lenient deserialization from strings.
  - `number` becomes `f64`. Amount-like fields stay `String` exactly as in the spec, and the `Amount` newtype helps build them.
  - Dates stay `String`. The official SDKs have date-parsing bugs, and we add typed parse helpers on top.
  - `additionalProperties` becomes `BTreeMap<String, T>` (or `serde_json::Value` when untyped).
- **Generated `Debug` redacts sensitive fields.** Field names matching the sensitive list in `codegen.toml` print as `"[REDACTED]"`.
- **Open enums.** These are curated in `codegen.toml` and parsed from descriptions for known status and reason fields. They are emitted through the `open_enum!` macro: known variants plus `Unknown(String)`, with `Display`/`FromStr`/serde implementations, marked `#[non_exhaustive]`. To keep the DSL simple, model fields stay `Option<String>` and typed getters (`resp.status_enum()`) are generated next to them.
- **Feature gating.** Each model is gated by the union of the API groups that use it, emitted as `#[cfg(any(feature = "payments", feature = "tms"))]`. The generator computes this from its reachability analysis.

### 2.6 Declarative DSL (`dsl.rs`)

There is one generic, recursive `macro_rules!` macro that works for **any** generated model, with no per-model code. Rust field names are checked at compile time, and types are inferred through `Option::get_or_insert_with(Default::default)`:
```rust
use cybersource::{build, models::CreatePaymentRequest};

let req = build!(CreatePaymentRequest {
    client_reference_information: { code: "TC50171_3" },
    processing_information: { capture: true, commerce_indicator: "internet" },
    payment_information: {
        card: { number: card_number, expiration_month: "12", expiration_year: "2031" },
    },
    order_information: {
        amount_details: { total_amount: amount!("102.21"), currency: "USD" },
        bill_to: { first_name: "John", last_name: "Doe", email: "jdoe@example.com" },
        line_items: [ { product_name: "Widget", unit_price: "51.10", quantity: 2 }, { … } ],
    },
    merchant_defined_information = existing_vec,       // `=` assigns raw (no Some/Into wrapping)
});
let req2 = build!(CreatePaymentRequest from req.clone() { order_information: { amount_details: { total_amount: "5.00" } } });
patch!(req, { processing_information: { capture: false } });
```

**Expansion rules.**
| Syntax | Expands to |
|---|---|
| `field: { … }` | `let n = target.field.get_or_insert_with(Default::default);`, then recurse into `n` |
| `field: [ {…}, … ]` | `target.field.get_or_insert_with(Vec::new)`, then for each element push `Default::default()` and recurse into the `last_mut()` |
| `field: expr` | `target.field = Some(Into::into(expr))` |
| `field = expr` | `target.field = expr` (raw assignment) |
| `from base` | starts from an existing value; `patch!` mutates in place |

**Flow sugar macros** wrap `build!` with the common defaults: `payment!`, `capture!`, `refund!`, `reversal!`, `void!` and `tms_customer!`.
- `payment!` takes `amount: "10.00" USD` and `card: { … }` shorthands and maps them to the nested paths.
- They are implemented as `macro_rules!` that rewrite the shorthands, then delegate to `build!`.

**Other helpers.**
- `amount!("10.00")` validates the literal and returns `Amount`. It is a const-checked format where possible, otherwise a debug assertion plus a runtime `Amount::new`.
- bon builders cover the hand-written entry points only: `Client::builder`, `MleConfig` and `CaptureContextVerifier`.

**Testing the DSL.** `trybuild` tests check compile-fail messages for misspelled fields.

### 2.7 Features
```toml
default        = ["server", "reqwest", "rustls", "payments", "tms", "capture-context"]
# tiers
server = []                    # credentialed Client, auth, keys, MLE, generated ops; every API group implies it
browser = ["dep:wasm-bindgen-futures", "dep:web-sys"]   # client-side tokenization only (§1.9); uses fetch directly
browser-bindings = ["browser", "dep:wasm-bindgen"]      # JS-callable exports (tokenize(contextJwt, card) → Promise<string>)
# transports
reqwest = [...]; ureq = [...]; worker = [...]; wasi = ["dep:wstd"]
rustls = ["reqwest?/rustls", "ureq?/rustls"]; native-tls = [...]
# auth / crypto
p12 = ["dep:p12-keystore"]     # PEM/PKCS#8 always available
mle = ["dep:aes-gcm"]          # rsa always present (JWT RS256)
http-signature = []            # legacy, deprecated
# API groups (≈ 20; mapping of 80 tags lives in codegen.toml)
payments, payouts, risk, tms, capture-context, transactions, reporting, secure-file-share,
recurring-billing, invoicing, webhooks, account-updater, bank-account-validation, bin-lookup,
tax, currency-conversion, boarding, user-management, devices, agentic-commerce, emv
full = [all API groups, "mle", "p12", "http-signature"]   # not "browser": it is a separate build profile
# Features are additive, so `server` + `browser` together still compiles (docs.rs, --all-features CI).
# Keeping secrets out of the browser is the merchant's build choice. The docs show the browser
# Cargo.toml recipe, and `cargo xtask check-browser` asserts the browser build contains no
# auth/keys/mle symbols.
# misc
tracing = ["dep:tracing"]      # redacted request/response logging
rust_decimal = ["dep:rust_decimal"]  # Amount <-> Decimal
```

### 2.8 Dependencies (all pure Rust, so they build for wasm32)
- **Core:** `http` 1, `bytes`, `serde`, `serde_json`, `thiserror` 2, `secrecy` 0.10, `zeroize`, `base64` 0.23, `percent-encoding`, `httpdate`, `web-time`.
- **Crypto:** `hmac` 0.13 + `sha2` 0.11, `sha1` 0.11 (only for Flex's RSA-OAEP key wrap), `rsa` 0.10 (PKCS#1 v1.5 RS256, OAEP-SHA1 and OAEP-SHA256), `aes-gcm` 0.11 (needed by both `mle` and `browser`), `x509-cert` 0.3 + `der`, `pkcs8`, `p12-keystore` 0.4 (with `pbes1` for legacy 3DES/RC2 bags), `getrandom` 0.4 (with `wasm_js` on `cfg(all(target_arch="wasm32", target_os="unknown"))` only), `subtle`.
  - **Hand-rolled JWS and JWE**, roughly 200 lines. `jsonwebtoken` pulls `js-sys` on WASI. `josekit` needs OpenSSL. No pure-Rust crate supports RSA-OAEP-256 with A256GCM.
  - **Before Stage 1, check that `rsa` 0.10 has the RUSTSEC-2023-0071 (Marvin) fix.** If not, document the risk; it applies to decryption only, so it affects response MLE.
- **Transports:** `reqwest` 0.13 (`default-features = false`), `ureq` 3, `worker` 0.9, `wstd` 0.6.
- **Browser:** `wasm-bindgen`, `wasm-bindgen-futures`, `web-sys` (`fetch`, `Request`, `Response`, `Headers`). The browser tier calls `fetch` directly instead of using reqwest, to keep the wasm small.
- **Dev:** `tokio`, `wiremock`, `insta`, `trybuild`, `wasm-bindgen-test`, `proptest`.
- **Codegen (xtask only):** `serde_json`, `heck`, `quote` + `proc-macro2` + `prettyplease`, `indexmap`, `toml`.

---

## 3. Implementation stages

Each stage leaves the crate compiling with green tests, and each is committed in small increments.

### Stage 1: Core, auth and transports (hand-written vertical slice)
**Status:** Complete (2026-11-20)
**Goal:** Authorize a payment against the sandbox from both async and blocking clients, using one hand-written `CreatePayment` operation and model.

**Work**
- Cargo workspace, CI with fmt, clippy `-D warnings`, test and MSRV jobs.
- `config.rs` with a validating builder. `Debug` redacts secrets; secrets are held in `SecretString`.
- `error.rs`, `clock.rs`, `operation.rs`, `pipeline.rs`, `response.rs`.
- `jose/{b64,jws}.rs` (HS256 and RS256 compact JWS), `auth/digest.rs`, `auth/jwt.rs` (v2 claims) and `auth/http_signature.rs`. Set up the `server` feature gate from the first commit.
- Key loading from PEM and PKCS#8, plus `keys/x509.rs` for the DN serialNumber and CN.
- Transports: `transport/{reqwest,ureq,mock}.rs`, then `Client` and `BlockingClient`.

**Tests**
- Known-answer tests for HTTP Signature: GET and POST, a meta key, a query string, and a single-digit day.
- Known-answer tests for HS256 and RS256 JWTs with a fixed clock and fixed `jti`.
- Digest vectors, including `{}`.
- Vectors cross-checked against the official Python and Node SDKs, generated by `cargo xtask vectors`, which runs a pinned SDK in a throwaway venv in the scratchpad. Inputs and outputs are stored with provenance.
- Pipeline tests against `MockTransport`, and a wiremock test of the headers on the wire.
- `#[ignore]` live sandbox tests using the public `testrest` credentials from the official samples, enabled with `CYBS_LIVE=1`.

**Success criteria**
- The sandbox authorizes 4111…1111 at 100.00 USD through both JWT HS256 and HTTP Signature, from both the async and the blocking client.

**Outcome and findings**
- **Success criterion met.** All four live tests (JWT HS256 and HTTP Signature, async and blocking) returned `AUTHORIZED` from `apitest.cybersource.com` with the public `testrest` credentials.
- **Ambiguities in §5 are resolved for JWT.** The sandbox accepts uppercase `request-method` and the `digestAlgorithm` claim, which is what we send.
- **Vectors.** They come from the official Python SDK 0.0.81 only, not Node. Our HTTP Signature headers and JWTs (HS256 and RS256, through a fixture P12) match the SDK **byte for byte**, because jwcrypto emits compact JSON with sorted keys and our claims struct is declared in sorted order. See `tests/vectors/PROVENANCE.md` for the SDK quirks the generator works around.
- **Deviations from the sketches above:**
  - `Operation::meta(&self)` returns a `&'static OperationMeta`, instead of an associated `const`.
  - `ErrorFlavor`, `ResponseKind` and `no_auth` are deferred to Stage 2, when operations need them.
  - `ErrorBody` is `Pts | Json | Text` for now.
  - `Client::new(config, transport)` plus `with_clock` / `with_entropy`, instead of a client builder; `Config` has the bon builder.
- **Intermediate hosts.** Transports take `with_base_url(..)` to connect somewhere other than the host they sign for. This is how an intermediate host is supported, and the wire tests use it to reach wiremock.
- **ureq is a native-only dependency** (`cfg(not(target_family = "wasm"))`), so `--all-features` builds for wasm32-unknown-unknown.
- **reqwest does not build for wasm32-wasip2.** WASI needs the `wstd` transport (Stage 5).

### Stage 2: Code generator and full API surface
**Status:** Complete (2026-11-20)
**Goal:** All 221 operations and about 2,200 models are generated, feature-gated and compiling.

**Work**
- Vendor the spec and `SOURCE.md`. `xtask` then runs these passes:
  1. **Load.** Read the spec with `serde_json`, preserving key order with `indexmap`.
  2. **Hoist.** Walk every inline schema. Name each one by its `title`; untitled schemas get a name derived from the parent name plus the field name in PascalCase.
  3. **Deduplicate and resolve collisions.** Hash each schema's structure to deduplicate. When a title maps to different structures, apply a deterministic rename, such as a path-qualified suffix, and record it in `codegen.toml`.
  4. **Normalize names.** Turn the inconsistent `PtsV2`/`Ptsv2` casing into PascalCase while keeping the SDK names as doc aliases (`#[doc(alias = "...")]`) so search works. Fields become snake_case, with keywords escaped.
  5. **Map types** as described in §2.5, plus lenient attributes and sensitive-field `Debug`.
  6. **Build operations.**
     - Choose a unique operation ID by prefixing duplicates with their group, and synthesize the missing one.
     - Generate path, query and header parameters, applying `x-queryParameterDefaults` as documented defaults rather than sending them implicitly.
     - Carry over the MLE policy, `retry_safe` (from the curated money-movement list), `ResponseKind` from `produces` and `x-streaming`, `ErrorFlavor` from the path prefix, and `no_auth`.
     - Allow a body on the `/icc` GET operations.
  7. **Group operations.** Map tags to features and compute per-model `cfg` attributes from reachability.
  8. **Emit.** Write models, operations and `api_group!` invocations; format them with `prettyplease`; add the `@generated` header.
- `cargo xtask check-codegen` runs in CI and fails if regenerating the output produces a diff.
- `cargo xtask update-spec --tag vX` updates the vendored spec and records which SDK release it came from.
- Replace the Stage 1 hand-written slice with the generated code. Keep its tests.

**Tests**
- Unit tests for each generator pass, using small synthetic specs.
- `insta` snapshots of selected generated items: `CreatePaymentRequest`, a TMS list operation, a CSV download operation and a JWT-response operation.
- Serde round-trips for sample payloads taken from the spec's `x-example` / `x-samplePayload` and from the samples repos.
- CI builds every API-group feature on its own, plus `--no-default-features` and `full`, to check compile times stay under budget. Track the full build time of `full`.

**Success criteria**
- `cargo build --features full` passes.
- Each group feature builds alone.
- Re-running codegen produces no diff.

**Outcome and findings**
- **All success criteria met.**
  - The spec is pinned to `cybersource-rest-client-python` tag 0.0.81, the same release as the auth vectors.
  - Generated: **220 operations** (the mTLS batch upload is skipped), **2,068 models** and **10,886 fields**, in 65 files (about 88k lines).
  - Each of the 20 API groups builds alone with no warnings.
  - `cargo xtask check-codegen` passes and runs in CI.
- **Compile time.** A clean `--features full` build, dependencies included, takes **62 s** on the dev machine, under the 90 s budget. That is without dropping lenient deserializers or splitting crates.
- **Deduplicating by title works.** The spec had far fewer real conflicts than the raw counts suggested. **One** rename was needed: the TMS payment-credentials `tmsMerchantInformation` against `TmsMerchantInformation`. The other case-only title pairs had identical shapes and merged.
- **Example corpus.** 554 examples (528 request, 26 response):
  - 269 round-trip exactly.
  - 275 round-trip apart from spec errata.
  - 10 contradict their own schema and are skipped, e.g. `actionList: "AP_ORDER"` where the schema says array, and `"PHYSICAL"` for a numeric field.

  The errata are mostly undeclared fields and `"Y"`/`"N"` used for booleans. The generator records them by checking each example against its raw schema, so the test still fails on any field the spec declares. Deleting one declared field from a model fails 217 examples. `[example_allowlist]` is empty.
- **Live.** The sandbox authorizes through the generated API (all 4 Stage 1 tests still pass). It also passes capture (a path parameter), transaction details (a real response decoded by a generated model) and capture-context creation (a JWT text response).
- **Deviations from §2:**
  - **No `api_group!` macro.** The generator emits plain accessor structs (`client.payments()`), methods that return a hand-written `Call<'c, C, Op>`, and inherent `Call` setters. `Call` implements `IntoFuture` for async clients and `send()` for blocking ones.
  - **`ErrorFlavor` is not used.** Error bodies are recognized by shape: `ErrorBody::Pts`, `ErrorBody::Tms` (`{"errors": [...]}`), or raw JSON or text.
  - `Operation::headers` returns `Result`, so an invalid header value is an error, never dropped. `Operation::accept` was added for CSV, XML and JWT.
  - **Bodies on any method.** A body is sent whenever an operation has one, which covers the `/icc` GETs. Digests still follow the method rule: POST, PUT and PATCH only.
  - **Output types.** `Bytes` for non-JSON content, `String` for JWT and JOSE, and a `<Op>Response` enum when 2xx statuses differ (8 operations).
  - **Field order and names.** Fields are in alphabetical JSON-name order, which keeps output deterministic without `preserve_order` leaking into the library's `serde_json`. Every field has an explicit rename, because property casing in the spec is mixed.
  - **Mixed objects.** When an object has both properties and `additionalProperties`, the map is ignored. All 165 occurrences are the same boarding error detail.
  - **Formatting.** `quote`, then `prettyplease`, then `rustfmt` (via stdin), so `cargo fmt` leaves the generated files unchanged.

### Stage 3: Key material and Message-Level Encryption
**Status:** Complete (2026-11-20)
**Goal:** RS256 with P12, request and response MLE, and correct per-operation MLE policy.

**Work**
- `keys/p12.rs`:
  - Load the merchant certificate and key by CN equality (case-insensitive) for both. This fixes the SDKs' `contains` mismatch.
  - Load the `CyberSource_SJC_US` MLE certificate.
  - Warn through `tracing` when a certificate expires within 90 days, and return an error if it has already expired. That check is on by default and can be turned off.
- `jose/jwe.rs`: compact JWE encrypt and decrypt. The key wrap is either `RSA-OAEP-256` (MLE) or `RSA-OAEP` with SHA-1 (Flex tokenization, used in Stage 5). Content encryption is A256GCM, and decryption also accepts A128GCM and A192GCM. Also `jose/jwk.rs` for RSA JWK import.
- `mle/policy.rs`: the mandatory/optional/override logic from §1.5, with the config-time validation described there.
- Response-MLE kid: configured explicitly, or auto-extracted from a Cybersource-generated P12.
- Wire both into the pipeline, encrypting before signing and decrypting before classifying the status.

**Tests**
- JWE round-trips for both key-wrap algorithms. RSA-OAEP (SHA-1) output must decrypt with Python `jwcrypto`.
- Decrypt vectors produced by Python `jwcrypto` and Node `jose`.
- Header-shape assertions.
- Every row of the policy truth table.
- Sample P12 files generated in tests: a legacy 3DES bag and an AES bag.
- A live sandbox test against an MLE-mandatory operation, enabled only when MLE credentials are present.

**Success criteria**
- A sandbox payment succeeds with request MLE and response MLE using a P12.

**Outcome and findings**
- **Success criterion met, with one change.** The plan was to prove MLE with a sandbox *payment*. Cybersource's public sample merchant `agentic_mid_091225001`, whose P12s ship in the official sample repos, answers `createPayment` with `502 SYSTEM_ERROR` even with plain RS256 and no MLE. That means it authenticates but isn't set up for card processing. The live tests use a transaction search (`POST /tss/v2/searches`) instead, which accepts optional MLE in both directions. All three pass:
  - JWT RS256 from the real P12;
  - an encrypted request, which the sandbox decrypts: it echoes back the search name, which only exists inside the JWE;
  - an encrypted request and response. The response on the wire is `{"encryptedResponse": …}`, and we decrypt it.

  The four Stage 1 authorization tests still pass. That makes 8/8 live tests.
- **P12.** `p12-keystore` 0.4.1 parses Cybersource's real files: a 3DES certificate bag, plain or shrouded key bags, and an SHA-256 MAC with a 512-byte salt. No in-house parser was needed.
  - **Surprise:** Cybersource certificates use the ASCII digits of the decimal serial as the X.509 serial (22 bytes). That is over RFC 5280's 20-octet limit, and `x509-cert` rejects it by default, so we parse with its `Raw` profile.
  - Keys are paired with certificates by public key, not by position in the file.
- **JWE.** Hand-written RSA-OAEP and RSA-OAEP-256 with A128, A192 and A256 GCM. It decrypts tokens made by the SDK's own `MLEUtility.encrypt_request_payload` and by jwcrypto. Every decryption failure is one opaque error. `rsa` 0.10 is patched for RUSTSEC-2023-0071 (Marvin).
- **Policy.** It matches the SDKs, with one difference: a mandatory-MLE operation without a certificate, or under HTTP Signature, fails with `Error::Mle` and **nothing is sent**, where the SDKs silently send plaintext.
- **Sample keys.** `cargo xtask sandbox-keys` downloads Cybersource's public sample keys at a pinned commit, SHA-256 checked, into `target/`. They are not committed: the sample repo licence is `NOASSERTION`. The response-MLE key expires 2026-11-28; after that the live test skips itself.
- **Deviations:**
  - **No `mle` feature.** MLE is always available under `server`, because 32 operations require it.
  - **Expiry is reported, not enforced.** `Config::certificate_expiries()` lists every certificate's expiry. The SDKs only warn, and the sandbox accepts expired keys.
  - `MleConfig` uses chained setters, with no bon builder.
  - `pipeline::finish` now takes the `Config`, because it needs the response key.
  - `SigningInput` has a new `response_mle_kid` field.

### Stage 4: Ergonomics, DSL and utilities
**Status:** Complete (2026-11-20)
**Goal:** The idiomatic layer: DSL, open enums, flow helpers, capture context, webhooks and redaction.

**Work**
- `types/`: `Amount`, `Currency` and `open_enum!`, with curated enums such as `PaymentStatus`, `ReasonCode`, `CaptureStatus`, `RefundStatus`, `VoidStatus` and `DecisionManagerDecision`.
- `dsl.rs`: `build!`, `patch!`, the flow sugar macros and `amount!`.
- `flows/`:
  - `PaymentOutcome`.
  - A HAL pagination iterator for TMS and RBS lists: an async `Stream` behind a `futures-core` feature, and a blocking `Iterator`.
  - ETag-aware TMS updates that read the `etag` from GET and send `if-match`.
  - `Response::correlation_id()`, which normalizes both header spellings.
- `capture_context.rs` (server tier, the authoritative check):
  - Verify RS256 only (the algorithm is pinned).
  - Check `exp` and `iat` with configurable clock-skew leeway.
  - Fetch the JWK through the client's transport, so proxies and WASM work.
  - Cache keys per `(host, kid)` with a TTL and re-fetch once on failure.
  - Expose typed claims: `ctx`, `flx.jwk`, client library URL and integrity.
  - Also verify transient-token JWTs. This is the server-side check every browser-tokenized token must pass before it is used in a payment.
- `webhook.rs`:
  - `WebhookVerifier::verify(headers, raw_body, now)` parses `v-c-signature`, looks up the key by `keyId`, compares in constant time, and applies a timestamp tolerance.
  - It is written against `http::HeaderMap`, so it works with axum, actix and Workers.
- `redact.rs` plus the `tracing` feature: spans for each request (operation ID, correlation ID, status) and redacted bodies at `TRACE` level. Authorization and Signature headers are never logged.
- Opt-in developerId injection through `Config::developer_id`, applied to a serialized copy of the body only, for the request types the SDKs list.

**Tests**
- `trybuild` tests for the DSL, both passing and compile-fail.
- DSL output matching the equivalent struct literals.
- Open-enum property tests: unknown values round-trip.
- Capture-context tests with an expired token, the wrong algorithm, an unknown `kid`, and key rotation.
- Webhook known-answer tests from the docs example, plus tamper tests.
- Redaction snapshot tests.

**Success criteria**
- Examples compile and run against the sandbox, and none of them uses a raw struct literal.

**Outcome and findings**
- **Success criterion met.** The five examples use the DSL with no struct literals, and all run against the sandbox:
  - `authorize_and_capture`: `payment!`, then `PaymentOutcome`, then `capture!`;
  - `blocking`;
  - `tms_customer`: create, read with ETag, update with `if_match`, paginated list, delete;
  - `capture_context`: create and verify against the live key endpoint;
  - `webhook`.

  The live suite also verifies a fresh Microform capture context.
- **DSL.**
  - **`build!`** is one recursive `macro_rules!` muncher with no per-model code that works on all 2,068 models. It covers nested objects, object lists, value lists (`["VISA", "MASTERCARD"]`), raw `field = expr`, and `..base`.
  - **Base values:** `..base` replaces the planned `from base`, because `macro_rules!` can't have an expression followed by `{`.
  - **`patch!`** applies the same syntax to an existing value.
  - **Flow macros:** `payment!`, `capture!`, `refund!`, `reversal!` and `void!` share one muncher with a mode token.
  - **Compile-time literals:** `amount!("10.00")` and `currency!(USD)` are checked at compile time with `const fn` validators.
  - **Error quality:** a misspelled field gives an ordinary compiler error pointing at the identifier, with a suggestion. `trybuild` locks this in, along with the invalid-literal errors.
  - **Not covered:** a "wrong type" compile-fail case was left out, because the compiler's list of candidate `From` impls differs by platform.
- **Typed statuses.**
  - `open_enum!` generates string enums with an `Unknown(String)` fallback.
  - Eight enums use the values from the spec descriptions: payment, capture, refund, reversal, void, credit and payout statuses, and `ReasonCode`.
  - Typed getters exist on the payment and payout response models, and `PaymentOutcome` interprets them (approved, partial, review, declined). Declines are HTTP 201.
- **Pagination.**
  - A `[pagination]` table in `codegen.toml` covers 9 list operations. Their total and count fields differ (`total`/`count`, `totalCount`/`plans`, `totalInvoices`, `totalLinks`, …), and invoices and payment links even make `offset` and `limit` *required*.
  - The generator implements `Paged`, and `Call::pages()` gives `next().await` on async clients and an `Iterator` on blocking ones. There is no `Stream` dependency.
- **Partner `developerId`.** It is opt-in (`Config::developer_id`) and is injected into the serialized copy of the body, only for the 32 operations whose body has the field, and never over a value the caller set.
- **Capture context and transient tokens.**
  - RS256 is pinned and `exp`/`iat` are checked with 20 s leeway; the SDKs check neither.
  - Keys come from `/flex/v2/public-keys/{kid}` through the client's own transport. They are cached by host and kid, and a cached key is re-fetched once when it fails, to handle rotation.
  - Transient tokens are verified with the context's one-time `flx.jwk`, with a matching `kid` required.
  - The spec's real Cybersource capture contexts verify against the published `zu` key, which is committed as a fixture.
  - The key endpoint marks its key `use: "enc"` and sends no `alg`, so neither is checked.
- **Webhooks.**
  - `WebhookVerifier` implements HMAC-SHA256 over `t + "." + payload` with the base64-decoded secret, constant-time comparison, ±5 min tolerance, and several keys by id for rotation.
  - The documented worked example passes.
  - **Open item:** Cybersource's own plugins disagree on whether the payload member or the raw body is signed, so both are accepted. A live webhook delivery, which needs a public endpoint, should settle it.
- **Redaction and tracing.**
  - The sensitive-field list is generated from `codegen.toml`, so `Debug` output and logs share one source.
  - The `tracing` feature adds one span per request (operation, method, path, status, correlation id, elapsed time). TRACE events log redacted bodies: the request before encryption and the response after decryption.
  - A test captures real log output and checks that the PAN, CVV, names, email, bearer token and JWTs never appear.
  - Expiring certificates (within 90 days) and MLE warnings are logged when the `Config` is built.
- **Deviations:**
  - A `Pager` with `next()` instead of a `Stream`.
  - Webhook verification accepts either payload form.
  - Typed getters are hand-written for the payment and payout models, not generated.
  - Base values use `..base`, not `from`.
  - New `Error::Verification` and `Error::UnexpectedStatus` variants.

### Stage 5: WASM targets, browser tokenization, documentation and release
**Status:** Not Started
**Goal:** Verified builds for edge and WASI (full client) and for the browser (client-side tokenization only), and a publishable 0.1.0.

**Work: server tier on WASM**
- `transport/worker.rs` (`worker::Fetch`) and `transport/wasi.rs` (`wstd` wasi-http).
- The reqwest fetch backend on wasm32-unknown-unknown, for Workers and other edge runtimes.
- `getrandom` `wasm_js` wiring and the `web-time` clock.
- Gate `BlockingClient` and `ureq` behind `cfg(not(target_family = "wasm"))`.

**Work: browser tier (§1.9, §2.4a)**
1. `flex/context.rs`:
   - Permissive parsing of the capture context.
   - Reject `mf-*` and `gda-*` contexts with `UnsupportedContextType`.
   - Check `exp` and `iat`.
   - Extract `requiredFields` and `optionalFields`.
2. `flex/long_term_keys.rs`: embed the published Flex long-term keys, for optional best-effort signature verification. An unknown `kid` returns a "can't verify here" result, not an error.
3. `flex/tokenize.rs`:
   - Validate the fields against the context.
   - Build the plaintext `{data, context, index: 0, iat, jti}`.
   - Encrypt with `jose::jwe` (RSA-OAEP + A256GCM, `kid` = `flx.jwk.kid`).
   - POST `{"keyId": jwe}` to `flx.origin + flx.path` through `web-sys` `fetch`.
   - Parse the JWT on success, or the `responseStatus` error body.
   - Zeroize the plaintext buffers.
4. `flex/token.rs`: `TransientToken` with its decoded but unverified claims (`jti`, `exp`, masked number, BIN, detected card types).
5. `flex/bindings.rs` (`browser-bindings`): the JS `tokenize` export, plus TypeScript definitions through wasm-bindgen.
6. `examples/browser_tokenize/`:
   - A minimal page and a server pair: an axum server mints the context, the page tokenizes, and the server verifies and authorizes.
   - The README carries the support and PCI warning from §1.9.
7. `cargo xtask check-browser`:
   - Builds `--no-default-features --features browser-bindings` for wasm32-unknown-unknown.
   - Fails if the binary contains auth, keys or MLE symbols.
   - Reports the wasm size; the budget is ≤ 300 KB after `wasm-opt`.
8. Before calling this stage done, **confirm the open items in §1.9 against the sandbox**: success content type, the data shape, and verifying the token with `flx.jwk`.

**Documentation for the browser tier**
- A prominent caveat: Cybersource states the Flex API is not designed for browsers, and the browser tier likely means SAQ A-EP scope. Recommend Microform or Unified Checkout for standard web checkouts.
- The browser `Cargo.toml` recipe.

**CI matrix**
- Native targets: linux, macOS and windows.
- `wasm32-unknown-unknown`, server tier: a build plus `wasm-bindgen-test` runs of the pipeline with a mock transport.
- `wasm32-unknown-unknown`, browser tier: `wasm-bindgen-test` headless Chrome and Firefox runs of tokenization against a mock `fetch` with a test RSA key, plus `check-browser`.
- `wasm32-wasip2`: a build plus a wasmtime run of a pipeline test.
- A Cloudflare Workers example built with `worker-build`.
- Documentation:
  - Crate docs: quickstart, auth matrix, MLE guide, migrating from HTTP Signature, DSL guide, error-handling guide covering 201 declines and 502 unknown outcomes, and feature table.
  - `CHANGELOG.md` and release automation.
  - A scheduled CI job that checks the upstream spec and opens a PR running `xtask update-spec`.

**Success criteria**
- All targets build in CI.
- The browser example tokenizes a sandbox card end to end, and the server verifies the token and authorizes with it.
- `cargo publish --dry-run` succeeds.
- docs.rs metadata builds with `full`.

---

## 4. Verification (end to end)
- `cargo test --all-features` runs unit, known-answer, snapshot, trybuild and mock-pipeline tests.
- `CYBS_LIVE=1 cargo test --test live_sandbox -- --ignored` runs against `apitest.cybersource.com` with the public `testrest` credentials:
  - authorize, capture, refund and void;
  - a TMS customer create/get/patch(if-match)/delete;
  - a capture-context create plus verification;
  - Flex tokenization run natively against `testflex.cybersource.com`: create a `/flex/v2/sessions` context, tokenize, verify the transient token on the server, and authorize with `tokenInformation.transientTokenJwt`. Natively, the `Digest` response header can be checked too;
  - a transaction search.
- `cargo xtask check-codegen` checks the generated code for drift.
- Cross-SDK parity: `cargo xtask vectors` regenerates the signature, JWT and JWE vectors from the pinned official SDKs, and the tests must stay green.
- WASM: `cargo xtask check-browser`, `wasm-pack test --headless --chrome --firefox`, the `examples/browser_tokenize` flow by hand in a browser, `cargo build --target wasm32-wasip2 --no-default-features --features wasi,payments`, and a Workers example deploy with `wrangler dev`.

## 5. Risks and open items
- **Compile time** of about 2,200 models. Mitigations: feature gating, no per-model builders, `Option` fields, avoiding `flatten`. Measure in Stage 2. If `full` takes more than about 90 s, split the generated code into internal crates later; the public API is unchanged because they are re-exported.
- **Pre-release dependencies.** `p12-keystore` pulls in `pkcs12`/`cms` release candidates and a second ASN.1 stack (`x509-parser`). crates.io allows publishing with them. If they become a problem, vendor a minimal PKCS#12 parser (PBES1 and PBES2 bags) on `pkcs12` types plus `pkcs5`.
- **Spec churn.** Cybersource releases monthly. Adding a field is semver-minor for us because structs use `Default` and `..` construction. Renamed types become a semver-major regeneration.
- **Ambiguous server behaviour.**
  - `digestAlgorithm` vs `digest-algorithm`, and the case of `request-method`: we follow the majority of SDKs, and the live tests confirm it.
  - Webhook signature format: confirm against a real webhook in sandbox during Stage 4.
- **Browser tokenization is unsupported by Cybersource.** The guide says the Flex API "is not designed to be used from the browser". Cybersource could restrict CORS on `/flex/v2/tokens` at any time; today it echoes any origin. Mitigations: the feature is opt-in and documented, and it also works from native callers, where nothing depends on CORS. Microform and Unified Checkout remain the recommended web path.
- **PCI.** Using the browser tier puts the merchant's page in scope for the card number, most likely SAQ A-EP. This is documented; it is not our liability, but it must be impossible to miss.
- **Flex protocol gaps.**
  - Some details are confirmed only by probes or by the iOS SDK.
  - The embedded long-term key set is incomplete (`j4` and `sn` are missing), so browser-side signature checks are best-effort.
  - `mf-*` and `gda-*` contexts are out of scope until Cybersource documents their plaintext formats.
- **Out of scope for v0.1:** OAuth, mutual TLS and the PGP batch upload. The design leaves room for them: `Credentials::OAuth`, and a native-only mTLS transport option.

## 6. Housekeeping (from the global CLAUDE.md)
- Keep this file's stage status updated as work progresses.
- Use the TDD loop for each unit: red, green, refactor, commit.
- Stop after 3 failed attempts on any issue and reassess.
- Every commit compiles, passes fmt and clippy, and includes tests.
