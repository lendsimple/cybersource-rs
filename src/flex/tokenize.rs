//! Flex API client-side tokenization: card data in, transient token out.
//!
//! **Not for web pages.** Flex rejects tokenization requests from browsers
//! (`400 VALIDATION_ERROR`: "Browser calls are not supported for Flex
//! Direct API calls"); web checkouts use Microform or Unified Checkout, which
//! keep card data in Cybersource-hosted iframes. This is for native, kiosk,
//! IoT and other clients that collect card data themselves, which puts them
//! in PCI scope for it.
//!
//! The protocol, as implemented by Cybersource's own iOS SDK:
//!
//! 1. Your server creates a capture context with
//!    `capture_context().generate_flex_api_capture_context(..)`, listing the
//!    fields to collect.
//! 2. The client builds the plaintext `{data, context, index: 0, iat, jti}`,
//!    encrypts it to the context's one-time key (`RSA-OAEP`, `A256GCM`,
//!    `kid` = `flx.jwk.kid`), and POSTs `{"keyId": "<JWE>"}` to
//!    `flx.origin + flx.path` with no authentication.
//! 3. The response carries the transient token, a JWT
//!    (`{"token": "<JWT>", ...}`). Your server verifies it
//!    with [`CaptureContext::verify_transient_token`] and pays with it
//!    (`tokenInformation.transientTokenJwt`).
//!
//! Only Flex API (`api-*`) contexts are supported; Microform (`mf-*`) and
//! Unified Checkout (`gda-*`) contexts belong to their own JavaScript.
//!
//! This module performs no I/O: send [`TokenizeRequest`] with any HTTP
//! client, then pass the response to [`parse_tokenize_response`]. It needs
//! no crate features, so a client build can use `default-features = false`
//! and carry no merchant credentials or signing code.

use std::collections::BTreeMap;
use std::fmt;

use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

use super::context::{CaptureContext, TransientToken};
use crate::entropy::Entropy;
use crate::jose::jwe::{self, Enc, KeyAlg};
use crate::jose::jws;

/// Card (and optional order) data to tokenize.
#[derive(Clone, Default)]
#[non_exhaustive]
pub struct CardData {
    /// Primary account number.
    pub number: Zeroizing<String>,
    /// CVV/CVC, if collected.
    pub security_code: Option<Zeroizing<String>>,
    /// Two-digit month.
    pub expiration_month: Option<String>,
    /// Four-digit year.
    pub expiration_year: Option<String>,
    /// Cybersource card type code, e.g. `001` (Visa).
    pub card_type: Option<String>,
    /// Total amount, if the session collects it.
    pub total_amount: Option<String>,
    /// Currency, if the session collects it.
    pub currency: Option<String>,
    /// Billing fields by Flex name (`firstName`, `address1`, `country`, ...).
    pub bill_to: BTreeMap<String, String>,
    /// Shipping fields by Flex name.
    pub ship_to: BTreeMap<String, String>,
}

impl CardData {
    /// Card data with a number and expiry.
    pub fn new(
        number: impl Into<String>,
        expiration_month: impl Into<String>,
        expiration_year: impl Into<String>,
    ) -> Self {
        CardData {
            number: Zeroizing::new(number.into()),
            expiration_month: Some(expiration_month.into()),
            expiration_year: Some(expiration_year.into()),
            ..Default::default()
        }
    }

    /// Adds the security code.
    pub fn security_code(mut self, code: impl Into<String>) -> Self {
        self.security_code = Some(Zeroizing::new(code.into()));
        self
    }

    /// Adds the card type code.
    pub fn card_type(mut self, card_type: impl Into<String>) -> Self {
        self.card_type = Some(card_type.into());
        self
    }

    /// Adds the amount and currency.
    pub fn amount(mut self, total: impl Into<String>, currency: impl Into<String>) -> Self {
        self.total_amount = Some(total.into());
        self.currency = Some(currency.into());
        self
    }

    /// Adds a billing field, e.g. `("postalCode", "94105")`.
    pub fn bill_to(mut self, field: impl Into<String>, value: impl Into<String>) -> Self {
        self.bill_to.insert(field.into(), value.into());
        self
    }

    /// Adds a shipping field.
    pub fn ship_to(mut self, field: impl Into<String>, value: impl Into<String>) -> Self {
        self.ship_to.insert(field.into(), value.into());
        self
    }

    /// Every provided value, by dotted Flex path.
    fn fields(&self) -> Vec<(String, &str)> {
        let fixed: [(&str, Option<&str>); 7] = [
            ("paymentInformation.card.number", Some(self.number.as_str())),
            (
                "paymentInformation.card.securityCode",
                self.security_code.as_ref().map(|c| c.as_str()),
            ),
            (
                "paymentInformation.card.expirationMonth",
                self.expiration_month.as_deref(),
            ),
            (
                "paymentInformation.card.expirationYear",
                self.expiration_year.as_deref(),
            ),
            ("paymentInformation.card.type", self.card_type.as_deref()),
            (
                "orderInformation.amountDetails.totalAmount",
                self.total_amount.as_deref(),
            ),
            (
                "orderInformation.amountDetails.currency",
                self.currency.as_deref(),
            ),
        ];
        let mut out: Vec<(String, &str)> = fixed
            .into_iter()
            .filter_map(|(path, value)| Some((path.to_owned(), value?)))
            .collect();
        for (k, v) in &self.bill_to {
            out.push((format!("orderInformation.billTo.{k}"), v.as_str()));
        }
        for (k, v) in &self.ship_to {
            out.push((format!("orderInformation.shipTo.{k}"), v.as_str()));
        }
        out
    }
}

impl fmt::Debug for CardData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CardData")
            .field("number", &"[REDACTED]")
            .field(
                "security_code",
                &self.security_code.as_ref().map(|_| "[REDACTED]"),
            )
            .field("expiration_month", &self.expiration_month)
            .field("expiration_year", &self.expiration_year)
            .field("card_type", &self.card_type)
            .finish_non_exhaustive()
    }
}

/// Why tokenization failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum FlexError {
    /// The capture context could not be used (malformed, no key).
    #[error("invalid capture context: {0}")]
    InvalidContext(String),
    /// Not a Flex API (`api-*`) context.
    #[error(
        "capture context type {0:?} is not supported; only Flex API (api-*) contexts can be tokenized directly"
    )]
    UnsupportedContextType(String),
    /// The capture context has expired.
    #[error("the capture context has expired")]
    Expired,
    /// The session requires a field that was not provided.
    #[error("the capture context requires {0}")]
    MissingRequiredField(String),
    /// A field was provided that the session does not accept.
    #[error("the capture context does not accept {0}")]
    FieldNotAllowed(String),
    /// Encrypting the card data failed.
    #[error("encryption failed: {0}")]
    Encryption(String),
    /// The request could not be sent.
    #[error("network error: {0}")]
    Network(String),
    /// Cybersource rejected the request.
    #[error("tokenization rejected ({status}): {reason} {message}")]
    Rejected {
        /// HTTP status.
        status: u16,
        /// e.g. `VALIDATION_ERROR`, `CAPTURE_CONTEXT_EXPIRED`.
        reason: String,
        /// Description.
        message: String,
        /// For Cybersource support.
        correlation_id: Option<String>,
        /// Field-level details, as sent.
        details: Vec<Value>,
    },
    /// The response was not a transient token.
    #[error("unexpected tokenization response: {0}")]
    InvalidResponse(String),
}

/// A tokenization request, ready to send with any HTTP client: POST `body`
/// to `url` with `Content-Type: content_type` and no authentication.
#[derive(Clone)]
#[non_exhaustive]
pub struct TokenizeRequest {
    /// `flx.origin + flx.path`, e.g. `https://testflex.cybersource.com/flex/v2/tokens`.
    pub url: String,
    /// `application/json; charset=utf-8`.
    pub content_type: &'static str,
    /// `{"keyId": "<compact JWE>"}`.
    pub body: String,
}

impl fmt::Debug for TokenizeRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenizeRequest")
            .field("url", &self.url)
            .field(
                "body",
                &format_args!("<{} bytes, encrypted>", self.body.len()),
            )
            .finish()
    }
}

/// Builds the encrypted tokenization request for `card`. `now` is seconds
/// since the epoch.
pub fn tokenize_request(
    context: &CaptureContext,
    card: &CardData,
    now: i64,
    entropy: &dyn Entropy,
) -> Result<TokenizeRequest, FlexError> {
    let kind = context.kind().unwrap_or_default();
    if !kind.starts_with("api-") {
        return Err(FlexError::UnsupportedContextType(kind.to_owned()));
    }
    context.ensure_fresh(now).map_err(|_| FlexError::Expired)?;
    let flx = context
        .flx
        .as_ref()
        .ok_or_else(|| FlexError::InvalidContext("no flx claim".into()))?;
    let key = flx
        .jwk
        .to_public_key()
        .map_err(|e| FlexError::InvalidContext(e.to_string()))?;
    let (origin, path) = match (&flx.origin, &flx.path) {
        (Some(o), Some(p)) => (o, p),
        _ => {
            return Err(FlexError::InvalidContext(
                "flx has no origin or path".into(),
            ));
        }
    };

    let fields = card.fields();
    check_fields(context, &fields)?;
    let mut data = Map::new();
    for (path, value) in &fields {
        insert_path(&mut data, path, value);
    }

    let mut jti = [0u8; 16];
    entropy
        .fill(&mut jti)
        .map_err(|e| FlexError::Encryption(e.to_string()))?;
    let plaintext = Zeroizing::new(
        serde_json::to_vec(&json!({
            "data": data,
            "context": context.jwt,
            "index": 0,
            "iat": now,
            "jti": jti.iter().map(|b| format!("{b:02x}")).collect::<String>(),
        }))
        .map_err(|e| FlexError::Encryption(e.to_string()))?,
    );
    // The card data now lives only in `plaintext`; drop the map's copies.
    drop(data);

    let mut header = Map::new();
    if let Some(kid) = &flx.jwk.kid {
        header.insert("kid".into(), kid.clone().into());
    }
    let token = jwe::encrypt(
        &key,
        KeyAlg::RsaOaep,
        Enc::A256Gcm,
        &header,
        &plaintext,
        entropy,
    )
    .map_err(|e| FlexError::Encryption(e.to_string()))?;
    Ok(TokenizeRequest {
        url: format!("{}{}", origin.trim_end_matches('/'), path),
        content_type: "application/json; charset=utf-8",
        body: json!({ "keyId": token }).to_string(),
    })
}

/// Checks `fields` against the context's required and optional lists (when
/// it has them).
fn check_fields(context: &CaptureContext, fields: &[(String, &str)]) -> Result<(), FlexError> {
    let required = context.required_fields();
    let optional = context.optional_fields();
    for path in &required {
        if !fields.iter().any(|(p, _)| p == path) {
            return Err(FlexError::MissingRequiredField(path.clone()));
        }
    }
    if !required.is_empty() || !optional.is_empty() {
        for (path, _) in fields {
            if !required.contains(path) && !optional.contains(path) {
                return Err(FlexError::FieldNotAllowed(path.clone()));
            }
        }
    }
    Ok(())
}

fn insert_path(root: &mut Map<String, Value>, path: &str, value: &str) {
    let mut node = root;
    let mut parts = path.split('.').peekable();
    while let Some(part) = parts.next() {
        if parts.peek().is_none() {
            node.insert(part.to_owned(), value.into());
            return;
        }
        node = node
            .entry(part)
            .or_insert_with(|| Value::Object(Map::new()))
            .as_object_mut()
            .expect("paths only nest objects");
    }
}

/// Reads the tokenization response: on success the transient token (its
/// claims decoded but **not verified**; verify it on your server).
pub fn parse_tokenize_response(status: u16, body: &[u8]) -> Result<TransientToken, FlexError> {
    let text = String::from_utf8_lossy(body);
    let text = text.trim();
    if !(200..300).contains(&status) {
        return Err(rejection(status, text));
    }
    // Flex answers `{"token": "<JWT>", ...}` (application/json); tolerate a
    // bare or JSON-quoted JWT as well.
    let jwt = if text.starts_with('{') {
        let value: Value =
            serde_json::from_str(text).map_err(|e| FlexError::InvalidResponse(e.to_string()))?;
        value
            .get("token")
            .and_then(Value::as_str)
            .ok_or_else(|| FlexError::InvalidResponse("no token in the response".into()))?
            .to_owned()
    } else if text.starts_with('"') {
        serde_json::from_str::<String>(text)
            .map_err(|e| FlexError::InvalidResponse(e.to_string()))?
    } else {
        text.to_owned()
    };
    let decoded =
        jws::decode_unverified(&jwt).map_err(|e| FlexError::InvalidResponse(e.to_string()))?;
    TransientToken::from_decoded(decoded, &jwt)
        .map_err(|e| FlexError::InvalidResponse(e.to_string()))
}

fn rejection(status: u16, text: &str) -> FlexError {
    let value: Value = serde_json::from_str(text).unwrap_or(Value::Null);
    // Either {"responseStatus": {...}} or a flat {"reason", "message", ...}.
    let body = value.get("responseStatus").unwrap_or(&value);
    let field = |k: &str| body.get(k).and_then(Value::as_str).map(str::to_owned);
    FlexError::Rejected {
        status,
        reason: field("reason").unwrap_or_else(|| "UNKNOWN".into()),
        message: field("message").unwrap_or_else(|| text.chars().take(200).collect()),
        correlation_id: field("correlationId"),
        details: body
            .get("details")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
    }
}
