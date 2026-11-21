//! Verifying webhook (notification subscription) signatures.
//!
//! Cybersource signs each notification with a shared secret you create via
//! `POST /kms/egress/v2/keys-sym` (the `webhooks` API group) and sends:
//!
//! ```text
//! v-c-signature: t=<unix ms>;keyId=<key id>;sig=<base64 HMAC-SHA256>
//! ```
//!
//! The HMAC key is the base64-*decoded* secret and the message is
//! `t + "." + payload`. Cybersource's documentation and two of its plugins
//! sign the notification's `payload` member, while its newest plugin signs
//! the raw body, so [`WebhookVerifier::verify`] accepts a signature over
//! either. Both are keyed with your secret, so this does not weaken
//! verification. Nothing here needs a client or a network connection.
//!
//! ```
//! # use std::time::Duration;
//! use cybersource::webhook::WebhookVerifier;
//!
//! let verifier = WebhookVerifier::new()
//!     .key("bf44c857-b182-bb05-e053-34b8d30a7a72", "dGVzdF9rZXk=")?;
//! let mut headers = http::HeaderMap::new();
//! headers.insert(
//!     "v-c-signature",
//!     "t=1617830804768;keyId=bf44c857-b182-bb05-e053-34b8d30a7a72;sig=CzHY47nzJgCSD/BREtSIb+9l/vfkaaL4qf9n8MNJ4CY="
//!         .parse()?,
//! );
//! let now = Duration::from_millis(1_617_830_804_768);
//! verifier.verify(&headers, b"this is a decrypted payload", now)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use std::collections::HashMap;
use std::fmt;
use std::time::Duration;

use hmac::{Hmac, KeyInit, Mac};
use http::HeaderMap;
use secrecy::{ExposeSecret, SecretBox};
use serde::Deserialize;
use serde_json::Value;
use serde_json::value::RawValue;
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::jose::b64;

/// The signature header.
pub const SIGNATURE_HEADER: &str = "v-c-signature";

const DEFAULT_TOLERANCE: Duration = Duration::from_secs(5 * 60);

/// Why a webhook failed verification.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum WebhookError {
    /// No `v-c-signature` header.
    #[error("missing v-c-signature header")]
    MissingHeader,
    /// The header is not `t=…;keyId=…;sig=…`.
    #[error("malformed v-c-signature header: {0}")]
    Malformed(String),
    /// The header names a key this verifier doesn't have.
    #[error("unknown webhook signing key {0:?}")]
    UnknownKey(String),
    /// The timestamp is outside the allowed tolerance.
    #[error("webhook timestamp {timestamp_ms} is outside the allowed window")]
    Expired {
        /// The header's timestamp, in milliseconds.
        timestamp_ms: i64,
    },
    /// The signature does not match.
    #[error("webhook signature does not match")]
    BadSignature,
    /// A configured key is not valid base64.
    #[error("invalid webhook key: {0}")]
    InvalidKey(String),
    /// The body is not a JSON notification.
    #[error("invalid notification body: {0}")]
    InvalidBody(String),
}

/// A parsed `v-c-signature` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureHeader {
    /// Signing time, Unix milliseconds.
    pub timestamp_ms: i64,
    /// The signing key's id.
    pub key_id: String,
    /// The HMAC-SHA256.
    pub signature: Vec<u8>,
}

impl SignatureHeader {
    /// Parses `t=…;keyId=…;sig=…` (parameters in any order, surrounding
    /// whitespace ignored; values split at the first `=`, since base64
    /// padding contains `=`).
    pub fn parse(header: &str) -> Result<Self, WebhookError> {
        let (mut t, mut key_id, mut sig) = (None, None, None);
        for part in header.split(';').map(str::trim).filter(|p| !p.is_empty()) {
            let (name, value) = part
                .split_once('=')
                .ok_or_else(|| WebhookError::Malformed(format!("{part:?} has no '='")))?;
            match name.trim() {
                "t" => t = Some(value.trim()),
                "keyId" => key_id = Some(value.trim()),
                "sig" => sig = Some(value.trim()),
                _ => {}
            }
        }
        let missing = |name| WebhookError::Malformed(format!("missing {name}"));
        let timestamp_ms = t
            .ok_or_else(|| missing("t"))?
            .parse()
            .map_err(|_| WebhookError::Malformed("t is not a number".into()))?;
        let signature = b64::decode(sig.ok_or_else(|| missing("sig"))?)
            .map_err(|_| WebhookError::Malformed("sig is not base64".into()))?;
        Ok(SignatureHeader {
            timestamp_ms,
            key_id: key_id.ok_or_else(|| missing("keyId"))?.to_owned(),
            signature,
        })
    }
}

/// A webhook notification envelope.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Notification {
    /// e.g. `payments.payments.accept`, `risk.profile.decision.reject`.
    pub event_type: Option<String>,
    /// The subscription that sent it.
    pub webhook_id: Option<String>,
    /// Delivery attempt (0 for the first).
    pub retry_number: Option<i64>,
    /// The event data.
    #[serde(default)]
    pub payload: Value,
}

/// Verifies webhook signatures. Holds one or more keys, by key id, so old
/// and new keys can overlap while you rotate them (yearly, per Cybersource).
#[derive(Clone)]
pub struct WebhookVerifier {
    keys: HashMap<String, std::sync::Arc<SecretBox<[u8]>>>,
    tolerance: Duration,
}

impl fmt::Debug for WebhookVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebhookVerifier")
            .field("key_ids", &self.keys.keys().collect::<Vec<_>>())
            .field("tolerance", &self.tolerance)
            .finish()
    }
}

impl Default for WebhookVerifier {
    fn default() -> Self {
        WebhookVerifier {
            keys: HashMap::new(),
            tolerance: DEFAULT_TOLERANCE,
        }
    }
}

impl WebhookVerifier {
    /// A verifier with no keys and a 5-minute timestamp tolerance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a signing key: its id and the base64 secret from
    /// `keyInformation.key` when it was created.
    pub fn key(
        mut self,
        key_id: impl Into<String>,
        secret_base64: &str,
    ) -> Result<Self, WebhookError> {
        let secret = b64::decode(secret_base64.trim())
            .map_err(|e| WebhookError::InvalidKey(e.to_string()))?;
        if secret.is_empty() {
            return Err(WebhookError::InvalidKey("empty key".into()));
        }
        self.keys.insert(
            key_id.into(),
            std::sync::Arc::new(SecretBox::new(secret.into_boxed_slice())),
        );
        Ok(self)
    }

    /// How far the signature timestamp may be from now, either way.
    pub fn tolerance(mut self, tolerance: Duration) -> Self {
        self.tolerance = tolerance;
        self
    }

    /// Verifies the `v-c-signature` header against the exact request body.
    /// `now` is the time since the Unix epoch.
    pub fn verify(
        &self,
        headers: &HeaderMap,
        body: &[u8],
        now: Duration,
    ) -> Result<(), WebhookError> {
        let header = headers
            .get(SIGNATURE_HEADER)
            .ok_or(WebhookError::MissingHeader)?
            .to_str()
            .map_err(|_| WebhookError::Malformed("not ASCII".into()))?;
        self.verify_header(&SignatureHeader::parse(header)?, body, now)
    }

    /// Verifies, then parses the notification.
    pub fn verify_and_parse(
        &self,
        headers: &HeaderMap,
        body: &[u8],
        now: Duration,
    ) -> Result<Notification, WebhookError> {
        self.verify(headers, body, now)?;
        serde_json::from_slice(body).map_err(|e| WebhookError::InvalidBody(e.to_string()))
    }

    /// Verifies an already-parsed header against the body.
    pub fn verify_header(
        &self,
        header: &SignatureHeader,
        body: &[u8],
        now: Duration,
    ) -> Result<(), WebhookError> {
        let key = self
            .keys
            .get(&header.key_id)
            .ok_or_else(|| WebhookError::UnknownKey(header.key_id.clone()))?;
        let now_ms = i64::try_from(now.as_millis()).unwrap_or(i64::MAX);
        let tolerance_ms = i64::try_from(self.tolerance.as_millis()).unwrap_or(i64::MAX);
        if now_ms.abs_diff(header.timestamp_ms) > tolerance_ms.unsigned_abs() {
            return Err(WebhookError::Expired {
                timestamp_ms: header.timestamp_ms,
            });
        }

        let payload_member = payload_member(body);
        let candidates = payload_member
            .as_deref()
            .map(str::as_bytes)
            .into_iter()
            .chain(std::iter::once(body));
        let mut matched = subtle::Choice::from(0);
        for message in candidates {
            let expected = hmac(key.expose_secret(), header.timestamp_ms, message);
            matched |= expected.as_slice().ct_eq(&header.signature);
        }
        if bool::from(matched) {
            Ok(())
        } else {
            Err(WebhookError::BadSignature)
        }
    }
}

/// The exact text of the body's top-level `payload` member, if any.
fn payload_member(body: &[u8]) -> Option<String> {
    #[derive(Deserialize)]
    struct Envelope<'a> {
        #[serde(borrow)]
        payload: Option<&'a RawValue>,
    }
    let envelope: Envelope<'_> = serde_json::from_slice(body).ok()?;
    envelope.payload.map(|raw| raw.get().to_owned())
}

fn hmac(key: &[u8], timestamp_ms: i64, message: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(timestamp_ms.to_string().as_bytes());
    mac.update(b".");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_ID: &str = "bf44c857-b182-bb05-e053-34b8d30a7a72";
    const SECRET: &str = "dGVzdF9rZXk=";
    const T: i64 = 1_617_830_804_768;

    fn verifier() -> WebhookVerifier {
        WebhookVerifier::new().key(KEY_ID, SECRET).unwrap()
    }

    fn headers(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(SIGNATURE_HEADER, value.parse().unwrap());
        h
    }

    fn signed(message: &[u8], t: i64) -> String {
        let sig = b64::encode(hmac(b"test_key", t, message));
        format!("t={t};keyId={KEY_ID};sig={sig}")
    }

    fn at(ms: i64) -> Duration {
        Duration::from_millis(ms as u64)
    }

    #[test]
    fn cybersource_documentation_example() {
        // https://developer.cybersource.com/docs/cybs/en-us/webhooks/implementation/all/rest/webhooks.md
        let h = headers(&format!(
            "t={T};keyId={KEY_ID};sig=CzHY47nzJgCSD/BREtSIb+9l/vfkaaL4qf9n8MNJ4CY="
        ));
        verifier()
            .verify(&h, b"this is a decrypted payload", at(T))
            .unwrap();
    }

    #[test]
    fn accepts_a_signature_over_the_payload_member() {
        let payload = r#"{"data":{"id":"123"},"organizationId":"testrest"}"#;
        let body = format!(
            r#"{{"eventType":"payments.payments.accept","webhookId":"w1","retryNumber":0,"payload":{payload}}}"#
        );
        let notification = verifier()
            .verify_and_parse(
                &headers(&signed(payload.as_bytes(), T)),
                body.as_bytes(),
                at(T),
            )
            .unwrap();
        assert_eq!(
            notification.event_type.as_deref(),
            Some("payments.payments.accept")
        );
        assert_eq!(notification.payload["data"]["id"], "123");
    }

    #[test]
    fn accepts_a_signature_over_the_raw_body() {
        let body = br#"{"eventType":"x","payload":{"a":1}}"#;
        verifier()
            .verify(&headers(&signed(body, T)), body, at(T))
            .unwrap();
    }

    #[test]
    fn rejects_tampering() {
        let body = br#"{"eventType":"x","payload":{"amount":"1.00"}}"#;
        let h = headers(&signed(br#"{"amount":"1.00"}"#, T));
        let tampered = br#"{"eventType":"x","payload":{"amount":"9.00"}}"#;
        assert_eq!(
            verifier().verify(&h, tampered, at(T)),
            Err(WebhookError::BadSignature)
        );
        verifier().verify(&h, body, at(T)).unwrap();

        let other_time = headers(
            &signed(br#"{"amount":"1.00"}"#, T).replace(&T.to_string(), &(T + 1).to_string()),
        );
        assert_eq!(
            verifier().verify(&other_time, body, at(T)),
            Err(WebhookError::BadSignature)
        );
    }

    #[test]
    fn rejects_wrong_or_unknown_keys() {
        let other = WebhookVerifier::new().key(KEY_ID, "b3RoZXI=").unwrap();
        let h = headers(&signed(b"x", T));
        assert_eq!(
            other.verify(&h, b"x", at(T)),
            Err(WebhookError::BadSignature)
        );
        let unknown = WebhookVerifier::new().key("someone-else", SECRET).unwrap();
        assert!(matches!(
            unknown.verify(&h, b"x", at(T)),
            Err(WebhookError::UnknownKey(_))
        ));
    }

    #[test]
    fn timestamps_outside_the_tolerance_are_rejected_both_ways() {
        let h = headers(&signed(b"x", T));
        let v = verifier().tolerance(Duration::from_secs(60));
        v.verify(&h, b"x", at(T + 59_000)).unwrap();
        assert!(matches!(
            v.verify(&h, b"x", at(T + 61_000)),
            Err(WebhookError::Expired { .. })
        ));
        assert!(matches!(
            v.verify(&h, b"x", at(T - 61_000)),
            Err(WebhookError::Expired { .. })
        ));
    }

    #[test]
    fn header_parsing_is_lenient_about_order_and_whitespace() {
        let sig = b64::encode(hmac(b"test_key", T, b"x"));
        let h = headers(&format!(" sig={sig} ; keyId={KEY_ID};t={T} "));
        verifier().verify(&h, b"x", at(T)).unwrap();
        assert!(
            sig.ends_with('='),
            "padding must survive splitting at the first '='"
        );
    }

    #[test]
    fn malformed_headers_are_reported() {
        assert_eq!(
            verifier().verify(&HeaderMap::new(), b"x", at(T)),
            Err(WebhookError::MissingHeader)
        );
        for bad in [
            "t=1;keyId=k",
            "keyId=k;sig=AA==",
            "t=abc;keyId=k;sig=AA==",
            "t=1;keyId=k;sig=!!",
            "nonsense",
        ] {
            assert!(
                matches!(SignatureHeader::parse(bad), Err(WebhookError::Malformed(_))),
                "{bad}"
            );
        }
    }

    #[test]
    fn debug_never_prints_keys() {
        let debug = format!("{:?}", verifier());
        assert!(debug.contains(KEY_ID));
        assert!(!debug.contains("dGVzdF9rZXk") && !debug.contains("test_key"));
    }
}
