//! Removing card data, personal data and secrets before anything is logged.
//!
//! The field list is generated from `spec/codegen.toml [sensitive]`, the same
//! list that makes generated models redact those fields in `Debug` output.

use http::HeaderMap;
use serde_json::{Map, Value};

use crate::generated::{SENSITIVE_FIELDS, SENSITIVE_NUMBER_PARENTS};

const REDACTED: &str = "[REDACTED]";

/// Personal data redacted in logs (in addition to the generated card and
/// credential fields).
const PERSONAL: &[&str] = &[
    "firstName",
    "lastName",
    "middleName",
    "email",
    "phoneNumber",
    "address1",
    "address2",
    "dateOfBirth",
    "personalIdentification",
    "ipAddress",
];

/// Headers never logged.
const SECRET_HEADERS: &[&str] = &["authorization", "signature", "v-c-signature"];

fn sensitive(key: &str, parent: Option<&str>) -> bool {
    SENSITIVE_FIELDS.contains(&key)
        || PERSONAL.contains(&key)
        || (key == "number"
            && parent.is_some_and(|p| {
                let p = p.to_ascii_lowercase();
                SENSITIVE_NUMBER_PARENTS.iter().any(|s| p.contains(s))
            }))
}

/// A copy of `value` with sensitive values replaced by `"[REDACTED]"`.
pub fn redact_json(value: &Value) -> Value {
    redact(value, None)
}

fn redact(value: &Value, parent: Option<&str>) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| {
                    let v = if sensitive(k, parent) && !v.is_null() {
                        Value::String(REDACTED.into())
                    } else {
                        redact(v, Some(k))
                    };
                    (k.clone(), v)
                })
                .collect::<Map<_, _>>(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(|v| redact(v, parent)).collect()),
        other => other.clone(),
    }
}

/// A redacted, loggable rendering of a body: redacted JSON, or a size
/// placeholder for anything else (CSV, PDF, JWTs).
pub fn redact_body(body: &[u8]) -> String {
    if body.is_empty() {
        return String::new();
    }
    match serde_json::from_slice::<Value>(body) {
        Ok(value @ (Value::Object(_) | Value::Array(_))) => redact_json(&value).to_string(),
        _ => format!("<{} bytes, not JSON>", body.len()),
    }
}

/// Header names and values safe to log: authentication headers are
/// replaced by `"[REDACTED]"`.
pub fn redact_headers(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| {
            let value = if SECRET_HEADERS.contains(&name.as_str()) {
                REDACTED.to_owned()
            } else {
                value.to_str().unwrap_or("<binary>").to_owned()
            };
            (name.as_str().to_owned(), value)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn redacts_card_personal_and_secret_fields() {
        let out = redact_json(&json!({
            "paymentInformation": { "card": { "number": "4111111111111111", "securityCode": "123", "expirationYear": "2031" } },
            "orderInformation": { "billTo": { "firstName": "Jane", "country": "US" }, "amountDetails": { "totalAmount": "10.00" } },
            "buyerInformation": { "personalIdentification": [{ "id": "x" }] },
            "phone": { "number": "5551234" },
            "encryptedRequest": "eyJ...",
        }));
        assert_eq!(out["paymentInformation"]["card"]["number"], REDACTED);
        assert_eq!(out["paymentInformation"]["card"]["securityCode"], REDACTED);
        assert_eq!(out["paymentInformation"]["card"]["expirationYear"], "2031");
        assert_eq!(out["orderInformation"]["billTo"]["firstName"], REDACTED);
        assert_eq!(out["orderInformation"]["billTo"]["country"], "US");
        assert_eq!(
            out["orderInformation"]["amountDetails"]["totalAmount"],
            "10.00"
        );
        assert_eq!(out["buyerInformation"]["personalIdentification"], REDACTED);
        assert_eq!(
            out["phone"]["number"], "5551234",
            "number is only sensitive under card/account/..."
        );
        assert_eq!(out["encryptedRequest"], REDACTED);
    }

    #[test]
    fn non_json_bodies_are_summarized() {
        assert_eq!(redact_body(b"a,b,c"), "<5 bytes, not JSON>");
        assert_eq!(redact_body(b""), "");
    }

    #[test]
    fn auth_headers_are_hidden() {
        let mut h = HeaderMap::new();
        h.insert("authorization", "Bearer x".parse().unwrap());
        h.insert("v-c-merchant-id", "m".parse().unwrap());
        let out = redact_headers(&h);
        assert!(out.contains(&("authorization".into(), REDACTED.into())));
        assert!(out.contains(&("v-c-merchant-id".into(), "m".into())));
    }
}
