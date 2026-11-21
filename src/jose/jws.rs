//! Compact JWS signing (RFC 7515) with HS256 or RS256.

use hmac::{Hmac, KeyInit, Mac};
use rsa::pkcs1v15::{Signature, SigningKey, VerifyingKey};
use rsa::signature::{SignatureEncoding, Signer, Verifier};
use rsa::{PrivateKey, PublicKey};
use serde::Serialize;
use serde_json::{Map, Value};
use sha2::Sha256;

use super::b64;

/// Key used to sign a JWS.
#[derive(Clone, Copy)]
pub enum JwsKey<'a> {
    /// HMAC-SHA256 with a raw (already base64-decoded) secret.
    Hs256(&'a [u8]),
    /// RSASSA-PKCS1-v1_5 with SHA-256.
    Rs256(&'a PrivateKey),
}

impl JwsKey<'_> {
    /// The JOSE `alg` name.
    pub fn alg(&self) -> &'static str {
        match self {
            JwsKey::Hs256(_) => "HS256",
            JwsKey::Rs256(_) => "RS256",
        }
    }
}

impl std::fmt::Debug for JwsKey<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "JwsKey::{}([REDACTED])", self.alg())
    }
}

#[derive(Serialize)]
struct Header<'a> {
    alg: &'a str,
    kid: &'a str,
    typ: &'a str,
}

/// Error from signing a JWS.
#[derive(Debug, thiserror::Error)]
pub enum JwsError {
    /// The claims could not be serialized.
    #[error("failed to serialize JWS payload: {0}")]
    Serialize(#[from] serde_json::Error),
    /// The HMAC key was rejected.
    #[error("invalid HMAC key")]
    InvalidHmacKey,
    /// RSA signing failed.
    #[error("RSA signing failed: {0}")]
    Rsa(String),
    /// Not a well-formed compact JWS.
    #[error("malformed JWT: {0}")]
    Malformed(&'static str),
    /// The token is signed with an algorithm other than the one required.
    #[error("JWT algorithm {0:?} is not allowed; expected RS256")]
    Algorithm(String),
    /// The signature does not verify with the key.
    #[error("JWT signature is invalid")]
    BadSignature,
    /// `exp` is in the past.
    #[error("JWT expired at {exp} (now {now})")]
    Expired {
        /// The token's `exp`.
        exp: i64,
        /// The time checked against.
        now: i64,
    },
    /// `nbf` or `iat` is in the future.
    #[error("JWT is not valid yet (now {now})")]
    NotYetValid {
        /// The time checked against.
        now: i64,
    },
}

/// The decoded header and claims of a compact JWS.
#[derive(Debug, Clone, PartialEq)]
pub struct Decoded {
    /// The protected header.
    pub header: Map<String, Value>,
    /// The claims.
    pub claims: Map<String, Value>,
}

impl Decoded {
    /// The header's `kid`.
    pub fn kid(&self) -> Option<&str> {
        self.header.get("kid").and_then(Value::as_str)
    }
}

fn split(jwt: &str) -> Result<(&str, &str, &str), JwsError> {
    let mut parts = jwt.trim().split('.');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(h), Some(c), Some(s), None) => Ok((h, c, s)),
        _ => Err(JwsError::Malformed("expected 3 dot-separated parts")),
    }
}

fn json_part(part: &str) -> Result<Map<String, Value>, JwsError> {
    let bytes = b64::url_decode(part).map_err(|_| JwsError::Malformed("invalid base64url"))?;
    serde_json::from_slice(&bytes).map_err(|_| JwsError::Malformed("part is not a JSON object"))
}

/// Decodes a JWS **without verifying it**: only to pick the key (`kid`).
pub fn decode_unverified(jwt: &str) -> Result<Decoded, JwsError> {
    let (header, claims, _) = split(jwt)?;
    Ok(Decoded {
        header: json_part(header)?,
        claims: json_part(claims)?,
    })
}

/// Verifies an RS256 JWS with `key`. Any other `alg` (including `none` and
/// HS256) is rejected. Time claims are checked separately with
/// [`check_times`].
pub fn verify_rs256(jwt: &str, key: &PublicKey) -> Result<Decoded, JwsError> {
    let (header_b64, claims_b64, signature_b64) = split(jwt)?;
    let decoded = Decoded {
        header: json_part(header_b64)?,
        claims: json_part(claims_b64)?,
    };
    match decoded.header.get("alg").and_then(Value::as_str) {
        Some("RS256") => {}
        other => return Err(JwsError::Algorithm(other.unwrap_or("<missing>").to_owned())),
    }
    let signature = b64::url_decode(signature_b64).map_err(|_| JwsError::BadSignature)?;
    let signature =
        Signature::try_from(signature.as_slice()).map_err(|_| JwsError::BadSignature)?;
    let signing_input = &jwt.trim()[..header_b64.len() + 1 + claims_b64.len()];
    VerifyingKey::<Sha256>::new(key.clone())
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| JwsError::BadSignature)?;
    Ok(decoded)
}

/// Checks `exp`, `nbf` and `iat` against `now` (seconds since the epoch),
/// allowing `leeway` seconds of clock skew. `exp` is required.
pub fn check_times(claims: &Map<String, Value>, now: i64, leeway: i64) -> Result<(), JwsError> {
    let time = |name: &str| claims.get(name).and_then(Value::as_i64);
    let exp = time("exp").ok_or(JwsError::Malformed("missing exp claim"))?;
    if now > exp.saturating_add(leeway) {
        return Err(JwsError::Expired { exp, now });
    }
    for name in ["nbf", "iat"] {
        if time(name).is_some_and(|t| t > now.saturating_add(leeway)) {
            return Err(JwsError::NotYetValid { now });
        }
    }
    Ok(())
}

/// Signs `claims` as a compact JWS with header `{"alg","kid","typ":"JWT"}`.
pub fn sign(key: JwsKey<'_>, kid: &str, claims: &impl Serialize) -> Result<String, JwsError> {
    let header = Header {
        alg: key.alg(),
        kid,
        typ: "JWT",
    };
    let signing_input = format!(
        "{}.{}",
        b64::url_encode(serde_json::to_vec(&header)?),
        b64::url_encode(serde_json::to_vec(claims)?)
    );
    let signature = match key {
        JwsKey::Hs256(secret) => {
            let mut mac =
                Hmac::<Sha256>::new_from_slice(secret).map_err(|_| JwsError::InvalidHmacKey)?;
            mac.update(signing_input.as_bytes());
            mac.finalize().into_bytes().to_vec()
        }
        JwsKey::Rs256(private_key) => SigningKey::<Sha256>::new(private_key.clone())
            .try_sign(signing_input.as_bytes())
            .map_err(|e| JwsError::Rsa(e.to_string()))?
            .to_vec(),
    };
    Ok(format!("{signing_input}.{}", b64::url_encode(signature)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn parts(jws: &str) -> Vec<serde_json::Value> {
        jws.split('.')
            .take(2)
            .map(|p| serde_json::from_slice(&b64::url_decode(p).unwrap()).unwrap())
            .collect()
    }

    #[test]
    fn hs256_matches_independent_known_answer() {
        // Computed with Python's hmac/hashlib/base64 over the same compact JSON.
        let jws = sign(JwsKey::Hs256(b"secret"), "k1", &json!({"a": 1})).unwrap();
        assert_eq!(
            jws,
            "eyJhbGciOiJIUzI1NiIsImtpZCI6ImsxIiwidHlwIjoiSldUIn0.eyJhIjoxfQ.\
             9WgIshmDo2r4kuprqtY1pT85oWWTMG8l8AGG9Cnwz4c"
        );
    }

    #[cfg(feature = "server")]
    #[test]
    fn rs256_matches_openssl_known_answer() {
        let pem = include_str!("../../tests/fixtures/rsa_test_key.pem");
        let key = crate::keys::pem::rsa_private_key_from_pem(pem).unwrap();
        let expected = include_str!("../../tests/fixtures/rs256_known_answer.txt").trim();
        let jws = sign(JwsKey::Rs256(&key), "k1", &json!({"a": 1})).unwrap();
        assert_eq!(jws, expected);
    }

    #[cfg(feature = "server")]
    fn rsa_key() -> PrivateKey {
        crate::keys::pem::rsa_private_key_from_pem(include_str!(
            "../../tests/fixtures/rsa_test_key.pem"
        ))
        .unwrap()
    }

    #[cfg(feature = "server")]
    #[test]
    fn verifies_its_own_rs256_tokens_and_rejects_tampering() {
        let key = rsa_key();
        let jws = sign(JwsKey::Rs256(&key), "k1", &json!({"a": 1, "exp": 10})).unwrap();
        let decoded = verify_rs256(&jws, &key.to_public_key()).unwrap();
        assert_eq!(decoded.kid(), Some("k1"));
        assert_eq!(decoded.claims["a"], 1);

        let mut parts: Vec<String> = jws.split('.').map(str::to_owned).collect();
        parts[1] = b64::url_encode(br#"{"a":2,"exp":10}"#);
        assert!(matches!(
            verify_rs256(&parts.join("."), &key.to_public_key()),
            Err(JwsError::BadSignature)
        ));
    }

    #[cfg(feature = "server")]
    #[test]
    fn rejects_other_algorithms() {
        let key = rsa_key();
        let hs = sign(JwsKey::Hs256(b"secret"), "k", &json!({"exp": 10})).unwrap();
        assert!(
            matches!(verify_rs256(&hs, &key.to_public_key()), Err(JwsError::Algorithm(a)) if a == "HS256")
        );
        let none = format!(
            "{}.{}.",
            b64::url_encode(br#"{"alg":"none"}"#),
            b64::url_encode(b"{}")
        );
        assert!(matches!(
            verify_rs256(&none, &key.to_public_key()),
            Err(JwsError::Algorithm(_))
        ));
    }

    #[test]
    fn time_checks_with_leeway() {
        let claims = |v: serde_json::Value| v.as_object().unwrap().clone();
        assert!(check_times(&claims(json!({"exp": 100})), 110, 20).is_ok());
        assert!(matches!(
            check_times(&claims(json!({"exp": 100})), 121, 20),
            Err(JwsError::Expired { .. })
        ));
        assert!(matches!(
            check_times(&claims(json!({"exp": 999, "iat": 200})), 100, 20),
            Err(JwsError::NotYetValid { .. })
        ));
        assert!(
            check_times(&claims(json!({})), 0, 0).is_err(),
            "exp is required"
        );
    }

    #[test]
    fn header_carries_alg_kid_and_typ() {
        let jws = sign(JwsKey::Hs256(b"secret"), "my-kid", &json!({})).unwrap();
        assert_eq!(
            parts(&jws)[0],
            json!({"alg": "HS256", "kid": "my-kid", "typ": "JWT"})
        );
    }

    #[test]
    fn debug_redacts_key_material() {
        assert_eq!(
            format!("{:?}", JwsKey::Hs256(b"secret")),
            "JwsKey::HS256([REDACTED])"
        );
    }
}
