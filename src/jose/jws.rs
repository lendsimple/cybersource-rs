//! Compact JWS signing (RFC 7515) with HS256 or RS256.

use hmac::{Hmac, KeyInit, Mac};
use rsa::PrivateKey;
use rsa::pkcs1v15::SigningKey;
use rsa::signature::{SignatureEncoding, Signer};
use serde::Serialize;
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
