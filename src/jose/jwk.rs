//! RSA JSON Web Keys (RFC 7517), as served by Cybersource's Flex key
//! endpoint and embedded in capture contexts.

use rsa::traits::PublicKeyParts;
use rsa::{BoxedUint, PublicKey};
use serde::{Deserialize, Serialize};

use super::b64;

/// An RSA public JWK. Cybersource marks its signing keys `use: "enc"` and
/// omits `alg`, so neither is checked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RsaJwk {
    /// Key type; must be `RSA`.
    pub kty: String,
    /// Modulus, base64url.
    pub n: String,
    /// Public exponent, base64url.
    pub e: String,
    /// Key id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    /// Intended use (`enc` or `sig`), informational only.
    #[serde(rename = "use", default, skip_serializing_if = "Option::is_none")]
    pub key_use: Option<String>,
}

/// Error converting a JWK.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid RSA JWK: {0}")]
pub struct JwkError(pub &'static str);

impl RsaJwk {
    /// The RSA public key.
    pub fn to_public_key(&self) -> Result<PublicKey, JwkError> {
        if self.kty != "RSA" {
            return Err(JwkError("kty is not RSA"));
        }
        let n = b64::url_decode(&self.n).map_err(|_| JwkError("n is not base64url"))?;
        let e = b64::url_decode(&self.e).map_err(|_| JwkError("e is not base64url"))?;
        PublicKey::new(
            BoxedUint::from_be_slice_vartime(&n),
            BoxedUint::from_be_slice_vartime(&e),
        )
        .map_err(|_| JwkError("not a usable RSA public key"))
    }

    /// The JWK for `key`, with an optional key id.
    pub fn from_public_key(key: &PublicKey, kid: Option<String>) -> Self {
        let strip = |b: Box<[u8]>| {
            let start = b.iter().position(|x| *x != 0).unwrap_or(b.len());
            b64::url_encode(&b[start..])
        };
        RsaJwk {
            kty: "RSA".into(),
            n: strip(key.n().to_be_bytes()),
            e: strip(key.e().to_be_bytes()),
            kid,
            key_use: None,
        }
    }
}

#[cfg(all(test, feature = "server"))]
mod tests {
    use super::*;

    #[test]
    fn round_trips_a_public_key() {
        let key = crate::keys::pem::rsa_private_key_from_pem(include_str!(
            "../../tests/fixtures/sjc_test_key.pem"
        ))
        .unwrap()
        .to_public_key();
        let jwk = RsaJwk::from_public_key(&key, Some("k".into()));
        assert_eq!(jwk.e, "AQAB");
        assert_eq!(jwk.to_public_key().unwrap(), key);
    }

    #[test]
    fn parses_cybersource_flex_key() {
        let jwk: RsaJwk =
            serde_json::from_str(include_str!("../../tests/fixtures/flex_zu_jwk.json")).unwrap();
        assert_eq!(jwk.kid.as_deref(), Some("zu"));
        assert_eq!(jwk.key_use.as_deref(), Some("enc"));
        assert_eq!(jwk.to_public_key().unwrap().size(), 256);
    }

    #[test]
    fn rejects_non_rsa_keys() {
        let jwk = RsaJwk {
            kty: "EC".into(),
            n: "AQAB".into(),
            e: "AQAB".into(),
            kid: None,
            key_use: None,
        };
        assert!(jwk.to_public_key().is_err());
    }
}
