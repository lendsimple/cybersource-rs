//! JWT (v2) authentication: the default scheme.
//!
//! Each request gets a fresh, short-lived (120 s) token sent as
//! `Authorization: Bearer <jwt>`. The claims bind the token to the request's
//! method, host, path and body digest.

use serde::Serialize;

use super::{SigningInput, digest};
use crate::clock::Clock;
use crate::config::{Config, Credentials};
use crate::entropy::{Entropy, uuid_v4};
use crate::jose::jws::{self, JwsKey};
use crate::{Error, Result};

/// Token lifetime Cybersource expects (`exp - iat`).
const LIFETIME_SECS: u64 = 120;

/// JWT v2 claims. Fields are declared in sorted key order: the official
/// SDKs serialize with sorted keys, and matching them keeps tokens
/// byte-identical to the SDK-generated test vectors.
#[derive(Serialize)]
struct Claims<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    digest: Option<String>,
    #[serde(rename = "digestAlgorithm", skip_serializing_if = "Option::is_none")]
    digest_algorithm: Option<&'static str>,
    exp: u64,
    iat: u64,
    iss: &'a str,
    jti: String,
    #[serde(rename = "request-host")]
    request_host: &'a str,
    #[serde(rename = "request-method")]
    request_method: &'a str,
    #[serde(rename = "request-resource-path")]
    request_resource_path: &'a str,
    #[serde(rename = "v-c-jwt-version")]
    jwt_version: &'static str,
    #[serde(rename = "v-c-merchant-id")]
    merchant_id: &'a str,
}

/// Creates the signed JWT for a request.
pub fn token(
    config: &Config,
    input: &SigningInput<'_>,
    clock: &dyn Clock,
    entropy: &dyn Entropy,
) -> Result<String> {
    let (kid, key) = match config.credentials() {
        Credentials::JwtSharedSecret { key_id, .. } => (
            key_id.as_str(),
            JwsKey::Hs256(config.credentials().secret().expect("shared secret")),
        ),
        Credentials::JwtRsa { kid, key } => (kid.as_str(), JwsKey::Rs256(key)),
        #[cfg(feature = "http-signature")]
        Credentials::HttpSignature { .. } => {
            return Err(Error::Auth("credentials are not JWT".into()));
        }
    };

    let iat = clock.now().as_secs();
    let has_body = input.has_body();
    let claims = Claims {
        digest: has_body.then(|| digest::sha256_b64(input.body)),
        digest_algorithm: has_body.then_some("SHA-256"),
        exp: iat + LIFETIME_SECS,
        iat,
        iss: config.key_owner(),
        jti: uuid_v4(entropy)?,
        request_host: config.environment().host(),
        request_method: input.method.as_str(),
        request_resource_path: input.target,
        jwt_version: "2",
        merchant_id: config.merchant_id(),
    };
    jws::sign(key, kid, &claims).map_err(|e| Error::Auth(e.to_string()))
}
