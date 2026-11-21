//! Verifying capture contexts and transient tokens (Microform, Unified
//! Checkout, Flex API).
//!
//! A *capture context* is the RS256 JWT your server gets from
//! `generate_capture_context` (and the other session operations). It is
//! signed with a long-term Cybersource key, fetched by `kid` from
//! `GET /flex/v2/public-keys/{kid}`. A *transient token* is the JWT the
//! browser gets after the customer enters card data; it is signed with the
//! one-time key embedded in the capture context (`flx.jwk`).
//!
//! Unlike the official SDKs, verification pins the algorithm to RS256 and
//! checks `exp`/`iat` (with 20 seconds of leeway by default).
//!
//! ```ignore
//! let verifier = CaptureContextVerifier::new();
//! let jwt = client.capture_context().generate_capture_context(request).await?;
//! let context = verifier.verify(&client, &jwt).await?;
//! // ... later, with the transient token from the browser:
//! let token = context.verify_transient_token(&transient_jwt, now)?;
//! ```

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use bytes::Bytes;
use http::{Method, StatusCode};
use rsa::PublicKey;
use serde::Deserialize;
use serde_json::{Map, Value};

#[cfg(not(target_family = "wasm"))]
use crate::client::BlockingClient;
use crate::client::Client;
use crate::jose::jwk::RsaJwk;
use crate::jose::jws::{self, Decoded, JwsError};
use crate::operation::{Operation, OperationMeta, encode_path_segment, json_decode};
#[cfg(not(target_family = "wasm"))]
use crate::transport::BlockingHttpTransport;
use crate::transport::HttpTransport;
use crate::{Error, Result};

const DEFAULT_LEEWAY_SECS: i64 = 20;

/// `GET /flex/v2/public-keys/{kid}`: a Flex signing key (unauthenticated,
/// not in the spec).
#[derive(Debug, Clone)]
pub struct GetFlexPublicKey {
    /// The key id from a capture context's JWT header.
    pub kid: String,
}

static GET_FLEX_PUBLIC_KEY: OperationMeta = OperationMeta::new(
    "getFlexPublicKey",
    Method::GET,
    "/flex/v2/public-keys/{kid}",
)
.no_auth();

impl Operation for GetFlexPublicKey {
    type Output = RsaJwk;
    fn meta(&self) -> &'static OperationMeta {
        &GET_FLEX_PUBLIC_KEY
    }
    fn path(&self) -> Cow<'_, str> {
        Cow::Owned(format!(
            "/flex/v2/public-keys/{}",
            encode_path_segment(&self.kid)
        ))
    }
    fn decode(&self, _: StatusCode, body: &Bytes) -> Result<Self::Output> {
        json_decode(body)
    }
}

/// The `flx` claim: where and how to tokenize.
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
pub struct Flx {
    /// Tokenization path, e.g. `/flex/v2/tokens`.
    pub path: Option<String>,
    /// Opaque session data.
    pub data: Option<String>,
    /// Tokenization origin, e.g. `https://testflex.cybersource.com`.
    pub origin: Option<String>,
    /// The one-time key: card data is encrypted to it, and transient tokens
    /// are signed with it.
    pub jwk: RsaJwk,
}

/// One entry of the `ctx` claim.
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
pub struct ContextEntry {
    /// e.g. `mf-2.1.0` (Microform), `gda-0.10.0` (Unified Checkout), `api-0.1.0` (Flex API).
    #[serde(rename = "type")]
    pub kind: String,
    /// Product-specific settings (client library URL, target origins, ...).
    #[serde(default)]
    pub data: Value,
}

/// A verified capture context.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct CaptureContext {
    /// Issuer (`Flex API`).
    pub iss: Option<String>,
    /// Expiry, seconds since the epoch.
    pub exp: i64,
    /// Issued at, seconds since the epoch.
    pub iat: Option<i64>,
    /// Token id.
    pub jti: Option<String>,
    /// Tokenization details and the one-time key.
    pub flx: Option<Flx>,
    /// Product context.
    pub ctx: Vec<ContextEntry>,
    /// Every claim, including ones this version doesn't model.
    pub claims: Map<String, Value>,
    /// The JWT itself, to hand to the browser.
    pub jwt: String,
}

#[derive(Deserialize)]
struct ContextClaims {
    iss: Option<String>,
    exp: i64,
    iat: Option<i64>,
    jti: Option<String>,
    flx: Option<Flx>,
    #[serde(default)]
    ctx: Vec<ContextEntry>,
}

impl CaptureContext {
    fn from_decoded(decoded: Decoded, jwt: &str) -> Result<Self> {
        let claims: ContextClaims = serde_json::from_value(Value::Object(decoded.claims.clone()))
            .map_err(|e| {
            Error::Verification(format!("unexpected capture context claims: {e}"))
        })?;
        Ok(CaptureContext {
            iss: claims.iss,
            exp: claims.exp,
            iat: claims.iat,
            jti: claims.jti,
            flx: claims.flx,
            ctx: claims.ctx,
            claims: decoded.claims,
            jwt: jwt.trim().to_owned(),
        })
    }

    /// The client library (Microform or Unified Checkout JS) URL to load.
    pub fn client_library(&self) -> Option<&str> {
        self.ctx
            .iter()
            .find_map(|c| c.data.get("clientLibrary")?.as_str())
    }

    /// The Subresource Integrity hash for [`client_library`](Self::client_library).
    pub fn client_library_integrity(&self) -> Option<&str> {
        self.ctx
            .iter()
            .find_map(|c| c.data.get("clientLibraryIntegrity")?.as_str())
    }

    /// Verifies a transient token issued under this capture context: RS256
    /// with the context's one-time key (`flx.jwk`), matching `kid`, not
    /// expired. `now` is seconds since the epoch.
    pub fn verify_transient_token(&self, token: &str, now: i64) -> Result<TransientToken> {
        self.verify_transient_token_with_leeway(token, now, DEFAULT_LEEWAY_SECS)
    }

    /// [`verify_transient_token`](Self::verify_transient_token) with a
    /// custom clock-skew allowance in seconds.
    pub fn verify_transient_token_with_leeway(
        &self,
        token: &str,
        now: i64,
        leeway: i64,
    ) -> Result<TransientToken> {
        let flx = self
            .flx
            .as_ref()
            .ok_or_else(|| Error::Verification("capture context has no flx.jwk".into()))?;
        let key = flx
            .jwk
            .to_public_key()
            .map_err(|e| Error::Verification(e.to_string()))?;
        let decoded = jws::verify_rs256(token, &key).map_err(verification)?;
        if decoded.kid() != flx.jwk.kid.as_deref() {
            return Err(Error::Verification(
                "transient token was not issued for this capture context (kid mismatch)".into(),
            ));
        }
        jws::check_times(&decoded.claims, now, leeway).map_err(verification)?;
        TransientToken::from_decoded(decoded, token)
    }
}

/// A verified transient token: pass `jwt` as
/// `tokenInformation.transientTokenJwt` when paying.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct TransientToken {
    /// Token id (also usable as `tokenInformation.jti`).
    pub jti: Option<String>,
    /// Issuer, e.g. `Flex/08`.
    pub iss: Option<String>,
    /// Expiry, seconds since the epoch (15 minutes after issue).
    pub exp: i64,
    /// Product and version, e.g. `mf-2.0.0`.
    pub kind: Option<String>,
    /// Masked card data and other details (newer tokens).
    pub content: Option<Value>,
    /// Masked card data (older `mf-0.11.0` tokens).
    pub data: Option<Value>,
    /// Every claim.
    pub claims: Map<String, Value>,
    /// The JWT itself.
    pub jwt: String,
}

impl TransientToken {
    fn from_decoded(decoded: Decoded, jwt: &str) -> Result<Self> {
        let c = &decoded.claims;
        let text = |k: &str| c.get(k).and_then(Value::as_str).map(str::to_owned);
        Ok(TransientToken {
            jti: text("jti"),
            iss: text("iss"),
            exp: c
                .get("exp")
                .and_then(Value::as_i64)
                .ok_or_else(|| Error::Verification("transient token has no exp".into()))?,
            kind: text("type"),
            content: c.get("content").cloned(),
            data: c.get("data").cloned(),
            claims: decoded.claims.clone(),
            jwt: jwt.trim().to_owned(),
        })
    }
}

fn verification(e: JwsError) -> Error {
    Error::Verification(e.to_string())
}

/// Verifies capture contexts, fetching and caching Cybersource's signing
/// keys. Keep one per application; it is cheap to share.
#[derive(Debug)]
pub struct CaptureContextVerifier {
    keys: Mutex<HashMap<(String, String), PublicKey>>,
    leeway: i64,
}

impl Default for CaptureContextVerifier {
    fn default() -> Self {
        CaptureContextVerifier {
            keys: Mutex::new(HashMap::new()),
            leeway: DEFAULT_LEEWAY_SECS,
        }
    }
}

impl CaptureContextVerifier {
    /// A verifier with an empty key cache and 20 seconds of leeway.
    pub fn new() -> Self {
        Self::default()
    }

    /// Clock-skew allowance for `exp`/`iat` checks.
    pub fn leeway(mut self, leeway: Duration) -> Self {
        self.leeway = i64::try_from(leeway.as_secs()).unwrap_or(i64::MAX);
        self
    }

    fn cached(&self, host: &str, kid: &str) -> Option<PublicKey> {
        self.keys
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&(host.to_owned(), kid.to_owned()))
            .cloned()
    }

    fn store(&self, host: &str, kid: &str, jwk: &RsaJwk) -> Result<PublicKey> {
        let key = jwk
            .to_public_key()
            .map_err(|e| Error::Verification(e.to_string()))?;
        self.keys
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert((host.to_owned(), kid.to_owned()), key.clone());
        Ok(key)
    }

    /// Verifies `jwt` with an already-known key (no network). `now` is
    /// seconds since the epoch.
    pub fn verify_with_key(&self, jwt: &str, key: &PublicKey, now: i64) -> Result<CaptureContext> {
        let decoded = jws::verify_rs256(jwt, key).map_err(verification)?;
        jws::check_times(&decoded.claims, now, self.leeway).map_err(verification)?;
        CaptureContext::from_decoded(decoded, jwt)
    }

    fn kid(jwt: &str) -> Result<String> {
        jws::decode_unverified(jwt)
            .map_err(verification)?
            .kid()
            .map(str::to_owned)
            .ok_or_else(|| Error::Verification("capture context header has no kid".into()))
    }

    /// Verifies a capture context, fetching its signing key through
    /// `client` if it isn't cached. A cached key that no longer verifies is
    /// fetched again once (key rotation).
    pub async fn verify<T: HttpTransport>(
        &self,
        client: &Client<T>,
        jwt: &str,
    ) -> Result<CaptureContext> {
        let host = client.config().environment().host();
        let kid = Self::kid(jwt)?;
        let now = i64::try_from(client.now().as_secs()).unwrap_or(i64::MAX);
        if let Some(key) = self.cached(host, &kid)
            && let Ok(context) = self.verify_with_key(jwt, &key, now)
        {
            return Ok(context);
        }
        let jwk = client
            .execute(&GetFlexPublicKey { kid: kid.clone() })
            .await?;
        let key = self.store(host, &kid, &jwk)?;
        self.verify_with_key(jwt, &key, now)
    }

    /// Blocking [`verify`](Self::verify).
    #[cfg(not(target_family = "wasm"))]
    pub fn verify_blocking<T: BlockingHttpTransport>(
        &self,
        client: &BlockingClient<T>,
        jwt: &str,
    ) -> Result<CaptureContext> {
        let host = client.config().environment().host();
        let kid = Self::kid(jwt)?;
        let now = i64::try_from(client.now().as_secs()).unwrap_or(i64::MAX);
        if let Some(key) = self.cached(host, &kid)
            && let Ok(context) = self.verify_with_key(jwt, &key, now)
        {
            return Ok(context);
        }
        let jwk = client.execute(&GetFlexPublicKey { kid: kid.clone() })?;
        let key = self.store(host, &kid, &jwk)?;
        self.verify_with_key(jwt, &key, now)
    }
}
