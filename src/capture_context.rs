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

#[cfg(not(target_family = "wasm"))]
use crate::client::BlockingClient;
use crate::client::Client;
use crate::jose::jwk::RsaJwk;
use crate::jose::jws;
use crate::operation::{Operation, OperationMeta, encode_path_segment, json_decode};
#[cfg(not(target_family = "wasm"))]
use crate::transport::BlockingHttpTransport;
use crate::transport::HttpTransport;
use crate::{Error, Result};

pub use crate::flex::context::{CaptureContext, ContextEntry, Flx, TransientToken};
use crate::flex::context::{DEFAULT_LEEWAY_SECS, verification};

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
