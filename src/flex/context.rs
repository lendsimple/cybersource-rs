//! Capture contexts and transient tokens: the types, and the checks that
//! need no network (shared by the server-side verifier and tokenizing clients).

use serde::Deserialize;
use serde_json::{Map, Value};

use crate::jose::jwk::RsaJwk;
use crate::jose::jws::{self, Decoded, JwsError};
use crate::{Error, Result};

/// Clock-skew allowance for `exp`/`iat`, as the official samples use.
pub(crate) const DEFAULT_LEEWAY_SECS: i64 = 20;

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
    pub(crate) fn from_decoded(decoded: Decoded, jwt: &str) -> Result<Self> {
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

    /// Decodes a capture context **without verifying its signature**.
    ///
    /// For tokenizing clients, which received the context from your server
    /// and need its key and field lists. Your server verifies the context
    /// with [`CaptureContextVerifier`] and the resulting transient token with
    /// [`CaptureContext::verify_transient_token`].
    ///
    /// [`CaptureContextVerifier`]: https://docs.rs/cybersource/latest/cybersource/capture_context/struct.CaptureContextVerifier.html
    pub fn parse_unverified(jwt: &str) -> Result<Self> {
        let decoded = jws::decode_unverified(jwt).map_err(verification)?;
        Self::from_decoded(decoded, jwt)
    }

    /// Fails if the context has expired at `now` (seconds since the epoch),
    /// allowing 20 seconds of clock skew.
    pub fn ensure_fresh(&self, now: i64) -> Result<()> {
        if now > self.exp.saturating_add(DEFAULT_LEEWAY_SECS) {
            return Err(Error::Verification(format!(
                "capture context expired at {} (now {now})",
                self.exp
            )));
        }
        Ok(())
    }

    /// The context type, e.g. `api-0.1.0` (Flex API), `mf-2.1.0`
    /// (Microform) or `gda-0.10.0` (Unified Checkout).
    pub fn kind(&self) -> Option<&str> {
        self.ctx.first().map(|c| c.kind.as_str())
    }

    /// Fields the session requires, as dotted paths such as
    /// `paymentInformation.card.number` (Flex API contexts).
    pub fn required_fields(&self) -> Vec<String> {
        self.field_list("requiredFields")
    }

    /// Fields the session accepts but does not require.
    pub fn optional_fields(&self) -> Vec<String> {
        self.field_list("optionalFields")
    }

    fn field_list(&self, key: &str) -> Vec<String> {
        self.ctx
            .iter()
            .filter_map(|c| c.data.get(key)?.as_array())
            .flatten()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect()
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
    pub(crate) fn from_decoded(decoded: Decoded, jwt: &str) -> Result<Self> {
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

pub(crate) fn verification(e: JwsError) -> Error {
    Error::Verification(e.to_string())
}
