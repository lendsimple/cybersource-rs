//! Request authentication: JWT (default) and legacy HTTP Signature.
//!
//! [`authenticate`] is pure: given the configuration, the exact request
//! target and body bytes, a clock and an entropy source, it returns the
//! headers to add. The body and target must be exactly what goes on the wire,
//! because both schemes sign over them.

pub mod digest;
#[cfg(feature = "http-signature")]
pub mod http_signature;
pub mod jwt;

use http::{HeaderMap, HeaderName, HeaderValue, Method};

use crate::clock::Clock;
use crate::config::{Config, Credentials};
use crate::entropy::Entropy;
use crate::{Error, Result};

/// The parts of a request that authentication signs.
#[derive(Debug, Clone, Copy)]
pub struct SigningInput<'a> {
    /// HTTP method. Only GET, POST, PUT, PATCH and DELETE are supported.
    pub method: &'a Method,
    /// Path plus query exactly as sent, e.g. `/pts/v2/payments?x=1`.
    pub target: &'a str,
    /// Body bytes exactly as sent. Ignored for GET and DELETE.
    pub body: &'a [u8],
}

impl SigningInput<'_> {
    /// Whether the method carries a body, and so a digest.
    pub(crate) fn has_body(&self) -> bool {
        matches!(*self.method, Method::POST | Method::PUT | Method::PATCH)
    }
}

/// Computes the authentication headers for a request.
///
/// Always sets `v-c-merchant-id` to the transacting merchant. JWT adds
/// `authorization`; HTTP Signature adds `date`, `signature` and, for requests
/// with a body, `digest`.
pub fn authenticate(
    config: &Config,
    input: &SigningInput<'_>,
    clock: &dyn Clock,
    entropy: &dyn Entropy,
) -> Result<HeaderMap> {
    if !matches!(
        *input.method,
        Method::GET | Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    ) {
        return Err(Error::Auth(format!(
            "Cybersource does not support signing {} requests",
            input.method
        )));
    }

    let mut headers = HeaderMap::new();
    insert(&mut headers, "v-c-merchant-id", config.merchant_id())?;

    match config.credentials() {
        Credentials::JwtSharedSecret { .. } | Credentials::JwtRsa { .. } => {
            let token = jwt::token(config, input, clock, entropy)?;
            insert(&mut headers, "authorization", &format!("Bearer {token}"))?;
        }
        #[cfg(feature = "http-signature")]
        Credentials::HttpSignature { .. } => {
            let signed = http_signature::sign(config, input, clock)?;
            insert(&mut headers, "date", &signed.date)?;
            if let Some(digest) = &signed.digest {
                insert(&mut headers, "digest", digest)?;
            }
            insert(&mut headers, "signature", &signed.signature)?;
        }
    }
    Ok(headers)
}

fn insert(headers: &mut HeaderMap, name: &'static str, value: &str) -> Result<()> {
    let mut value = HeaderValue::from_str(value)
        .map_err(|_| Error::Auth(format!("invalid characters in {name} header")))?;
    if matches!(name, "authorization" | "signature") {
        value.set_sensitive(true);
    }
    headers.insert(HeaderName::from_static(name), value);
    Ok(())
}
