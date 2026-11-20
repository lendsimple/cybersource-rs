//! Legacy HTTP Signature authentication (HMAC-SHA256).
//!
//! Cybersource retires this scheme in March 2027. The signing string is
//! lowercase `name: value` lines joined by `\n` with no trailing newline:
//!
//! ```text
//! host: apitest.cybersource.com
//! date: Thu, 05 Nov 2026 08:00:00 GMT
//! request-target: post /pts/v2/payments
//! digest: SHA-256=...            (POST, PUT and PATCH only)
//! v-c-merchant-id: <portfolio id with a meta key, otherwise merchant id>
//! ```
//!
//! The pseudo-header is `request-target`, without the parentheses of the
//! HTTP Signatures draft; Cybersource rejects `(request-target)`.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use super::{SigningInput, digest};
use crate::clock::Clock;
use crate::config::Config;
use crate::jose::b64;
use crate::{Error, Result};

/// Header values produced by HTTP Signature authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedHeaders {
    /// The `date` header (IMF-fixdate).
    pub date: String,
    /// The `digest` header, for requests with a body.
    pub digest: Option<String>,
    /// The `signature` header.
    pub signature: String,
}

/// Signs a request with the configured HTTP Signature credentials.
pub fn sign(config: &Config, input: &SigningInput<'_>, clock: &dyn Clock) -> Result<SignedHeaders> {
    let key_id = match config.credentials() {
        crate::config::Credentials::HttpSignature { key_id, .. } => key_id,
        _ => return Err(Error::Auth("credentials are not HTTP Signature".into())),
    };
    let secret = config
        .credentials()
        .secret()
        .expect("HTTP Signature has a secret");

    let date = httpdate::fmt_http_date(std::time::UNIX_EPOCH + clock.now());
    let digest = input
        .has_body()
        .then(|| digest::http_digest_header(input.body));

    let mut lines = vec![
        format!("host: {}", config.environment().host()),
        format!("date: {date}"),
        format!(
            "request-target: {} {}",
            input.method.as_str().to_ascii_lowercase(),
            input.target
        ),
    ];
    let mut signed_headers = "host date request-target".to_string();
    if let Some(digest) = &digest {
        lines.push(format!("digest: {digest}"));
        signed_headers.push_str(" digest");
    }
    lines.push(format!("v-c-merchant-id: {}", config.key_owner()));
    signed_headers.push_str(" v-c-merchant-id");

    let mut mac = Hmac::<Sha256>::new_from_slice(secret)
        .map_err(|_| Error::Auth("invalid HTTP Signature secret".into()))?;
    mac.update(lines.join("\n").as_bytes());
    let signature = b64::encode(mac.finalize().into_bytes());

    Ok(SignedHeaders {
        date,
        digest,
        signature: format!(
            r#"keyid="{key_id}", algorithm="HmacSHA256", headers="{signed_headers}", signature="{signature}""#
        ),
    })
}
