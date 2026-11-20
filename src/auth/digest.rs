//! SHA-256 body digests.
//!
//! HTTP Signature sends `SHA-256=<b64>`, while the JWT `digest` claim is the
//! bare `<b64>`. Both hash the exact body bytes sent on the wire.

use sha2::{Digest, Sha256};

use crate::jose::b64;

/// Base64 (standard alphabet) of the SHA-256 of `body`.
pub fn sha256_b64(body: &[u8]) -> String {
    b64::encode(Sha256::digest(body))
}

/// The HTTP Signature `digest` header value: `SHA-256=<b64>`.
pub fn http_digest_header(body: &[u8]) -> String {
    format!("SHA-256={}", sha256_b64(body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_of_empty_object() {
        // printf '{}' | openssl dgst -sha256 -binary | base64
        assert_eq!(
            sha256_b64(b"{}"),
            "RBNvo1WzZ4oRRq0W9+hknpT7T8If536DEMBg9hyq/4o="
        );
    }

    #[test]
    fn header_form_has_prefix() {
        assert_eq!(
            http_digest_header(b"{}"),
            "SHA-256=RBNvo1WzZ4oRRq0W9+hknpT7T8If536DEMBg9hyq/4o="
        );
    }
}
