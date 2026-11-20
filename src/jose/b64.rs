//! Base64 helpers: standard alphabet (Cybersource digests, secrets) and
//! unpadded URL-safe alphabet (JOSE).

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

/// Standard base64 with padding.
pub fn encode(data: impl AsRef<[u8]>) -> String {
    STANDARD.encode(data)
}

/// Decodes standard base64 with padding.
pub fn decode(data: impl AsRef<[u8]>) -> Result<Vec<u8>, base64::DecodeError> {
    STANDARD.decode(data)
}

/// Unpadded URL-safe base64, as used by JOSE.
pub fn url_encode(data: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// Decodes unpadded URL-safe base64.
pub fn url_decode(data: impl AsRef<[u8]>) -> Result<Vec<u8>, base64::DecodeError> {
    URL_SAFE_NO_PAD.decode(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_round_trip() {
        assert_eq!(encode(b"\xfb\xff"), "+/8=");
        assert_eq!(decode("+/8=").unwrap(), b"\xfb\xff");
    }

    #[test]
    fn url_safe_has_no_padding_or_plus() {
        assert_eq!(url_encode(b"\xfb\xff"), "-_8");
        assert_eq!(url_decode("-_8").unwrap(), b"\xfb\xff");
    }
}
