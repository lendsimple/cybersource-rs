//! RSA private keys from PEM (PKCS#8 or PKCS#1).

use pkcs1::DecodeRsaPrivateKey;
use pkcs8::DecodePrivateKey;
use rsa::PrivateKey;

use crate::{Error, Result};

/// Parses an unencrypted RSA private key in PKCS#8 (`BEGIN PRIVATE KEY`)
/// or PKCS#1 (`BEGIN RSA PRIVATE KEY`) PEM form.
pub fn rsa_private_key_from_pem(pem: &str) -> Result<PrivateKey> {
    let pem = pem.trim();
    if pem.starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----") {
        return Err(Error::Config(
            "encrypted PKCS#8 keys are not supported; decrypt the key or use a P12".into(),
        ));
    }
    if pem.starts_with("-----BEGIN RSA PRIVATE KEY-----") {
        PrivateKey::from_pkcs1_pem(pem)
            .map_err(|e| Error::Config(format!("invalid PKCS#1 RSA private key: {e}")))
    } else {
        PrivateKey::from_pkcs8_pem(pem)
            .map_err(|e| Error::Config(format!("invalid PKCS#8 RSA private key: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PKCS8: &str = include_str!("../../tests/fixtures/rsa_test_key.pem");
    const PKCS1: &str = include_str!("../../tests/fixtures/rsa_test_key_pkcs1.pem");

    #[test]
    fn pkcs8_and_pkcs1_load_the_same_key() {
        assert_eq!(
            rsa_private_key_from_pem(PKCS8).unwrap(),
            rsa_private_key_from_pem(PKCS1).unwrap()
        );
    }

    #[test]
    fn encrypted_key_is_rejected_with_explanation() {
        let err = rsa_private_key_from_pem(
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAA==\n-----END ENCRYPTED PRIVATE KEY-----",
        )
        .unwrap_err();
        assert!(err.to_string().contains("encrypted PKCS#8"));
    }

    #[test]
    fn garbage_is_a_config_error() {
        assert!(matches!(
            rsa_private_key_from_pem("not a key"),
            Err(Error::Config(_))
        ));
    }
}
