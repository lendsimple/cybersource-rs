//! RSA private keys from PEM (PKCS#8 or PKCS#1).

use pkcs1::DecodeRsaPrivateKey;
use pkcs8::DecodePrivateKey;
use rsa::PrivateKey;

use crate::{Error, Result};

/// Drops any text before the PEM block, such as the "Bag Attributes"
/// preamble `openssl pkcs12` writes.
fn pem_block(pem: &str) -> &str {
    let pem = pem.trim();
    pem.find("-----BEGIN").map_or(pem, |i| &pem[i..])
}

/// Parses an unencrypted RSA private key in PKCS#8 (`BEGIN PRIVATE KEY`)
/// or PKCS#1 (`BEGIN RSA PRIVATE KEY`) PEM form.
pub fn rsa_private_key_from_pem(pem: &str) -> Result<PrivateKey> {
    let pem = pem_block(pem);
    if pem.starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----") {
        return Err(Error::Config(
            "this key is encrypted; use the password-taking constructor".into(),
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

/// Parses a password-protected PKCS#8 RSA key (`BEGIN ENCRYPTED PRIVATE KEY`,
/// e.g. PBES2 with PBKDF2 and AES-256-CBC).
pub fn rsa_private_key_from_encrypted_pem(pem: &str, password: &str) -> Result<PrivateKey> {
    PrivateKey::from_pkcs8_encrypted_pem(pem_block(pem), password).map_err(|e| {
        Error::Config(format!(
            "could not decrypt PKCS#8 private key (wrong password?): {e}"
        ))
    })
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

    const RESPONSE_KEY: &str = include_str!("../../tests/fixtures/response_mle_key.pem");
    const ENCRYPTED: &str = include_str!("../../tests/fixtures/response_mle_key_encrypted.pem");
    const PREAMBLE: &str = include_str!("../../tests/fixtures/response_mle_key_with_preamble.pem");

    #[test]
    fn encrypted_key_needs_the_password_constructor() {
        let err = rsa_private_key_from_pem(ENCRYPTED).unwrap_err();
        assert!(err.to_string().contains("password"), "{err}");
    }

    #[test]
    fn encrypted_pkcs8_decrypts_with_the_password() {
        assert_eq!(
            rsa_private_key_from_encrypted_pem(ENCRYPTED, "secret-pw").unwrap(),
            rsa_private_key_from_pem(RESPONSE_KEY).unwrap()
        );
        assert!(rsa_private_key_from_encrypted_pem(ENCRYPTED, "wrong").is_err());
    }

    #[test]
    fn text_before_the_pem_block_is_skipped() {
        assert_eq!(
            rsa_private_key_from_pem(PREAMBLE).unwrap(),
            rsa_private_key_from_pem(RESPONSE_KEY).unwrap()
        );
    }

    #[test]
    fn garbage_is_a_config_error() {
        assert!(matches!(
            rsa_private_key_from_pem("not a key"),
            Err(Error::Config(_))
        ));
    }
}
