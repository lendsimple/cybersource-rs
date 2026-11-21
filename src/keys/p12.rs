//! PKCS#12 (`.p12`) key stores, as downloaded from the Business Center.
//!
//! A Cybersource P12 holds the merchant's certificate and private key, the
//! `CyberSource_SJC_US` certificate used for request message-level
//! encryption, and a root CA. Certificates are found by subject CN (bag
//! aliases are not reliable), and a private key is paired with a certificate
//! by comparing public keys, never by position.

use pkcs8::DecodePrivateKey;
use rsa::PrivateKey;

use super::x509::CertificateInfo;
use crate::{Error, Result};

/// CN of the certificate Cybersource uses to receive encrypted requests.
pub const CYBERSOURCE_MLE_CN: &str = "CyberSource_SJC_US";

/// The certificates and private keys in a P12 file.
pub struct P12 {
    certs: Vec<CertificateInfo>,
    keys: Vec<PrivateKey>,
}

impl std::fmt::Debug for P12 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("P12")
            .field("certificates", &self.certs)
            .field("private_keys", &self.keys.len())
            .finish()
    }
}

impl P12 {
    /// Opens a P12 with its password.
    pub fn parse(bytes: &[u8], password: &str) -> Result<Self> {
        let archive = p12_keystore::Pkcs12Archive::from_pkcs12(bytes, password).map_err(|e| {
            Error::Config(format!(
                "could not open P12 (wrong password or corrupt file?): {e}"
            ))
        })?;
        let certs = archive
            .certs
            .iter()
            .map(|bag| CertificateInfo::from_der(bag.cert.as_der()))
            .collect::<Result<Vec<_>>>()?;
        let keys = archive
            .keys
            .iter()
            .map(|bag| {
                PrivateKey::from_pkcs8_der(bag.key.as_der())
                    .map_err(|e| Error::Config(format!("P12 private key is not RSA: {e}")))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(P12 { certs, keys })
    }

    /// Every certificate in the file.
    pub fn certificates(&self) -> &[CertificateInfo] {
        &self.certs
    }

    /// The certificate whose subject CN is `cn` (case-insensitive).
    pub fn certificate(&self, cn: &str) -> Option<&CertificateInfo> {
        self.certs.iter().find(|c| {
            c.common_name()
                .ok()
                .flatten()
                .is_some_and(|name| name.eq_ignore_ascii_case(cn))
        })
    }

    /// The certificate with CN `cn` and the private key that belongs to it.
    pub fn identity(&self, cn: &str) -> Result<(PrivateKey, CertificateInfo)> {
        let cert = self.certificate(cn).ok_or_else(|| {
            Error::Config(format!(
                "P12 has no certificate with CN `{cn}`; it has: {}",
                self.common_names().join(", ")
            ))
        })?;
        let key = self.keys.iter().find(|k| cert.matches(k)).ok_or_else(|| {
            Error::Config(format!(
                "P12 has no private key for the certificate with CN `{cn}`"
            ))
        })?;
        Ok((key.clone(), cert.clone()))
    }

    /// The `CyberSource_SJC_US` request-encryption certificate, if present.
    pub fn mle_certificate(&self) -> Option<&CertificateInfo> {
        self.certificate(CYBERSOURCE_MLE_CN)
    }

    fn common_names(&self) -> Vec<String> {
        self.certs
            .iter()
            .filter_map(|c| c.common_name().ok().flatten())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::pem::rsa_private_key_from_pem;

    const MERCHANT_KEY: &str = include_str!("../../tests/fixtures/rsa_test_key.pem");

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(format!(
            "{}/tests/fixtures/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    }

    #[test]
    fn opens_cybersource_shaped_modern_and_legacy_p12s() {
        for file in ["cybs_shaped.p12", "testmerchant.p12", "legacy.p12"] {
            let p12 = P12::parse(&fixture(file), "testmerchant").unwrap();
            let (key, cert) = p12.identity("TestMerchant").unwrap();
            assert_eq!(
                key,
                rsa_private_key_from_pem(MERCHANT_KEY).unwrap(),
                "{file}"
            );
            assert_eq!(cert.subject_serial_number().unwrap(), "1234567890ABCDEF");
        }
    }

    #[test]
    fn finds_the_request_mle_certificate() {
        let p12 = P12::parse(&fixture("cybs_shaped.p12"), "testmerchant").unwrap();
        let mle = p12.mle_certificate().expect("CyberSource_SJC_US");
        assert_eq!(mle.subject_serial_number().unwrap(), "SJC0000000001");
        assert!(
            P12::parse(&fixture("testmerchant.p12"), "testmerchant")
                .unwrap()
                .mle_certificate()
                .is_none()
        );
    }

    #[test]
    fn the_key_matches_the_certificate_not_the_file_order() {
        // The SJC cert in this file has no private key here; asking for it
        // must not hand back the merchant's key.
        let p12 = P12::parse(&fixture("cybs_shaped.p12"), "testmerchant").unwrap();
        let err = p12.identity(CYBERSOURCE_MLE_CN).unwrap_err();
        assert!(err.to_string().contains("no private key"), "{err}");
    }

    #[test]
    fn wrong_password_is_a_clear_config_error() {
        let err = P12::parse(&fixture("cybs_shaped.p12"), "nope").unwrap_err();
        assert!(err.to_string().contains("wrong password"), "{err}");
    }

    #[test]
    fn missing_cn_lists_what_is_there() {
        let p12 = P12::parse(&fixture("cybs_shaped.p12"), "testmerchant").unwrap();
        let err = p12.identity("someone_else").unwrap_err().to_string();
        assert!(
            err.contains("testmerchant") && err.contains("CyberSource_SJC_US"),
            "{err}"
        );
    }
}
