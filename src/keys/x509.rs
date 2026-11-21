//! X.509 certificate attributes Cybersource uses for key identification.
//!
//! Cybersource identifies a merchant's RSA key by the `serialNumber`
//! attribute (OID 2.5.4.5) of the certificate's subject DN. This is *not* the
//! X.509 certificate serial number; the official Java and C# SDKs fall back to
//! that when the attribute is missing, and disagree on its format. We return
//! an error instead.

use der::oid::ObjectIdentifier;
use der::{Decode, DecodePem, Encode};
use pkcs8::DecodePublicKey;
use rsa::traits::PublicKeyParts;
use rsa::{PrivateKey, PublicKey};
use x509_cert::certificate::{CertificateInner, Raw};
use x509_cert::ext::pkix::name::DirectoryString;

use crate::{Error, Result};

/// Cybersource's certificates use the ASCII digits of the decimal serial as
/// the X.509 serial number: 22 bytes, over RFC 5280's 20-octet limit. The
/// `Raw` profile skips only that length check.
type Certificate = CertificateInner<Raw>;

const SERIAL_NUMBER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.5");

/// A parsed X.509 certificate.
#[derive(Clone)]
pub struct CertificateInfo {
    cert: Certificate,
}

impl std::fmt::Debug for CertificateInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertificateInfo")
            .field(
                "subject",
                &self.cert.tbs_certificate().subject().to_string(),
            )
            .finish()
    }
}

impl CertificateInfo {
    /// Parses a PEM certificate (`BEGIN CERTIFICATE`).
    pub fn from_pem(pem: &str) -> Result<Self> {
        let cert = Certificate::from_pem(pem.trim())
            .map_err(|e| Error::Config(format!("invalid PEM certificate: {e}")))?;
        Ok(CertificateInfo { cert })
    }

    /// Parses a DER certificate.
    pub fn from_der(der: &[u8]) -> Result<Self> {
        let cert = Certificate::from_der(der)
            .map_err(|e| Error::Config(format!("invalid DER certificate: {e}")))?;
        Ok(CertificateInfo { cert })
    }

    /// The subject DN as text, e.g. `CN=testmerchant,serialNumber=…`.
    pub fn subject(&self) -> String {
        self.cert.tbs_certificate().subject().to_string()
    }

    /// When the certificate expires, as seconds since the Unix epoch.
    pub fn not_after_unix(&self) -> u64 {
        self.cert
            .tbs_certificate()
            .validity()
            .not_after
            .to_unix_duration()
            .as_secs()
    }

    /// The certificate's RSA public key.
    pub fn rsa_public_key(&self) -> Result<PublicKey> {
        let spki = self
            .cert
            .tbs_certificate()
            .subject_public_key_info()
            .to_der()
            .map_err(|e| Error::Config(format!("invalid certificate public key: {e}")))?;
        PublicKey::from_public_key_der(&spki)
            .map_err(|e| Error::Config(format!("certificate key is not RSA: {e}")))
    }

    /// Whether `key` is the private half of this certificate's key.
    pub fn matches(&self, key: &PrivateKey) -> bool {
        self.rsa_public_key()
            .is_ok_and(|public| public.n() == key.n() && public.e() == key.e())
    }

    /// The subject DN's `serialNumber` attribute: the JWT `kid` for this key.
    pub fn subject_serial_number(&self) -> Result<String> {
        self.subject_attr(SERIAL_NUMBER)?.ok_or_else(|| {
            Error::Config(format!(
                "certificate subject `{}` has no serialNumber attribute; \
                 pass the key id explicitly",
                self.cert.tbs_certificate().subject()
            ))
        })
    }

    /// The subject DN's common name (CN), if present.
    pub fn common_name(&self) -> Result<Option<String>> {
        self.cert
            .tbs_certificate()
            .subject()
            .common_name()
            .map(|cn| cn.map(|s| directory_string(&s)))
            .map_err(|e| Error::Config(format!("invalid certificate CN: {e}")))
    }

    fn subject_attr(&self, oid: ObjectIdentifier) -> Result<Option<String>> {
        self.cert
            .tbs_certificate()
            .subject()
            .by_oid::<DirectoryString>(oid)
            .map(|v| v.map(|s| directory_string(&s)))
            .map_err(|e| Error::Config(format!("invalid certificate attribute {oid}: {e}")))
    }
}

fn directory_string(s: &DirectoryString) -> String {
    s.value().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    const WITH_SERIAL: &str = include_str!("../../tests/fixtures/merchant_cert.pem");
    const WITHOUT_SERIAL: &str = include_str!("../../tests/fixtures/cert_without_serial.pem");

    #[test]
    fn reads_subject_serial_number_attribute() {
        let cert = CertificateInfo::from_pem(WITH_SERIAL).unwrap();
        assert_eq!(cert.subject_serial_number().unwrap(), "1234567890ABCDEF");
    }

    #[test]
    fn reads_common_name() {
        let cert = CertificateInfo::from_pem(WITH_SERIAL).unwrap();
        assert_eq!(cert.common_name().unwrap().as_deref(), Some("testmerchant"));
    }

    #[test]
    fn missing_serial_number_is_an_error_not_a_fallback() {
        let cert = CertificateInfo::from_pem(WITHOUT_SERIAL).unwrap();
        let err = cert.subject_serial_number().unwrap_err();
        assert!(err.to_string().contains("no serialNumber attribute"));
    }

    #[test]
    fn exposes_expiry_and_matching_key() {
        let cert = CertificateInfo::from_pem(WITH_SERIAL).unwrap();
        assert!(
            cert.not_after_unix() > 4_000_000_000,
            "fixtures are valid for 100 years"
        );
        let key = crate::keys::pem::rsa_private_key_from_pem(include_str!(
            "../../tests/fixtures/rsa_test_key.pem"
        ))
        .unwrap();
        assert!(cert.matches(&key));
        let other = crate::keys::pem::rsa_private_key_from_pem(include_str!(
            "../../tests/fixtures/sjc_test_key.pem"
        ))
        .unwrap();
        assert!(!cert.matches(&other));
    }

    #[test]
    fn accepts_cybersource_serials_longer_than_rfc5280_allows() {
        let cert =
            CertificateInfo::from_pem(include_str!("../../tests/fixtures/long_serial_cert.pem"))
                .unwrap();
        assert_eq!(
            cert.subject_serial_number().unwrap(),
            "1764300477485036947162"
        );
    }

    #[test]
    fn invalid_pem_is_a_config_error() {
        assert!(matches!(
            CertificateInfo::from_pem("nope"),
            Err(Error::Config(_))
        ));
    }
}
