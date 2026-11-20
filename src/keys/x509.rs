//! X.509 certificate attributes Cybersource uses for key identification.
//!
//! Cybersource identifies a merchant's RSA key by the `serialNumber`
//! attribute (OID 2.5.4.5) of the certificate's subject DN. This is *not* the
//! X.509 certificate serial number; the official Java and C# SDKs fall back to
//! that when the attribute is missing, and disagree on its format. We return
//! an error instead.

use der::DecodePem;
use der::oid::ObjectIdentifier;
use x509_cert::Certificate;
use x509_cert::ext::pkix::name::DirectoryString;

use crate::{Error, Result};

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
    fn invalid_pem_is_a_config_error() {
        assert!(matches!(
            CertificateInfo::from_pem("nope"),
            Err(Error::Config(_))
        ));
    }
}
