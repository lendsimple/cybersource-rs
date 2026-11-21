//! Message-level encryption (MLE): JWE-encrypted request and response bodies.
//!
//! Cybersource requires MLE for some operations and allows it for others;
//! each generated operation records which (see [`OperationMeta`]). Requests
//! are encrypted to Cybersource's `CyberSource_SJC_US` certificate; responses
//! are encrypted to the merchant's own response-MLE key. Unlike the official
//! SDKs, this crate never silently sends a mandatory-MLE request in plaintext.
//!
//! [`OperationMeta`]: crate::operation::OperationMeta

pub mod policy;

use std::collections::BTreeMap;

use rsa::{PrivateKey, PublicKey};

use crate::Result;
use crate::keys::pem;
use crate::keys::x509::CertificateInfo;

/// Cybersource's certificate for encrypting requests.
#[derive(Debug, Clone)]
pub struct RequestMleCert {
    pub(crate) kid: String,
    pub(crate) key: PublicKey,
    pub(crate) cert: CertificateInfo,
}

impl RequestMleCert {
    /// From a PEM certificate (Cybersource's `CyberSource_SJC_US` cert).
    pub fn from_pem(certificate_pem: &str) -> Result<Self> {
        Self::from_certificate(CertificateInfo::from_pem(certificate_pem)?)
    }

    /// From the `CyberSource_SJC_US` certificate inside a Business Center P12.
    #[cfg(feature = "p12")]
    pub fn from_p12(p12: &[u8], password: &str) -> Result<Self> {
        let store = crate::keys::p12::P12::parse(p12, password)?;
        let cert = store.mle_certificate().cloned().ok_or_else(|| {
            crate::Error::Config(format!(
                "P12 has no `{}` certificate for request encryption",
                crate::keys::p12::CYBERSOURCE_MLE_CN
            ))
        })?;
        Self::from_certificate(cert)
    }

    pub(crate) fn from_certificate(cert: CertificateInfo) -> Result<Self> {
        Ok(RequestMleCert {
            kid: cert.subject_serial_number()?,
            key: cert.rsa_public_key()?,
            cert,
        })
    }

    /// The JWE `kid`: the certificate subject's `serialNumber`.
    pub fn kid(&self) -> &str {
        &self.kid
    }
}

/// The merchant's private key for decrypting responses, and its key id.
#[derive(Clone)]
pub struct ResponseMleKey {
    pub(crate) kid: Option<String>,
    pub(crate) key: PrivateKey,
    pub(crate) cert: Option<CertificateInfo>,
    warning: Option<String>,
}

impl std::fmt::Debug for ResponseMleKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResponseMleKey")
            .field("kid", &self.kid)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl ResponseMleKey {
    /// From the response-MLE P12 generated in the Business Center. The key id
    /// is the `serialNumber` of the certificate whose CN is `merchant_cn`
    /// (the merchant ID, or portfolio ID with a meta key).
    #[cfg(feature = "p12")]
    pub fn from_p12(p12: &[u8], password: &str, merchant_cn: &str) -> Result<Self> {
        let store = crate::keys::p12::P12::parse(p12, password)?;
        let (key, cert) = store.identity(merchant_cn)?;
        Ok(ResponseMleKey {
            kid: cert.subject_serial_number().ok(),
            key,
            cert: Some(cert),
            warning: None,
        })
    }

    /// From an unencrypted PEM private key and its key id (shown in the
    /// Business Center when the key was created).
    pub fn from_pem(private_key_pem: &str, kid: impl Into<String>) -> Result<Self> {
        Ok(Self::with_key(
            pem::rsa_private_key_from_pem(private_key_pem)?,
            kid,
        ))
    }

    /// From a password-protected PKCS#8 PEM private key and its key id.
    pub fn from_encrypted_pem(
        private_key_pem: &str,
        password: &str,
        kid: impl Into<String>,
    ) -> Result<Self> {
        Ok(Self::with_key(
            pem::rsa_private_key_from_encrypted_pem(private_key_pem, password)?,
            kid,
        ))
    }

    fn with_key(key: PrivateKey, kid: impl Into<String>) -> Self {
        ResponseMleKey {
            kid: Some(kid.into()),
            key,
            cert: None,
            warning: None,
        }
    }

    /// Sets the key id explicitly, overriding one read from a P12.
    pub fn kid(mut self, kid: impl Into<String>) -> Self {
        let kid = kid.into();
        if let Some(found) = self.kid.as_deref().filter(|found| *found != kid) {
            self.warning = Some(format!(
                "response MLE kid {kid:?} overrides {found:?} read from the P12 certificate"
            ));
        }
        self.kid = Some(kid);
        self
    }

    /// The key id sent as `v-c-response-mle-kid`.
    pub fn key_id(&self) -> Option<&str> {
        self.kid.as_deref()
    }
}

/// Per-operation override of the MLE policy. `None` keeps the default.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MleOverride {
    /// Encrypt the request?
    pub request: Option<bool>,
    /// Ask for an encrypted response?
    pub response: Option<bool>,
}

/// Message-level encryption settings.
///
/// By default, mandatory-MLE operations are encrypted (with the request
/// certificate from a P12 [`Credentials::jwt_p12`](crate::Credentials::jwt_p12),
/// or one set here), and nothing else is.
#[derive(Debug, Clone, Default)]
pub struct MleConfig {
    pub(crate) request_cert: Option<RequestMleCert>,
    pub(crate) optional_globally: bool,
    pub(crate) disable_mandatory: bool,
    pub(crate) response_key: Option<ResponseMleKey>,
    pub(crate) response_globally: bool,
    pub(crate) overrides: BTreeMap<String, MleOverride>,
}

impl MleConfig {
    /// Default settings: only mandatory operations are encrypted.
    pub fn new() -> Self {
        Self::default()
    }

    /// The certificate used to encrypt requests.
    pub fn request_cert(mut self, cert: RequestMleCert) -> Self {
        self.request_cert = Some(cert);
        self
    }

    /// Also encrypt requests for operations where MLE is optional.
    pub fn optional_globally(mut self, on: bool) -> Self {
        self.optional_globally = on;
        self
    }

    /// Stop encrypting mandatory-MLE operations (Cybersource will reject them
    /// unless your account is configured otherwise).
    pub fn disable_mandatory(mut self, disabled: bool) -> Self {
        self.disable_mandatory = disabled;
        self
    }

    /// The key for decrypting encrypted responses.
    pub fn response_key(mut self, key: ResponseMleKey) -> Self {
        self.response_key = Some(key);
        self
    }

    /// Ask for encrypted responses on every operation.
    pub fn response_globally(mut self, on: bool) -> Self {
        self.response_globally = on;
        self
    }

    /// Overrides the policy for one operation, by its spec operation id
    /// (e.g. `"createPayment"`; see `OperationMeta::id`).
    pub fn override_op(mut self, operation_id: impl Into<String>, rule: MleOverride) -> Self {
        self.overrides.insert(operation_id.into(), rule);
        self
    }

    /// The request certificate's key id, if one is configured.
    pub fn request_cert_kid(&self) -> Option<&str> {
        self.request_cert.as_ref().map(RequestMleCert::kid)
    }

    /// Non-fatal notes about this configuration (e.g. a key id override).
    pub fn warnings(&self) -> Vec<String> {
        self.response_key
            .iter()
            .filter_map(|k| k.warning.clone())
            .collect()
    }

    /// Whether any setting asks for request encryption beyond mandatory ops.
    pub(crate) fn requests_encryption(&self) -> bool {
        self.optional_globally || self.overrides.values().any(|o| o.request == Some(true))
    }

    /// Whether any setting asks for encrypted responses.
    pub(crate) fn requests_encrypted_responses(&self) -> bool {
        self.response_globally || self.overrides.values().any(|o| o.response == Some(true))
    }
}
