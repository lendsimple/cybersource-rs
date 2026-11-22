//! Client configuration: environment, merchant and credentials.
//!
//! Everything is validated when the [`Config`] is built, so a misconfigured
//! client fails at startup rather than on its first request.

use rsa::PrivateKey;
use secrecy::{ExposeSecret, SecretBox};

use crate::jose::b64;
use crate::keys::{pem, x509::CertificateInfo};
use crate::mle::{MleConfig, RequestMleCert};
use crate::{Error, Result};

/// The Cybersource environment (API host) to talk to.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum Environment {
    /// Sandbox: `apitest.cybersource.com`. The default.
    #[default]
    Sandbox,
    /// Production: `api.cybersource.com`.
    Production,
    /// Production for India: `api.in.cybersource.com`.
    ProductionIndia,
    /// Any other host, e.g. a regional endpoint. Host name only, no scheme.
    Custom(String),
}

impl Environment {
    /// The API host name. This is also the host every request is signed for.
    pub fn host(&self) -> &str {
        match self {
            Environment::Sandbox => "apitest.cybersource.com",
            Environment::Production => "api.cybersource.com",
            Environment::ProductionIndia => "api.in.cybersource.com",
            Environment::Custom(host) => host,
        }
    }
}

/// How requests are authenticated.
///
/// JWT is the default and recommended scheme. Cybersource retires HTTP
/// Signature in March 2027 and recommends moving to JWT signed with the same
/// shared secret ([`Credentials::jwt_shared_secret`]).
#[non_exhaustive]
pub enum Credentials {
    /// JWT signed with HS256 using a REST shared secret key.
    JwtSharedSecret {
        /// The shared secret's key id; becomes the JWT `kid`.
        key_id: String,
        /// The raw (base64-decoded) shared secret.
        secret: SecretBox<[u8]>,
    },
    /// JWT signed with RS256 using the merchant's certificate key.
    JwtRsa {
        /// The JWT `kid`: the certificate subject's `serialNumber` attribute.
        kid: String,
        /// The merchant's RSA private key.
        key: Box<PrivateKey>,
        /// The signing certificate, when known (for expiry reporting).
        signing_cert: Option<Box<CertificateInfo>>,
        /// Cybersource's request-encryption certificate, when the key came
        /// from a Business Center P12 (which includes it).
        request_mle_cert: Option<Box<CertificateInfo>>,
    },
    /// Legacy HTTP Signature (HMAC-SHA256). Deprecated by Cybersource.
    #[cfg(feature = "http-signature")]
    HttpSignature {
        /// The shared secret's key id.
        key_id: String,
        /// The raw (base64-decoded) shared secret.
        secret: SecretBox<[u8]>,
    },
}

impl Credentials {
    /// JWT (HS256) with a REST shared secret, as shown in the Business Center
    /// (`secret_base64` is the base64 string Cybersource gives you).
    pub fn jwt_shared_secret(key_id: impl Into<String>, secret_base64: &str) -> Result<Self> {
        Ok(Credentials::JwtSharedSecret {
            key_id: non_empty("key id", key_id.into())?,
            secret: decode_secret(secret_base64)?,
        })
    }

    /// JWT (RS256) from a PEM private key and the matching merchant
    /// certificate. The `kid` is read from the certificate.
    pub fn jwt_rsa_pem(private_key_pem: &str, certificate_pem: &str) -> Result<Self> {
        let cert = CertificateInfo::from_pem(certificate_pem)?;
        let kid = cert.subject_serial_number()?;
        let mut credentials = Self::jwt_rsa_pem_with_kid(private_key_pem, kid)?;
        if let Credentials::JwtRsa { signing_cert, .. } = &mut credentials {
            *signing_cert = Some(Box::new(cert));
        }
        Ok(credentials)
    }

    /// JWT (RS256) from a PEM private key and an explicit `kid`.
    pub fn jwt_rsa_pem_with_kid(private_key_pem: &str, kid: impl Into<String>) -> Result<Self> {
        Ok(Credentials::JwtRsa {
            kid: non_empty("kid", kid.into())?,
            key: Box::new(pem::rsa_private_key_from_pem(private_key_pem)?),
            signing_cert: None,
            request_mle_cert: None,
        })
    }

    /// JWT (RS256) from a Business Center P12.
    ///
    /// `alias` is the CN of the signing certificate: the merchant ID, or the
    /// portfolio ID when using a meta key. The `kid` comes from that
    /// certificate, and the P12's `CyberSource_SJC_US` certificate (if any)
    /// becomes the default for request message-level encryption.
    #[cfg(feature = "p12")]
    pub fn jwt_p12(p12: &[u8], password: &str, alias: &str) -> Result<Self> {
        let store = crate::keys::p12::P12::parse(p12, password)?;
        let (key, cert) = store.identity(alias)?;
        Ok(Credentials::JwtRsa {
            kid: cert.subject_serial_number()?,
            key: Box::new(key),
            signing_cert: Some(Box::new(cert)),
            request_mle_cert: store.mle_certificate().cloned().map(Box::new),
        })
    }

    /// Legacy HTTP Signature with a REST shared secret.
    ///
    /// Prefer [`Credentials::jwt_shared_secret`]: it uses the same key and
    /// Cybersource retires HTTP Signature in March 2027.
    #[cfg(feature = "http-signature")]
    pub fn http_signature(key_id: impl Into<String>, secret_base64: &str) -> Result<Self> {
        Ok(Credentials::HttpSignature {
            key_id: non_empty("key id", key_id.into())?,
            secret: decode_secret(secret_base64)?,
        })
    }

    fn kind(&self) -> &'static str {
        match self {
            Credentials::JwtSharedSecret { .. } => "JwtSharedSecret",
            Credentials::JwtRsa { .. } => "JwtRsa",
            #[cfg(feature = "http-signature")]
            Credentials::HttpSignature { .. } => "HttpSignature",
        }
    }

    fn key_id(&self) -> &str {
        match self {
            Credentials::JwtSharedSecret { key_id, .. } => key_id,
            Credentials::JwtRsa { kid, .. } => kid,
            #[cfg(feature = "http-signature")]
            Credentials::HttpSignature { key_id, .. } => key_id,
        }
    }

    pub(crate) fn secret(&self) -> Option<&[u8]> {
        match self {
            Credentials::JwtSharedSecret { secret, .. } => Some(secret.expose_secret()),
            #[cfg(feature = "http-signature")]
            Credentials::HttpSignature { secret, .. } => Some(secret.expose_secret()),
            Credentials::JwtRsa { .. } => None,
        }
    }
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct(self.kind())
            .field("key_id", &self.key_id())
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

/// Validated client configuration.
#[derive(Debug)]
pub struct Config {
    environment: Environment,
    merchant_id: String,
    credentials: Credentials,
    portfolio_id: Option<String>,
    user_agent: String,
    mle: MleConfig,
    developer_id: Option<String>,
    validate_requests: bool,
}

/// What a certificate is used for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CertificateRole {
    /// Signs JWTs (RS256).
    Signing,
    /// Cybersource's certificate that requests are encrypted to.
    RequestMle,
    /// The merchant's response-encryption key.
    ResponseMle,
}

/// When a configured certificate expires.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateExpiry {
    /// What the certificate is used for.
    pub role: CertificateRole,
    /// Its subject DN.
    pub subject: String,
    /// Expiry, as seconds since the Unix epoch.
    pub not_after_unix: u64,
}

#[bon::bon]
impl Config {
    /// Builds a validated configuration.
    ///
    /// ```
    /// # use cybersource::config::{Config, Credentials, Environment};
    /// let config = Config::builder()
    ///     .environment(Environment::Sandbox)
    ///     .merchant_id("testrest")
    ///     .credentials(Credentials::jwt_shared_secret(
    ///         "08c94330-f618-42a3-b09d-e1e43be5efda",
    ///         "yBJxy6LjM2TmcPGu+GaJrHtkke25fPpUX+UY6/L/1tE=",
    ///     )?)
    ///     .build()?;
    /// # Ok::<(), cybersource::Error>(())
    /// ```
    #[builder]
    pub fn new(
        /// Which Cybersource host to use. Defaults to the sandbox, so
        /// production is only ever chosen explicitly.
        #[builder(default)]
        environment: Environment,
        /// The transacting merchant ID.
        #[builder(into)]
        merchant_id: String,
        /// How to authenticate.
        credentials: Credentials,
        /// Portfolio ID when authenticating with a portfolio meta key. The
        /// key then belongs to the portfolio while requests transact for
        /// `merchant_id`.
        #[builder(into)]
        portfolio_id: Option<String>,
        /// Overrides the `User-Agent` header.
        #[builder(into)]
        user_agent: Option<String>,
        /// Message-level encryption settings. Without them, mandatory-MLE
        /// operations still use the request certificate from a P12.
        mle: Option<MleConfig>,
        /// Your Cybersource partner developer id. When set, it is added as
        /// `clientReferenceInformation.partner.developerId` to request bodies
        /// that accept it and don't already have one. Off by default.
        #[builder(into)]
        developer_id: Option<String>,
        /// Whether request bodies are checked against the spec's
        /// constraints before sending. On by default; an invalid body fails
        /// with [`Error::Validation`] and is never sent. Turn it off only to
        /// work around a constraint the spec gets wrong.
        #[builder(default = true)]
        validate_requests: bool,
    ) -> Result<Self> {
        let merchant_id = non_empty("merchant id", merchant_id)?;
        let portfolio_id = portfolio_id
            .map(|p| non_empty("portfolio id", p))
            .transpose()?;
        if let Environment::Custom(host) = &environment
            && (host.is_empty() || host.contains('/') || host.contains(':'))
        {
            return Err(Error::Config(format!(
                "custom environment must be a bare host name, got {host:?}"
            )));
        }
        let mle = resolve_mle(mle.unwrap_or_default(), &credentials)?;
        let config = Config {
            environment,
            merchant_id,
            credentials,
            portfolio_id,
            user_agent: user_agent
                .unwrap_or_else(|| concat!("cybersource-rust/", env!("CARGO_PKG_VERSION")).into()),
            mle,
            developer_id: developer_id
                .map(|d| non_empty("developer id", d))
                .transpose()?,
            validate_requests,
        };
        #[cfg(feature = "tracing")]
        crate::telemetry::config_warnings(&config);
        Ok(config)
    }
}

impl Config {
    /// The configured environment.
    pub fn environment(&self) -> &Environment {
        &self.environment
    }

    /// The transacting merchant ID.
    pub fn merchant_id(&self) -> &str {
        &self.merchant_id
    }

    /// The configured credentials.
    pub fn credentials(&self) -> &Credentials {
        &self.credentials
    }

    /// The portfolio ID, when using a meta key.
    pub fn portfolio_id(&self) -> Option<&str> {
        self.portfolio_id.as_deref()
    }

    /// The `User-Agent` sent with every request.
    pub fn user_agent(&self) -> &str {
        &self.user_agent
    }

    /// The partner developer id added to request bodies, if configured.
    pub fn developer_id(&self) -> Option<&str> {
        self.developer_id.as_deref()
    }

    /// Whether request bodies are validated before sending.
    pub fn validate_requests(&self) -> bool {
        self.validate_requests
    }

    /// Message-level encryption settings.
    pub fn mle(&self) -> &MleConfig {
        &self.mle
    }

    /// Expiry of every configured certificate. Nothing is enforced: the
    /// official SDKs only warn, and the sandbox accepts expired keys. Check
    /// this at startup and alert before production keys lapse.
    pub fn certificate_expiries(&self) -> Vec<CertificateExpiry> {
        let entry = |role, cert: &CertificateInfo| CertificateExpiry {
            role,
            subject: cert.subject(),
            not_after_unix: cert.not_after_unix(),
        };
        let mut out = Vec::new();
        if let Credentials::JwtRsa {
            signing_cert: Some(cert),
            ..
        } = &self.credentials
        {
            out.push(entry(CertificateRole::Signing, cert));
        }
        if let Some(c) = &self.mle.request_cert {
            out.push(entry(CertificateRole::RequestMle, &c.cert));
        }
        if let Some(cert) = self.mle.response_key.as_ref().and_then(|k| k.cert.as_ref()) {
            out.push(entry(CertificateRole::ResponseMle, cert));
        }
        out
    }

    /// The merchant that owns the signing key: the portfolio with a meta key,
    /// otherwise the merchant itself.
    pub(crate) fn key_owner(&self) -> &str {
        self.portfolio_id.as_deref().unwrap_or(&self.merchant_id)
    }
}

/// Fills in the request certificate from P12 credentials and rejects
/// settings that cannot work.
fn resolve_mle(mut mle: MleConfig, credentials: &Credentials) -> Result<MleConfig> {
    if mle.request_cert.is_none()
        && let Credentials::JwtRsa {
            request_mle_cert: Some(cert),
            ..
        } = credentials
    {
        mle.request_cert = Some(RequestMleCert::from_certificate((**cert).clone())?);
    }
    let jwt = matches!(
        credentials,
        Credentials::JwtSharedSecret { .. } | Credentials::JwtRsa { .. }
    );
    let wants_mle = mle.requests_encryption()
        || mle.requests_encrypted_responses()
        || mle.response_key.is_some();
    if wants_mle && !jwt {
        return Err(Error::Config(
            "message-level encryption requires JWT authentication".into(),
        ));
    }
    if mle.requests_encryption() && mle.request_cert.is_none() {
        return Err(Error::Config(
            "request encryption is enabled but no request MLE certificate is configured; \
             use a Business Center P12 or MleConfig::request_cert"
                .into(),
        ));
    }
    if mle.requests_encrypted_responses() && mle.response_key.is_none() {
        return Err(Error::Config(
            "encrypted responses are enabled but no response MLE key is configured; \
             use MleConfig::response_key"
                .into(),
        ));
    }
    if let Some(key) = &mle.response_key
        && key.kid.is_none()
    {
        return Err(Error::Config(
            "the response MLE key has no key id; set it with ResponseMleKey::kid".into(),
        ));
    }
    Ok(mle)
}

fn non_empty(what: &str, value: String) -> Result<String> {
    if value.trim().is_empty() {
        Err(Error::Config(format!("{what} must not be empty")))
    } else {
        Ok(value)
    }
}

fn decode_secret(secret_base64: &str) -> Result<SecretBox<[u8]>> {
    let bytes = b64::decode(secret_base64.trim())
        .map_err(|e| Error::Config(format!("shared secret is not valid base64: {e}")))?;
    if bytes.is_empty() {
        return Err(Error::Config("shared secret must not be empty".into()));
    }
    Ok(SecretBox::new(bytes.into_boxed_slice()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "yBJxy6LjM2TmcPGu+GaJrHtkke25fPpUX+UY6/L/1tE=";

    fn creds() -> Credentials {
        Credentials::jwt_shared_secret("key-1", SECRET).unwrap()
    }

    #[test]
    fn environment_hosts() {
        assert_eq!(Environment::Sandbox.host(), "apitest.cybersource.com");
        assert_eq!(Environment::Production.host(), "api.cybersource.com");
        assert_eq!(
            Environment::ProductionIndia.host(),
            "api.in.cybersource.com"
        );
    }

    #[test]
    fn builds_valid_config() {
        let config = Config::builder()
            .environment(Environment::Sandbox)
            .merchant_id("m1")
            .credentials(creds())
            .build()
            .unwrap();
        assert_eq!(config.merchant_id(), "m1");
        assert_eq!(config.key_owner(), "m1");
        assert!(config.user_agent().starts_with("cybersource-rust/"));
    }

    #[test]
    fn environment_defaults_to_sandbox() {
        let config = Config::builder()
            .merchant_id("m1")
            .credentials(creds())
            .build()
            .unwrap();
        assert_eq!(config.environment(), &Environment::Sandbox);
    }

    #[test]
    fn meta_key_owner_is_portfolio() {
        let config = Config::builder()
            .environment(Environment::Sandbox)
            .merchant_id("m1")
            .portfolio_id("p1")
            .credentials(creds())
            .build()
            .unwrap();
        assert_eq!(config.key_owner(), "p1");
    }

    #[test]
    fn rejects_empty_merchant_id() {
        let err = Config::builder()
            .environment(Environment::Sandbox)
            .merchant_id(" ")
            .credentials(creds())
            .build()
            .unwrap_err();
        assert!(err.to_string().contains("merchant id"));
    }

    #[test]
    fn rejects_custom_host_with_scheme() {
        let err = Config::builder()
            .environment(Environment::Custom("https://example.com".into()))
            .merchant_id("m1")
            .credentials(creds())
            .build()
            .unwrap_err();
        assert!(err.to_string().contains("bare host name"));
    }

    #[test]
    fn rejects_invalid_base64_secret() {
        let err = Credentials::jwt_shared_secret("k", "not base64!").unwrap_err();
        assert!(err.to_string().contains("not valid base64"));
    }

    #[test]
    fn rsa_kid_comes_from_certificate() {
        let creds = Credentials::jwt_rsa_pem(
            include_str!("../tests/fixtures/rsa_test_key.pem"),
            include_str!("../tests/fixtures/merchant_cert.pem"),
        )
        .unwrap();
        assert_eq!(creds.key_id(), "1234567890ABCDEF");
    }

    #[cfg(feature = "p12")]
    #[test]
    fn jwt_p12_takes_kid_key_and_mle_cert_from_the_file() {
        let bytes = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/cybs_shaped.p12"
        ))
        .unwrap();
        let Credentials::JwtRsa {
            kid,
            request_mle_cert,
            ..
        } = Credentials::jwt_p12(&bytes, "testmerchant", "testmerchant").unwrap()
        else {
            panic!("expected JwtRsa");
        };
        assert_eq!(kid, "1234567890ABCDEF");
        assert_eq!(
            request_mle_cert.unwrap().subject_serial_number().unwrap(),
            "SJC0000000001"
        );
    }

    #[test]
    fn debug_never_prints_secrets() {
        let config = Config::builder()
            .environment(Environment::Sandbox)
            .merchant_id("m1")
            .credentials(creds())
            .build()
            .unwrap();
        let debug = format!("{config:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(SECRET));
        let rsa = Credentials::jwt_rsa_pem(
            include_str!("../tests/fixtures/rsa_test_key.pem"),
            include_str!("../tests/fixtures/merchant_cert.pem"),
        )
        .unwrap();
        assert!(!format!("{rsa:?}").contains("PrivateKey"));
    }
}
