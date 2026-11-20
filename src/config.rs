//! Client configuration: environment, merchant and credentials.
//!
//! Everything is validated when the [`Config`] is built, so a misconfigured
//! client fails at startup rather than on its first request.

use rsa::PrivateKey;
use secrecy::{ExposeSecret, SecretBox};

use crate::jose::b64;
use crate::keys::{pem, x509::CertificateInfo};
use crate::{Error, Result};

/// The Cybersource environment (API host) to talk to.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Environment {
    /// Sandbox: `apitest.cybersource.com`.
    Test,
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
            Environment::Test => "apitest.cybersource.com",
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
        let kid = CertificateInfo::from_pem(certificate_pem)?.subject_serial_number()?;
        Self::jwt_rsa_pem_with_kid(private_key_pem, kid)
    }

    /// JWT (RS256) from a PEM private key and an explicit `kid`.
    pub fn jwt_rsa_pem_with_kid(private_key_pem: &str, kid: impl Into<String>) -> Result<Self> {
        Ok(Credentials::JwtRsa {
            kid: non_empty("kid", kid.into())?,
            key: Box::new(pem::rsa_private_key_from_pem(private_key_pem)?),
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
}

#[bon::bon]
impl Config {
    /// Builds a validated configuration.
    ///
    /// ```
    /// # use cybersource::config::{Config, Credentials, Environment};
    /// let config = Config::builder()
    ///     .environment(Environment::Test)
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
        /// Which Cybersource host to use. There is no default, so production
        /// is never chosen by accident.
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
        Ok(Config {
            environment,
            merchant_id,
            credentials,
            portfolio_id,
            user_agent: user_agent
                .unwrap_or_else(|| concat!("cybersource-rust/", env!("CARGO_PKG_VERSION")).into()),
        })
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

    /// The merchant that owns the signing key: the portfolio with a meta key,
    /// otherwise the merchant itself.
    pub(crate) fn key_owner(&self) -> &str {
        self.portfolio_id.as_deref().unwrap_or(&self.merchant_id)
    }
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
        assert_eq!(Environment::Test.host(), "apitest.cybersource.com");
        assert_eq!(Environment::Production.host(), "api.cybersource.com");
        assert_eq!(
            Environment::ProductionIndia.host(),
            "api.in.cybersource.com"
        );
    }

    #[test]
    fn builds_valid_config() {
        let config = Config::builder()
            .environment(Environment::Test)
            .merchant_id("m1")
            .credentials(creds())
            .build()
            .unwrap();
        assert_eq!(config.merchant_id(), "m1");
        assert_eq!(config.key_owner(), "m1");
        assert!(config.user_agent().starts_with("cybersource-rust/"));
    }

    #[test]
    fn meta_key_owner_is_portfolio() {
        let config = Config::builder()
            .environment(Environment::Test)
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
            .environment(Environment::Test)
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

    #[test]
    fn debug_never_prints_secrets() {
        let config = Config::builder()
            .environment(Environment::Test)
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
