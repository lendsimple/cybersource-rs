//! Compact JWE (RFC 7516) with RSA-OAEP key wrapping and AES-GCM.
//!
//! Message-level encryption uses `RSA-OAEP-256` + `A256GCM`; Flex
//! client-side tokenization uses `RSA-OAEP` (SHA-1) + `A256GCM`. Decryption
//! also accepts A128GCM and A192GCM, as the official SDKs do.
//!
//! Every cryptographic failure while decrypting is reported as the same
//! opaque [`JweError::Decrypt`], so callers cannot be used as a padding
//! oracle.

use aes_gcm::aead::array::Array;
use aes_gcm::aead::consts::U12;
use aes_gcm::aead::{AeadInOut, KeyInit, Nonce, Tag};
use aes_gcm::aes::Aes192;
use aes_gcm::{Aes128Gcm, Aes256Gcm, AesGcm};
use rsa::rand_core::{TryCryptoRng, TryRng};
use rsa::{Oaep, PrivateKey, PublicKey};
use serde_json::{Map, Value};
use sha1::Sha1;
use sha2::Sha256;
use zeroize::Zeroizing;

use super::b64;
use crate::entropy::Entropy;

type Aes192Gcm = AesGcm<Aes192, U12>;

const IV_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// Key management algorithm (`alg`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyAlg {
    /// RSAES-OAEP with SHA-1 and MGF1-SHA-1 (`RSA-OAEP`).
    RsaOaep,
    /// RSAES-OAEP with SHA-256 and MGF1-SHA-256 (`RSA-OAEP-256`).
    RsaOaep256,
}

impl KeyAlg {
    /// The JOSE name.
    pub fn name(self) -> &'static str {
        match self {
            KeyAlg::RsaOaep => "RSA-OAEP",
            KeyAlg::RsaOaep256 => "RSA-OAEP-256",
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        match name {
            "RSA-OAEP" => Some(KeyAlg::RsaOaep),
            "RSA-OAEP-256" => Some(KeyAlg::RsaOaep256),
            _ => None,
        }
    }
}

/// Content encryption algorithm (`enc`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Enc {
    /// AES-128-GCM.
    A128Gcm,
    /// AES-192-GCM.
    A192Gcm,
    /// AES-256-GCM.
    A256Gcm,
}

impl Enc {
    /// The JOSE name.
    pub fn name(self) -> &'static str {
        match self {
            Enc::A128Gcm => "A128GCM",
            Enc::A192Gcm => "A192GCM",
            Enc::A256Gcm => "A256GCM",
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        match name {
            "A128GCM" => Some(Enc::A128Gcm),
            "A192GCM" => Some(Enc::A192Gcm),
            "A256GCM" => Some(Enc::A256Gcm),
            _ => None,
        }
    }

    fn key_len(self) -> usize {
        match self {
            Enc::A128Gcm => 16,
            Enc::A192Gcm => 24,
            Enc::A256Gcm => 32,
        }
    }
}

/// JWE failure.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum JweError {
    /// Not a well-formed compact JWE (wrong shape, bad base64 or header).
    #[error("malformed JWE: {0}")]
    Malformed(&'static str),
    /// The token uses an algorithm this caller does not accept.
    #[error("unsupported JWE algorithm: {0}")]
    Unsupported(String),
    /// Decryption failed (wrong key or tampered token). Deliberately opaque.
    #[error("JWE decryption failed")]
    Decrypt,
    /// Encryption failed (key or random number generator problem).
    #[error("JWE encryption failed: {0}")]
    Encrypt(String),
}

/// A decrypted JWE.
#[derive(Debug)]
pub struct Decrypted {
    /// The protected header.
    pub header: Map<String, Value>,
    /// The plaintext.
    pub plaintext: Vec<u8>,
}

/// Bridges [`Entropy`] to the RNG traits `rsa` expects.
struct EntropyRng<'a>(&'a dyn Entropy);

impl TryRng for EntropyRng<'_> {
    type Error = crate::Error;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut b = [0u8; 4];
        self.0.fill(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut b = [0u8; 8];
        self.0.fill(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        self.0.fill(dst)
    }
}

impl TryCryptoRng for EntropyRng<'_> {}

/// Encrypts `plaintext` to `key`. `extra` header parameters (e.g. `kid`,
/// `iat`, `cty`) are added to the protected header after `alg` and `enc`.
pub fn encrypt(
    key: &PublicKey,
    alg: KeyAlg,
    enc: Enc,
    extra: &Map<String, Value>,
    plaintext: &[u8],
    entropy: &dyn Entropy,
) -> Result<String, JweError> {
    let mut header = extra.clone();
    header.insert("alg".into(), alg.name().into());
    header.insert("enc".into(), enc.name().into());
    let header_b64 =
        b64::url_encode(serde_json::to_vec(&header).map_err(|e| JweError::Encrypt(e.to_string()))?);

    let mut cek = Zeroizing::new(vec![0u8; enc.key_len()]);
    let mut iv = [0u8; IV_LEN];
    entropy
        .fill(&mut cek)
        .and_then(|()| entropy.fill(&mut iv))
        .map_err(|e| JweError::Encrypt(e.to_string()))?;

    let mut rng = EntropyRng(entropy);
    let wrapped = match alg {
        KeyAlg::RsaOaep => key.encrypt(&mut rng, Oaep::<Sha1>::new(), &cek),
        KeyAlg::RsaOaep256 => key.encrypt(&mut rng, Oaep::<Sha256>::new(), &cek),
    }
    .map_err(|e| JweError::Encrypt(e.to_string()))?;

    let mut buf = plaintext.to_vec();
    let tag = gcm(enc, &cek, &iv, header_b64.as_bytes(), &mut buf, None)
        .map_err(|()| JweError::Encrypt("AES-GCM failed".into()))?;

    Ok([
        header_b64,
        b64::url_encode(wrapped),
        b64::url_encode(iv),
        b64::url_encode(buf),
        b64::url_encode(tag),
    ]
    .join("."))
}

/// Decrypts a compact JWE whose `alg` is one of `allowed`.
pub fn decrypt(key: &PrivateKey, token: &str, allowed: &[KeyAlg]) -> Result<Decrypted, JweError> {
    let parts: Vec<&str> = token.trim().split('.').collect();
    let [header_b64, wrapped, iv, ciphertext, tag] = parts[..] else {
        return Err(JweError::Malformed("expected 5 dot-separated parts"));
    };
    let decode = |s: &str| b64::url_decode(s).map_err(|_| JweError::Malformed("invalid base64url"));
    let header: Map<String, Value> = serde_json::from_slice(&decode(header_b64)?)
        .map_err(|_| JweError::Malformed("header is not a JSON object"))?;
    let alg_name = header
        .get("alg")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let enc_name = header
        .get("enc")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let alg = KeyAlg::from_name(alg_name)
        .filter(|a| allowed.contains(a))
        .ok_or_else(|| JweError::Unsupported(format!("alg {alg_name:?}")))?;
    let enc = Enc::from_name(enc_name)
        .ok_or_else(|| JweError::Unsupported(format!("enc {enc_name:?}")))?;
    let (wrapped, iv, mut buf, tag) = (
        decode(wrapped)?,
        decode(iv)?,
        decode(ciphertext)?,
        decode(tag)?,
    );
    if iv.len() != IV_LEN || tag.len() != TAG_LEN {
        return Err(JweError::Malformed("bad IV or tag length"));
    }

    // From here on, every failure is the same opaque error.
    let cek = Zeroizing::new(
        match alg {
            KeyAlg::RsaOaep => key.decrypt(Oaep::<Sha1>::new(), &wrapped),
            KeyAlg::RsaOaep256 => key.decrypt(Oaep::<Sha256>::new(), &wrapped),
        }
        .map_err(|_| JweError::Decrypt)?,
    );
    if cek.len() != enc.key_len() {
        return Err(JweError::Decrypt);
    }
    gcm(enc, &cek, &iv, header_b64.as_bytes(), &mut buf, Some(&tag))
        .map_err(|()| JweError::Decrypt)?;
    Ok(Decrypted {
        header,
        plaintext: buf,
    })
}

/// AES-GCM in place: encrypts and returns the tag when `tag` is `None`,
/// otherwise decrypts and checks `tag`.
fn gcm(
    enc: Enc,
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    buf: &mut [u8],
    tag: Option<&[u8]>,
) -> Result<Vec<u8>, ()> {
    fn run<C: KeyInit + AeadInOut>(
        key: &[u8],
        iv: &[u8],
        aad: &[u8],
        buf: &mut [u8],
        tag: Option<&[u8]>,
    ) -> Result<Vec<u8>, ()> {
        let cipher = C::new_from_slice(key).map_err(|_| ())?;
        let nonce = Nonce::<C>::try_from(iv).map_err(|_| ())?;
        match tag {
            None => cipher
                .encrypt_inout_detached(&nonce, aad, buf.into())
                .map(|t| t.to_vec())
                .map_err(|_| ()),
            Some(tag) => {
                let tag: Tag<C> = Array::try_from(tag).map_err(|_| ())?;
                cipher
                    .decrypt_inout_detached(&nonce, aad, buf.into(), &tag)
                    .map(|()| Vec::new())
                    .map_err(|_| ())
            }
        }
    }
    match enc {
        Enc::A128Gcm => run::<Aes128Gcm>(key, iv, aad, buf, tag),
        Enc::A192Gcm => run::<Aes192Gcm>(key, iv, aad, buf, tag),
        Enc::A256Gcm => run::<Aes256Gcm>(key, iv, aad, buf, tag),
    }
}

#[cfg(all(test, feature = "server"))]
mod tests {
    use super::*;
    use crate::entropy::OsEntropy;
    use crate::keys::pem::rsa_private_key_from_pem;

    fn keys() -> (PrivateKey, PublicKey) {
        let private =
            rsa_private_key_from_pem(include_str!("../../tests/fixtures/sjc_test_key.pem"))
                .unwrap();
        let public = private.to_public_key();
        (private, public)
    }

    fn extra() -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("kid".into(), "SJC0000000001".into());
        m.insert("iat".into(), 1_793_865_600.into());
        m.insert("cty".into(), "application/json".into());
        m
    }

    #[test]
    fn round_trips_every_algorithm_pair() {
        let (private, public) = keys();
        for alg in [KeyAlg::RsaOaep, KeyAlg::RsaOaep256] {
            for enc in [Enc::A128Gcm, Enc::A192Gcm, Enc::A256Gcm] {
                let token = encrypt(&public, alg, enc, &extra(), b"{\"a\":1}", &OsEntropy).unwrap();
                let out = decrypt(&private, &token, &[alg]).unwrap();
                assert_eq!(out.plaintext, b"{\"a\":1}", "{alg:?} {enc:?}");
                assert_eq!(out.header["alg"], alg.name());
                assert_eq!(out.header["enc"], enc.name());
                assert_eq!(out.header["kid"], "SJC0000000001");
            }
        }
    }

    #[test]
    fn tampering_with_any_encrypted_part_gives_the_same_opaque_error() {
        let (private, public) = keys();
        let token = encrypt(
            &public,
            KeyAlg::RsaOaep256,
            Enc::A256Gcm,
            &extra(),
            b"secret",
            &OsEntropy,
        )
        .unwrap();
        let parts: Vec<&str> = token.split('.').collect();
        for i in [0, 1, 3, 4] {
            let mut tampered: Vec<String> = parts.iter().map(|p| p.to_string()).collect();
            let mut bytes = b64::url_decode(&tampered[i]).unwrap();
            let last = bytes.len() - 1;
            bytes[last] ^= 1;
            tampered[i] = b64::url_encode(bytes);
            let err = decrypt(&private, &tampered.join("."), &[KeyAlg::RsaOaep256]).unwrap_err();
            assert!(
                matches!(err, JweError::Decrypt | JweError::Malformed(_)),
                "part {i}: {err:?}"
            );
            if i != 0 {
                assert_eq!(err, JweError::Decrypt, "part {i}");
            }
        }
    }

    #[test]
    fn wrong_key_is_the_same_opaque_error() {
        let (_, public) = keys();
        let other =
            rsa_private_key_from_pem(include_str!("../../tests/fixtures/response_mle_key.pem"))
                .unwrap();
        let token = encrypt(
            &public,
            KeyAlg::RsaOaep256,
            Enc::A256Gcm,
            &extra(),
            b"x",
            &OsEntropy,
        )
        .unwrap();
        assert_eq!(
            decrypt(&other, &token, &[KeyAlg::RsaOaep256]).unwrap_err(),
            JweError::Decrypt
        );
    }

    #[test]
    fn algorithms_outside_the_allowlist_are_rejected() {
        let (private, public) = keys();
        let token = encrypt(
            &public,
            KeyAlg::RsaOaep,
            Enc::A256Gcm,
            &extra(),
            b"x",
            &OsEntropy,
        )
        .unwrap();
        assert!(matches!(
            decrypt(&private, &token, &[KeyAlg::RsaOaep256]),
            Err(JweError::Unsupported(_))
        ));
    }

    #[test]
    fn malformed_tokens_are_reported_as_such() {
        let (private, _) = keys();
        assert!(matches!(
            decrypt(&private, "a.b.c", &[KeyAlg::RsaOaep256]),
            Err(JweError::Malformed(_))
        ));
    }

    #[test]
    fn injected_entropy_drives_cek_and_iv() {
        let (private, public) = keys();
        let fixed = crate::entropy::FixedEntropy(vec![7]);
        let a = encrypt(
            &public,
            KeyAlg::RsaOaep256,
            Enc::A256Gcm,
            &extra(),
            b"x",
            &fixed,
        )
        .unwrap();
        let b = encrypt(
            &public,
            KeyAlg::RsaOaep256,
            Enc::A256Gcm,
            &extra(),
            b"x",
            &fixed,
        )
        .unwrap();
        assert_eq!(a, b, "same entropy, same token");
        assert_eq!(
            decrypt(&private, &a, &[KeyAlg::RsaOaep256])
                .unwrap()
                .plaintext,
            b"x"
        );
    }
}
