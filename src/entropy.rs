//! Randomness source, injectable so signing is deterministic in tests.

use crate::{Error, Result};

/// A source of random bytes.
pub trait Entropy: Send + Sync {
    /// Fills `buf` with random bytes.
    fn fill(&self, buf: &mut [u8]) -> Result<()>;
}

/// The operating system's random number generator, via `getrandom`.
#[derive(Debug, Clone, Copy, Default)]
pub struct OsEntropy;

impl Entropy for OsEntropy {
    fn fill(&self, buf: &mut [u8]) -> Result<()> {
        getrandom::fill(buf).map_err(|e| Error::Entropy(e.to_string()))
    }
}

/// Repeats a fixed byte pattern, for tests. Never use outside tests.
#[derive(Debug, Clone)]
pub struct FixedEntropy(pub Vec<u8>);

impl Entropy for FixedEntropy {
    fn fill(&self, buf: &mut [u8]) -> Result<()> {
        if self.0.is_empty() {
            return Err(Error::Entropy("FixedEntropy has no bytes".into()));
        }
        for (dst, src) in buf.iter_mut().zip(self.0.iter().cycle()) {
            *dst = *src;
        }
        Ok(())
    }
}

/// Formats 16 random bytes as a lowercase UUIDv4 string.
pub fn uuid_v4(entropy: &dyn Entropy) -> Result<String> {
    let mut b = [0u8; 16];
    entropy.fill(&mut b)?;
    b[6] = (b[6] & 0x0f) | 0x40; // version 4
    b[8] = (b[8] & 0x3f) | 0x80; // RFC 4122 variant
    let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_entropy_fills_buffer() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        OsEntropy.fill(&mut a).unwrap();
        OsEntropy.fill(&mut b).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn fixed_entropy_cycles_pattern() {
        let mut buf = [0u8; 5];
        FixedEntropy(vec![1, 2]).fill(&mut buf).unwrap();
        assert_eq!(buf, [1, 2, 1, 2, 1]);
    }

    #[test]
    fn fixed_entropy_rejects_empty_pattern() {
        assert!(FixedEntropy(vec![]).fill(&mut [0u8; 1]).is_err());
    }

    #[test]
    fn uuid_v4_sets_version_and_variant() {
        let id = uuid_v4(&FixedEntropy(vec![0xff])).unwrap();
        assert_eq!(id, "ffffffff-ffff-4fff-bfff-ffffffffffff");
    }
}
