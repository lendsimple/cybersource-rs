//! Time source, injectable so signing is deterministic in tests.
//!
//! [`SystemClock`] uses `web-time`, because `std::time::SystemTime::now()`
//! panics on `wasm32-unknown-unknown`.

use std::time::Duration;

/// A source of the current time.
pub trait Clock: Send + Sync {
    /// Time elapsed since the Unix epoch.
    fn now(&self) -> Duration;
}

/// The real system clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Duration {
        web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .expect("system clock is before the Unix epoch")
    }
}

/// A clock frozen at a fixed instant, for tests.
#[derive(Debug, Clone, Copy)]
pub struct FixedClock(pub Duration);

impl FixedClock {
    /// A clock frozen at `secs` seconds after the Unix epoch.
    pub fn from_secs(secs: u64) -> Self {
        FixedClock(Duration::from_secs(secs))
    }
}

impl Clock for FixedClock {
    fn now(&self) -> Duration {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_clock_is_after_2025() {
        assert!(SystemClock.now().as_secs() > 1_735_689_600);
    }

    #[test]
    fn fixed_clock_returns_its_instant() {
        assert_eq!(FixedClock::from_secs(42).now(), Duration::from_secs(42));
    }
}
