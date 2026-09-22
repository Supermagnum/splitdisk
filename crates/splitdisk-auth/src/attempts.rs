//! Software PIN attempt counter with injectable cool-down (SPEC §5.2).

use crate::pin::{MAX_PIN_ATTEMPTS, MIN_PIN_ATTEMPTS};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Clock abstraction so tests never sleep a real 30 seconds.
pub trait Clock {
    fn now(&self) -> Instant;
    fn sleep(&self, duration: Duration);
}

/// Production clock using `std::thread::sleep`.
#[derive(Debug, Default, Clone, Copy)]
pub struct InstantClock;

impl Clock for InstantClock {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn sleep(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

/// Mock clock for tests: advances a virtual timeline; `sleep` only advances `now`.
#[derive(Debug, Clone)]
pub struct MockClock {
    start: Instant,
    offset: Arc<Mutex<Duration>>,
}

impl MockClock {
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
            offset: Arc::new(Mutex::new(Duration::ZERO)),
        }
    }

    pub fn advance(&self, d: Duration) {
        let mut o = self.offset.lock().expect("mock clock lock");
        *o = o.checked_add(d).unwrap_or(Duration::MAX);
    }
}

impl Default for MockClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for MockClock {
    fn now(&self) -> Instant {
        let o = self.offset.lock().expect("mock clock lock");
        self.start + *o
    }

    fn sleep(&self, duration: Duration) {
        self.advance(duration);
    }
}

/// Attempt / cool-down policy (configurable at creation time).
#[derive(Debug, Clone, Copy)]
pub struct AttemptPolicy {
    /// Failed attempts allowed per insertion before ejection (3–10).
    pub max_attempts: u32,
    /// Cool-down after each failed attempt (SPEC default 30s).
    pub cooldown: Duration,
}

impl Default for AttemptPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            cooldown: Duration::from_secs(30),
        }
    }
}

impl AttemptPolicy {
    pub fn new(max_attempts: u32, cooldown: Duration) -> Result<Self, &'static str> {
        if !(MIN_PIN_ATTEMPTS..=MAX_PIN_ATTEMPTS).contains(&max_attempts) {
            return Err("max_attempts must be in 3..=10");
        }
        Ok(Self {
            max_attempts,
            cooldown,
        })
    }
}

/// Per-insertion attempt limiter.
pub struct AttemptLimiter<C: Clock> {
    policy: AttemptPolicy,
    clock: C,
    failures: u32,
    cooldown_until: Option<Instant>,
}

impl<C: Clock> AttemptLimiter<C> {
    pub fn new(policy: AttemptPolicy, clock: C) -> Self {
        Self {
            policy,
            clock,
            failures: 0,
            cooldown_until: None,
        }
    }

    /// Reset state as if the drive were re-inserted.
    pub fn on_reinsert(&mut self) {
        self.failures = 0;
        self.cooldown_until = None;
    }

    /// Block until cool-down elapses (uses injectable clock sleep).
    pub fn wait_cooldown_if_needed(&mut self) {
        if let Some(until) = self.cooldown_until {
            let now = self.clock.now();
            if now < until {
                self.clock.sleep(until.saturating_duration_since(now));
            }
            self.cooldown_until = None;
        }
    }

    /// Returns `Err` if the attempt limit for this insertion is exhausted.
    pub fn before_attempt(&mut self) -> Result<(), splitdisk_core::Error> {
        self.wait_cooldown_if_needed();
        if self.failures >= self.policy.max_attempts {
            return Err(splitdisk_core::Error::AttemptLimitReached);
        }
        Ok(())
    }

    /// Record a failed authentication (starts cool-down).
    pub fn record_failure(&mut self) {
        self.failures = self.failures.saturating_add(1);
        let until = self.clock.now() + self.policy.cooldown;
        self.cooldown_until = Some(until);
        self.clock.sleep(self.policy.cooldown);
        self.cooldown_until = None;
    }

    pub fn failures(&self) -> u32 {
        self.failures
    }

    pub fn remaining(&self) -> u32 {
        self.policy.max_attempts.saturating_sub(self.failures)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limit_and_cooldown_with_mock_clock() {
        let clock = MockClock::new();
        let policy = AttemptPolicy::new(3, Duration::from_millis(50)).unwrap();
        let mut lim = AttemptLimiter::new(policy, clock.clone());

        lim.before_attempt().unwrap();
        lim.record_failure();
        assert_eq!(lim.failures(), 1);

        lim.before_attempt().unwrap();
        lim.record_failure();
        lim.before_attempt().unwrap();
        lim.record_failure();

        assert!(matches!(
            lim.before_attempt(),
            Err(splitdisk_core::Error::AttemptLimitReached)
        ));

        lim.on_reinsert();
        lim.before_attempt().unwrap();
    }
}
