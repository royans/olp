use rand::Rng;
use std::time::Duration;

/// Fibonacci backoff state machine starting at `initial_delay_sec` (default 1s)
/// and capped at `max_delay_sec` (default 300s / 5 minutes).
#[derive(Debug, Clone)]
pub struct FibonacciBackoff {
    prev: u64,
    curr: u64,
    initial_sec: u64,
    max_sec: u64,
    attempt: u32,
}

impl FibonacciBackoff {
    pub fn new(initial_sec: u64, max_sec: u64) -> Self {
        let init = initial_sec.max(1);
        let max = max_sec.max(init);
        Self {
            prev: 0,
            curr: init,
            initial_sec: init,
            max_sec: max,
            attempt: 0,
        }
    }

    /// Resets the backoff sequence back to the initial 1s state after a healthy connection.
    pub fn reset(&mut self) {
        self.prev = 0;
        self.curr = self.initial_sec;
        self.attempt = 0;
    }

    /// Returns the exact base delay in seconds (without jitter) for the next attempt
    /// and advances the Fibonacci sequence: 1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233, 300.
    pub fn next_base_delay_sec(&mut self) -> u64 {
        self.attempt = self.attempt.saturating_add(1);
        let delay = self.curr.min(self.max_sec);
        let next = self.prev.saturating_add(self.curr).min(self.max_sec);
        self.prev = self.curr.min(self.max_sec);
        self.curr = next.max(self.initial_sec);
        delay
    }

    /// Returns the next backoff Duration with uniform +/- 10% random jitter.
    pub fn next_backoff(&mut self) -> Duration {
        let base_sec = self.next_base_delay_sec();
        let base_ms = (base_sec as f64) * 1000.0;
        let mut rng = rand::thread_rng();
        let jitter_factor: f64 = rng.gen_range(0.90..=1.10);
        let max_ms = (self.max_sec as f64) * 1000.0;
        let final_ms = (base_ms * jitter_factor).min(max_ms).max(100.0) as u64;
        Duration::from_millis(final_ms)
    }

    pub fn attempt(&self) -> u32 {
        self.attempt
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fibonacci_sequence_and_cap() {
        let mut fb = FibonacciBackoff::new(1, 300);
        let expected = [
            1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233, 300, 300, 300,
        ];
        for &exp in &expected {
            assert_eq!(fb.next_base_delay_sec(), exp);
        }
        fb.reset();
        assert_eq!(fb.next_base_delay_sec(), 1);
        assert_eq!(fb.next_base_delay_sec(), 1);
        assert_eq!(fb.next_base_delay_sec(), 2);
    }

    #[test]
    fn test_fibonacci_jitter_range() {
        let mut fb = FibonacciBackoff::new(10, 300);
        for _ in 0..20 {
            let dur = fb.next_backoff();
            let millis = dur.as_millis();
            // 10s base with +/- 10% jitter -> 9000ms ..= 11000ms
            assert!(millis >= 8900 && millis <= 11100, "millis was {}", millis);
            fb.reset();
        }
    }
}

