//! Global packets-per-second ceiling (architecture doc §5.2).

use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use tokio::time::Instant;

/// A generic cell rate limiter: on average at most `pps` permits per second,
/// with bursts of up to one second's worth.
#[derive(Debug)]
pub struct RateLimiter {
    interval: Duration,
    burst: Duration,
    /// Theoretical arrival time of the next permit.
    tat: Mutex<Option<Instant>>,
}

impl RateLimiter {
    /// `pps` must be at least 1.
    pub fn new(pps: u32) -> Self {
        let pps = pps.max(1);
        Self {
            interval: Duration::from_secs(1) / pps,
            burst: Duration::from_secs(1),
            tat: Mutex::new(None),
        }
    }

    /// Wait until one more packet may be sent.
    pub async fn acquire(&self) {
        let wait = {
            let now = Instant::now();
            let mut tat = self.tat.lock().unwrap_or_else(PoisonError::into_inner);
            let t = tat.map_or(now, |t| t.max(now));
            *tat = Some(t + self.interval);
            // Permits up to `burst` ahead of the even pace go out at once.
            (t.saturating_duration_since(now)).checked_sub(self.burst)
        };
        if let Some(wait) = wait.filter(|w| !w.is_zero()) {
            tokio::time::sleep(wait).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn bursts_one_second_then_paces() {
        let rl = RateLimiter::new(10);
        let start = Instant::now();
        // 1 s of burst (10 permits) plus the one at t=0 go out immediately.
        for _ in 0..11 {
            rl.acquire().await;
        }
        assert_eq!(start.elapsed(), Duration::ZERO);
        // The next 10 take one more second.
        for _ in 0..10 {
            rl.acquire().await;
        }
        let e = start.elapsed();
        assert!(
            e >= Duration::from_millis(990) && e <= Duration::from_millis(1010),
            "{e:?}"
        );
    }
}
