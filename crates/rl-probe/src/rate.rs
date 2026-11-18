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
    ///
    /// Capacity is taken only when the caller may go ahead, checked again
    /// after every wait: a task that wakes late (a stalled worker) cannot
    /// use a permit computed for an earlier time.
    pub async fn acquire(&self) {
        loop {
            let wait = {
                let now = Instant::now();
                let mut tat = self.tat.lock().unwrap_or_else(PoisonError::into_inner);
                let next = tat.map_or(now, |t| t.max(now)) + self.interval;
                // This permit included, at most `burst` ahead of the even pace.
                match next.checked_duration_since(now + self.burst) {
                    None | Some(Duration::ZERO) => {
                        *tat = Some(next);
                        return;
                    }
                    Some(wait) => wait,
                }
            };
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
        // Exactly one second's worth (10 permits) goes out at once.
        for _ in 0..10 {
            rl.acquire().await;
        }
        assert_eq!(start.elapsed(), Duration::ZERO);
        rl.acquire().await;
        assert_eq!(start.elapsed(), Duration::from_millis(100));
        // The next 9 take until t = 1 s.
        for _ in 0..9 {
            rl.acquire().await;
        }
        assert_eq!(start.elapsed(), Duration::from_secs(1));
    }

    #[tokio::test(start_paused = true)]
    async fn one_pps_allows_one_immediate_permit() {
        let rl = RateLimiter::new(1);
        let start = Instant::now();
        rl.acquire().await;
        assert_eq!(start.elapsed(), Duration::ZERO);
        rl.acquire().await;
        assert_eq!(start.elapsed(), Duration::from_secs(1));
    }

    #[tokio::test(start_paused = true)]
    async fn waiters_woken_together_still_respect_the_rate() {
        let rl = std::sync::Arc::new(RateLimiter::new(10));
        for _ in 0..10 {
            rl.acquire().await;
        }
        // 20 waiters; then the runtime "stalls" past all their deadlines.
        let start = Instant::now();
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..20 {
            let rl = rl.clone();
            tasks.spawn(async move {
                rl.acquire().await;
                Instant::now()
            });
        }
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(5)).await;
        let mut times = Vec::new();
        while let Some(t) = tasks.join_next().await {
            times.push(t.unwrap().duration_since(start));
        }
        times.sort();
        // At most one second's worth may go at the moment of the stall.
        let at_once = times.iter().filter(|&&t| t == times[0]).count();
        assert!(at_once <= 10, "{at_once} permits at {:?}", times[0]);
    }
}
