//! Bounded history buffers and rolling statistics.
//!
//! [`RingBuffer`] is a fixed-capacity FIFO (oldest evicted on overflow). [`Series`] wraps
//! one for numeric metrics and exposes rolling min/avg/max/p95/jitter for the charts and
//! stat sidebars. [`LossWindow`] tracks answered/unanswered probes to derive packet-loss %.

use std::collections::VecDeque;

/// Fixed-capacity FIFO ring buffer; pushing at capacity evicts the oldest element.
#[derive(Debug, Clone)]
pub struct RingBuffer<T> {
    buf: VecDeque<T>,
    cap: usize,
}

impl<T> RingBuffer<T> {
    /// Create a buffer holding at most `cap` items (clamped to a minimum of 1).
    pub fn new(cap: usize) -> Self {
        let cap = cap.max(1);
        Self {
            buf: VecDeque::with_capacity(cap),
            cap,
        }
    }

    /// Append `v`, evicting the oldest element if already at capacity.
    pub fn push(&mut self, v: T) {
        if self.buf.len() == self.cap {
            self.buf.pop_front();
        }
        self.buf.push_back(v);
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.cap
    }

    /// The most recently pushed element, if any.
    pub fn latest(&self) -> Option<&T> {
        self.buf.back()
    }

    /// Iterate oldest → newest.
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.buf.iter()
    }
}

/// A rolling window of `f64` samples with summary statistics.
#[derive(Debug, Clone)]
pub struct Series {
    ring: RingBuffer<f64>,
}

impl Series {
    pub fn new(cap: usize) -> Self {
        Self {
            ring: RingBuffer::new(cap),
        }
    }

    pub fn push(&mut self, v: f64) {
        self.ring.push(v);
    }

    pub fn len(&self) -> usize {
        self.ring.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ring.is_empty()
    }

    pub fn latest(&self) -> Option<f64> {
        self.ring.latest().copied()
    }

    /// Values oldest → newest (for feeding charts/sparklines).
    pub fn values(&self) -> Vec<f64> {
        self.ring.iter().copied().collect()
    }

    pub fn min(&self) -> Option<f64> {
        self.ring.iter().copied().reduce(f64::min)
    }

    pub fn max(&self) -> Option<f64> {
        self.ring.iter().copied().reduce(f64::max)
    }

    pub fn mean(&self) -> Option<f64> {
        let n = self.ring.len();
        if n == 0 {
            return None;
        }
        Some(self.ring.iter().sum::<f64>() / n as f64)
    }

    /// Nearest-rank percentile, `p` in `0..=100`. `None` if empty.
    pub fn percentile(&self, p: f64) -> Option<f64> {
        let n = self.ring.len();
        if n == 0 {
            return None;
        }
        let mut sorted: Vec<f64> = self.ring.iter().copied().collect();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        // Nearest-rank: rank = ceil(p/100 * n), 1-indexed; clamp into range.
        let rank = ((p / 100.0) * n as f64).ceil() as usize;
        let idx = rank.clamp(1, n) - 1;
        Some(sorted[idx])
    }

    /// Convenience for the 95th percentile.
    pub fn p95(&self) -> Option<f64> {
        self.percentile(95.0)
    }

    /// Mean absolute difference of consecutive samples. `None` with fewer than 2 samples.
    pub fn jitter(&self) -> Option<f64> {
        if self.ring.len() < 2 {
            return None;
        }
        let vals: Vec<f64> = self.ring.iter().copied().collect();
        let sum: f64 = vals.windows(2).map(|w| (w[1] - w[0]).abs()).sum();
        Some(sum / (vals.len() - 1) as f64)
    }
}

/// Rolling window of probe outcomes used to compute packet-loss percentage.
#[derive(Debug, Clone)]
pub struct LossWindow {
    ring: RingBuffer<bool>,
}

impl LossWindow {
    pub fn new(cap: usize) -> Self {
        Self {
            ring: RingBuffer::new(cap),
        }
    }

    /// Record one probe: `true` if a reply was received, `false` if it timed out.
    pub fn record(&mut self, answered: bool) {
        self.ring.push(answered);
    }

    pub fn len(&self) -> usize {
        self.ring.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ring.is_empty()
    }

    /// Percentage of unanswered probes in the window, `0.0..=100.0`. Empty window is 0.0.
    pub fn loss_pct(&self) -> f64 {
        let n = self.ring.len();
        if n == 0 {
            return 0.0;
        }
        let lost = self.ring.iter().filter(|&&answered| !answered).count();
        (lost as f64 / n as f64) * 100.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn approx(a: f64, b: f64) {
        assert!((a - b).abs() < 1e-9, "expected ~{b}, got {a}");
    }

    #[test]
    fn ring_new_caps_minimum_one() {
        let rb: RingBuffer<i32> = RingBuffer::new(0);
        assert_eq!(rb.capacity(), 1);
    }

    #[test]
    fn ring_push_evicts_oldest_and_preserves_order() {
        let mut rb = RingBuffer::new(3);
        rb.push(1);
        rb.push(2);
        rb.push(3);
        rb.push(4); // evicts 1
        assert_eq!(rb.len(), 3);
        assert_eq!(rb.iter().copied().collect::<Vec<_>>(), vec![2, 3, 4]);
        assert_eq!(rb.latest(), Some(&4));
    }

    #[test]
    fn ring_empty_state() {
        let rb: RingBuffer<i32> = RingBuffer::new(2);
        assert!(rb.is_empty());
        assert_eq!(rb.latest(), None);
    }

    #[test]
    fn series_stats_on_empty_are_none() {
        let s = Series::new(8);
        assert_eq!(s.min(), None);
        assert_eq!(s.max(), None);
        assert_eq!(s.mean(), None);
        assert_eq!(s.p95(), None);
        assert_eq!(s.jitter(), None);
    }

    #[test]
    fn series_min_max_mean() {
        let mut s = Series::new(8);
        for v in [10.0, 20.0, 30.0] {
            s.push(v);
        }
        approx(s.min().unwrap(), 10.0);
        approx(s.max().unwrap(), 30.0);
        approx(s.mean().unwrap(), 20.0);
        assert_eq!(s.values(), vec![10.0, 20.0, 30.0]);
    }

    #[test]
    fn series_percentile_nearest_rank() {
        let mut s = Series::new(200);
        for i in 1..=100 {
            s.push(i as f64);
        }
        approx(s.p95().unwrap(), 95.0);
        approx(s.percentile(0.0).unwrap(), 1.0); // min
        approx(s.percentile(100.0).unwrap(), 100.0); // max
    }

    #[test]
    fn series_percentile_median_odd() {
        let mut s = Series::new(8);
        for v in [30.0, 10.0, 20.0] {
            s.push(v);
        }
        approx(s.percentile(50.0).unwrap(), 20.0);
    }

    #[test]
    fn series_jitter_is_mean_abs_consecutive_diff() {
        let mut s = Series::new(8);
        for v in [10.0, 12.0, 10.0, 14.0] {
            s.push(v);
        }
        // diffs: |2|, |2|, |4| -> mean 8/3
        approx(s.jitter().unwrap(), 8.0 / 3.0);
    }

    #[test]
    fn series_jitter_needs_two_samples() {
        let mut s = Series::new(8);
        s.push(5.0);
        assert_eq!(s.jitter(), None);
    }

    #[test]
    fn loss_empty_is_zero() {
        let w = LossWindow::new(4);
        approx(w.loss_pct(), 0.0);
    }

    #[test]
    fn loss_all_answered_is_zero() {
        let mut w = LossWindow::new(4);
        for _ in 0..4 {
            w.record(true);
        }
        approx(w.loss_pct(), 0.0);
    }

    #[test]
    fn loss_half() {
        let mut w = LossWindow::new(4);
        w.record(true);
        w.record(false);
        w.record(true);
        w.record(false);
        approx(w.loss_pct(), 50.0);
    }

    #[test]
    fn loss_window_evicts_old_outcomes() {
        let mut w = LossWindow::new(4);
        w.record(false); // will be evicted
        for _ in 0..4 {
            w.record(true);
        }
        assert_eq!(w.len(), 4);
        approx(w.loss_pct(), 0.0);
    }
}
