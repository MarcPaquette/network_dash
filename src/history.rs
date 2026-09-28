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

    /// Mutable access to the most recently pushed element, for buffers whose newest slot
    /// accumulates (e.g. the worst health seen so far in the current minute).
    pub fn latest_mut(&mut self) -> Option<&mut T> {
        self.buf.back_mut()
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

    /// Percentage of unanswered probes among those actually recorded, `0.0..=100.0`. Empty
    /// window is 0.0. This is the observed figure, and what the panel shows.
    pub fn loss_pct(&self) -> f64 {
        let n = self.ring.len();
        if n == 0 {
            return 0.0;
        }
        (self.lost() as f64 / n as f64) * 100.0
    }

    /// Loss as a rate over the **whole** window, counting slots not yet probed as answered.
    ///
    /// This is what the health verdict reads, and it differs from [`Self::loss_pct`] only
    /// until the window first fills. Dividing by the probes seen so far makes the opening
    /// minute wildly overconfident: one dropped echo eleven probes after launch is "9%
    /// loss", a crit-grade rate inferred from a single packet. A window is a rate over a
    /// span of time, and time that has not passed yet has not lost anything.
    pub fn rate_over_window(&self) -> f64 {
        (self.lost() as f64 / self.ring.capacity() as f64) * 100.0
    }

    /// Number of unanswered probes currently in the window.
    pub fn lost(&self) -> usize {
        self.ring.iter().filter(|&&answered| !answered).count()
    }
}

/// What a window of probe outcomes says the *typical* probe does.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Typical {
    /// Nothing has been recorded yet.
    Unknown,
    /// The typical probe comes back in this many milliseconds.
    Rtt(f64),
    /// The typical probe does not come back at all.
    TimedOut,
}

/// A short rolling window of probe outcomes — a measured RTT, or a timeout.
///
/// This is what the latency verdict is read from, and it exists because the alternative —
/// classifying the single most recent packet — cannot tell a link that is slow from a link
/// that was slow *once*. Over Wi-Fi an isolated 200 ms echo to your own router is ordinary
/// (the radio was asleep), and judging it in isolation reports a fault that nothing else on
/// the dashboard can corroborate.
///
/// Deliberately short: the verdict has to be able to change within a few probes, so this is
/// not the same window the chart is drawn from.
#[derive(Debug, Clone)]
pub struct OutcomeWindow {
    ring: RingBuffer<Option<f64>>,
}

impl OutcomeWindow {
    pub fn new(cap: usize) -> Self {
        Self {
            ring: RingBuffer::new(cap),
        }
    }

    /// Record one probe: its RTT, or `None` if it timed out.
    pub fn record(&mut self, rtt_ms: Option<f64>) {
        self.ring.push(rtt_ms);
    }

    pub fn len(&self) -> usize {
        self.ring.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ring.is_empty()
    }

    /// The median outcome, with timeouts ranked worse than any RTT.
    ///
    /// Ranking a lost packet above the slowest measured one is the whole point: sorting it
    /// anywhere else lets an outage — where there is no RTT to be slow — read as healthy.
    pub fn typical(&self) -> Typical {
        let n = self.ring.len();
        if n == 0 {
            return Typical::Unknown;
        }
        let mut sorted: Vec<Option<f64>> = self.ring.iter().copied().collect();
        // `None` (a timeout) sorts last: worse than every measured value.
        sorted.sort_by(|a, b| match (a, b) {
            (Some(x), Some(y)) => x.total_cmp(y),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => std::cmp::Ordering::Equal,
        });
        // Nearest-rank median, matching `Series::percentile`'s convention.
        match sorted[(n - 1) / 2] {
            Some(ms) => Typical::Rtt(ms),
            None => Typical::TimedOut,
        }
    }
}

/// Render a span of seconds as a compact age: `45s`, `3m`, `2h`, `2d`.
///
/// Shared by the panel that ages a reading and the diagnosis text that quotes the window a
/// baseline was drawn from — one implementation, so the two can never describe the same
/// span differently. A negative span (a clock that stepped backwards) reads as `0s` rather
/// than as a measurement from the future.
pub fn compact_age(secs: i64) -> String {
    let s = secs.max(0);
    match s {
        _ if s < 60 => format!("{s}s"),
        _ if s < 3_600 => format!("{}m", s / 60),
        _ if s < 86_400 => format!("{}h", s / 3_600),
        _ => format!("{}d", s / 86_400),
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
    fn ring_latest_mut_updates_the_newest_slot_in_place() {
        let mut rb = RingBuffer::new(3);
        rb.push(1);
        rb.push(2);
        *rb.latest_mut().unwrap() = 9;
        assert_eq!(rb.iter().copied().collect::<Vec<_>>(), vec![1, 9]);
        assert_eq!(rb.len(), 2, "mutating must not append");
    }

    #[test]
    fn ring_latest_mut_is_none_when_empty() {
        let mut rb: RingBuffer<i32> = RingBuffer::new(3);
        assert!(rb.latest_mut().is_none());
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

    /// A rate needs a denominator. Before the window fills, the observed figure and the
    /// rate over the window are different numbers, and only one of them is safe to judge.
    #[test]
    fn a_partly_filled_loss_window_does_not_inflate_the_rate() {
        let mut w = LossWindow::new(60);
        w.record(false);
        for _ in 0..10 {
            w.record(true);
        }
        approx(w.loss_pct(), 100.0 / 11.0); // observed: 9%, and honestly so
        approx(w.rate_over_window(), 100.0 / 60.0); // judged: 1.7%, one packet in a minute
    }

    #[test]
    fn a_full_loss_window_reports_the_same_rate_either_way() {
        let mut w = LossWindow::new(4);
        w.record(false);
        for _ in 0..3 {
            w.record(true);
        }
        approx(w.loss_pct(), 25.0);
        approx(w.rate_over_window(), 25.0);
    }

    /// An outage from the first probe still crosses a crit bound quickly — the point is to
    /// stop inferring a rate from one packet, not to go quiet during a real one.
    #[test]
    fn a_total_outage_still_climbs_the_rate_fast() {
        let mut w = LossWindow::new(60);
        for _ in 0..6 {
            w.record(false);
        }
        approx(w.rate_over_window(), 10.0);
    }

    /// Feed a window of `cap` outcomes and read its verdict.
    fn outcomes(cap: usize, seq: &[Option<f64>]) -> Typical {
        let mut w = OutcomeWindow::new(cap);
        for &o in seq {
            w.record(o);
        }
        w.typical()
    }

    #[test]
    fn an_empty_outcome_window_has_no_opinion() {
        assert_eq!(OutcomeWindow::new(10).typical(), Typical::Unknown);
    }

    #[test]
    fn the_typical_outcome_is_the_median_rtt() {
        let seq: Vec<Option<f64>> = [5.0, 4.0, 6.0, 5.0, 200.0]
            .iter()
            .map(|&v| Some(v))
            .collect();
        assert_eq!(outcomes(10, &seq), Typical::Rtt(5.0));
    }

    /// The reason this type exists: one slow packet on an otherwise quick link is not a slow
    /// link, and reading the latest outcome instead of the median is how it was reported as one.
    #[test]
    fn a_lone_spike_does_not_move_the_typical_outcome() {
        let mut seq: Vec<Option<f64>> = (0..9).map(|_| Some(4.0)).collect();
        seq.push(Some(400.0));
        assert_eq!(outcomes(10, &seq), Typical::Rtt(4.0));
    }

    /// ...and neither does one dropped packet. A window that flipped to `TimedOut` here would
    /// report a total outage every time Wi-Fi lost a single echo.
    #[test]
    fn a_lone_timeout_does_not_move_the_typical_outcome() {
        let mut seq: Vec<Option<f64>> = (0..9).map(|_| Some(4.0)).collect();
        seq.push(None);
        assert_eq!(outcomes(10, &seq), Typical::Rtt(4.0));
    }

    /// A timeout is not fast. Sorting it as a missing value rather than as the worst possible
    /// one is how an outage — where there is no RTT left to be slow — reads as healthy.
    #[test]
    fn a_window_of_mostly_timeouts_is_a_timeout() {
        let seq = vec![Some(4.0), None, None, None, Some(5.0)];
        assert_eq!(outcomes(10, &seq), Typical::TimedOut);
    }

    #[test]
    fn a_sustained_slowdown_moves_the_typical_outcome() {
        let seq: Vec<Option<f64>> = (0..10).map(|_| Some(120.0)).collect();
        assert_eq!(outcomes(10, &seq), Typical::Rtt(120.0));
    }

    /// The window is short on purpose, so a link that recovers is not held down by history.
    #[test]
    fn the_outcome_window_forgets_beyond_its_capacity() {
        let mut seq: Vec<Option<f64>> = (0..5).map(|_| Some(500.0)).collect();
        seq.extend((0..5).map(|_| Some(3.0)));
        assert_eq!(outcomes(5, &seq), Typical::Rtt(3.0));
    }

    #[test]
    fn an_age_reads_in_the_largest_unit_that_still_says_something() {
        assert_eq!(compact_age(0), "0s");
        assert_eq!(compact_age(45), "45s");
        assert_eq!(compact_age(90), "1m");
        assert_eq!(compact_age(180), "3m");
        assert_eq!(compact_age(3600), "1h");
        assert_eq!(compact_age(7_200), "2h");
        assert_eq!(compact_age(172_800), "2d");
    }

    // A clock that stepped backwards must not render "-3s ago".
    #[test]
    fn a_negative_span_is_not_an_age() {
        assert_eq!(compact_age(-5), "0s");
    }
}
