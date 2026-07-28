//! Health classification for metrics.
//!
//! [`Health`] is the three-level severity used everywhere (borders, header rollup,
//! incident severity). [`Thresholds`] classifies a scalar value against warn/crit
//! bounds. The debounce/hysteresis state machine that smooths flapping is added in a
//! later phase and builds on these types.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

/// Health state of a single metric, ordered `Ok < Warn < Crit` so the worst state of a
/// set is simply the maximum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Health {
    Ok,
    Warn,
    Crit,
}

impl Health {
    /// The more severe of two states.
    pub fn worst(self, other: Health) -> Health {
        self.max(other)
    }

    /// Roll a set of states up into the single worst one. An empty set is [`Health::Ok`].
    pub fn worst_of(iter: impl IntoIterator<Item = Health>) -> Health {
        iter.into_iter().max().unwrap_or(Health::Ok)
    }
}

/// Which direction of a metric's value is "bad".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// Larger is worse — latency, jitter, loss%, DNS resolution time.
    HigherIsWorse,
    /// Smaller is worse — throughput Mbps, WiFi RSSI (dBm).
    LowerIsWorse,
}

/// Warn/crit thresholds for a scalar metric.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Thresholds {
    pub warn: f64,
    pub crit: f64,
    pub direction: Direction,
}

impl Thresholds {
    /// Thresholds where crossing upward is bad (`warn <= crit`).
    pub fn higher_is_worse(warn: f64, crit: f64) -> Self {
        Self {
            warn,
            crit,
            direction: Direction::HigherIsWorse,
        }
    }

    /// Thresholds where dropping is bad (`warn >= crit`).
    pub fn lower_is_worse(warn: f64, crit: f64) -> Self {
        Self {
            warn,
            crit,
            direction: Direction::LowerIsWorse,
        }
    }

    /// Classify `value`. Bounds are **inclusive**: reaching `warn` is [`Health::Warn`],
    /// reaching `crit` is [`Health::Crit`].
    pub fn evaluate(&self, value: f64) -> Health {
        match self.direction {
            Direction::HigherIsWorse => {
                if value >= self.crit {
                    Health::Crit
                } else if value >= self.warn {
                    Health::Warn
                } else {
                    Health::Ok
                }
            }
            Direction::LowerIsWorse => {
                if value <= self.crit {
                    Health::Crit
                } else if value <= self.warn {
                    Health::Warn
                } else {
                    Health::Ok
                }
            }
        }
    }
}

/// Debounces a stream of raw [`Health`] classifications so the *reported* state only
/// changes once a differing value has persisted for a minimum **duration**.
///
/// Time, not a sample count: a count means something different on every probe. Three
/// consecutive samples is 3 seconds of ping but 45 seconds of Wi-Fi polling, so one knob
/// could never mean the same thing twice. Wall-clock is also what an operator actually
/// cares about — "it has been bad for ten seconds", not "for four readings".
///
/// The two dwells are asymmetric on purpose. Tripping is fast, because a fault you are
/// slow to report is a fault you notice from a user complaint instead. Clearing is slow,
/// because a link that dips healthy for a moment mid-flap is not fixed, and reporting it
/// as recovered turns one incident into a stream of round trips.
#[derive(Debug, Clone)]
pub struct Debouncer {
    current: Health,
    /// The differing state we are waiting on, and when its run began.
    pending: Option<(Health, DateTime<Utc>)>,
    trip_after: Duration,
    clear_after: Duration,
}

impl Debouncer {
    /// Start in `initial`, requiring a worse state to persist for `trip_after` and a
    /// better one for `clear_after` before it is committed.
    pub fn new(initial: Health, trip_after: Duration, clear_after: Duration) -> Self {
        Self {
            current: initial,
            pending: None,
            trip_after,
            clear_after,
        }
    }

    /// The currently reported (committed) state.
    pub fn current(&self) -> Health {
        self.current
    }

    /// Feed one raw classification observed at `now`. Returns `Some(new_state)` on a
    /// confirmed transition, otherwise `None`.
    pub fn update(&mut self, now: DateTime<Utc>, raw: Health) -> Option<Health> {
        if raw == self.current {
            // Back to (or still at) the committed state: abandon any pending change.
            self.pending = None;
            return None;
        }
        let worsening = raw > self.current;
        let since = match &mut self.pending {
            // Still on the same side of the committed state — a fault that deepened, or a
            // recovery that stalled part-way. The run began when the state first differed,
            // so getting worse (or less bad) must not buy a fresh grace period.
            Some((candidate, since)) if (*candidate > self.current) == worsening => {
                *candidate = raw;
                // A clock corrected backwards would otherwise strand `since` in the
                // future, where no later sample could ever satisfy the dwell.
                *since = (*since).min(now);
                *since
            }
            _ => {
                self.pending = Some((raw, now));
                now
            }
        };
        let dwell = if worsening {
            self.trip_after
        } else {
            self.clear_after
        };
        if now.signed_duration_since(since) >= dwell {
            self.current = raw;
            self.pending = None;
            Some(raw)
        } else {
            None
        }
    }
}

/// Spots a metric that keeps changing its mind.
///
/// The [`Debouncer`] stops one bad reading from raising an alert, but it has nothing to say
/// about a link that genuinely trips and clears every ten seconds. That produces a stream of
/// perfectly-correct incidents which together convey one fact — "this is unstable" — and
/// bury everything else in the feed while doing it.
///
/// Once `flaps` committed transitions land inside `window`, the detector says so, and the
/// caller reports that instead of the individual swings. It settles again when the window
/// empties, which needs the passage of time, not a transition: a metric that has gone quiet
/// has no swings left to notice with.
#[derive(Debug, Clone)]
pub struct FlapDetector {
    /// Transition instants inside the window, oldest first.
    transitions: std::collections::VecDeque<DateTime<Utc>>,
    flaps: usize,
    window: Duration,
    flapping: bool,
}

impl FlapDetector {
    /// Report flapping once `flaps` transitions fall within `window`. A `flaps` under 2 is
    /// treated as *disabled* — "every transition is a flap" would silence the whole feed.
    pub fn new(flaps: usize, window: Duration) -> Self {
        Self {
            transitions: std::collections::VecDeque::new(),
            flaps,
            window,
            flapping: false,
        }
    }

    /// Whether the metric is currently considered unstable.
    pub fn is_flapping(&self) -> bool {
        self.flapping
    }

    /// Transitions currently inside the window — what the "is flapping" incident reports.
    pub fn recent(&self) -> usize {
        self.transitions.len()
    }

    /// Record whether a transition happened at `now`, expiring any that have aged out.
    ///
    /// Returns `Some(true)` the moment the metric starts flapping and `Some(false)` the
    /// moment it settles; `None` when the verdict is unchanged. Callers should pass
    /// `false` on every fold so a quiet metric can settle.
    pub fn observe(&mut self, now: DateTime<Utc>, transitioned: bool) -> Option<bool> {
        if transitioned {
            self.transitions.push_back(now);
        }
        // A clock corrected backwards would otherwise hold stale transitions forever.
        let cutoff = now - self.window;
        while self.transitions.front().is_some_and(|t| *t < cutoff) {
            self.transitions.pop_front();
        }
        let flapping = self.flaps >= 2 && self.transitions.len() >= self.flaps;
        if flapping == self.flapping {
            return None;
        }
        self.flapping = flapping;
        Some(flapping)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use rstest::rstest;

    #[test]
    fn health_orders_ok_warn_crit() {
        assert!(Health::Ok < Health::Warn);
        assert!(Health::Warn < Health::Crit);
    }

    #[rstest]
    #[case(10.0, Health::Ok)] // comfortably under warn
    #[case(79.999, Health::Ok)] // just under warn
    #[case(80.0, Health::Warn)] // warn boundary is inclusive
    #[case(120.0, Health::Warn)] // between warn and crit
    #[case(150.0, Health::Crit)] // crit boundary is inclusive
    #[case(300.0, Health::Crit)] // well over crit
    fn evaluate_higher_is_worse(#[case] value: f64, #[case] expected: Health) {
        let t = Thresholds::higher_is_worse(80.0, 150.0);
        assert_eq!(t.evaluate(value), expected);
    }

    #[rstest]
    #[case(500.0, Health::Ok)] // fast link is fine
    #[case(100.1, Health::Ok)] // just above warn
    #[case(100.0, Health::Warn)] // warn boundary is inclusive
    #[case(50.0, Health::Warn)] // between warn and crit
    #[case(20.0, Health::Crit)] // crit boundary is inclusive
    #[case(1.0, Health::Crit)] // near-dead link
    fn evaluate_lower_is_worse(#[case] value: f64, #[case] expected: Health) {
        let t = Thresholds::lower_is_worse(100.0, 20.0);
        assert_eq!(t.evaluate(value), expected);
    }

    #[test]
    fn worst_picks_more_severe() {
        assert_eq!(Health::Ok.worst(Health::Warn), Health::Warn);
        assert_eq!(Health::Crit.worst(Health::Warn), Health::Crit);
    }

    #[test]
    fn worst_of_rolls_up() {
        assert_eq!(
            Health::worst_of([Health::Ok, Health::Warn, Health::Ok]),
            Health::Warn
        );
        assert_eq!(
            Health::worst_of([Health::Ok, Health::Crit, Health::Warn]),
            Health::Crit
        );
        assert_eq!(Health::worst_of([Health::Ok, Health::Ok]), Health::Ok);
        assert_eq!(Health::worst_of([]), Health::Ok);
    }

    use Health::{Crit, Ok as HOk, Warn};
    use chrono::{Duration, TimeZone, Utc};

    fn t0() -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 20, 14, 0, 0).unwrap()
    }

    fn secs(n: i64) -> Duration {
        Duration::seconds(n)
    }

    /// Feed `(offset_secs, raw)` pairs, collecting the transition emitted at each step.
    fn run(
        initial: Health,
        trip: Duration,
        clear: Duration,
        seq: &[(i64, Health)],
    ) -> Vec<Option<Health>> {
        let mut d = Debouncer::new(initial, trip, clear);
        seq.iter()
            .map(|&(at, h)| d.update(t0() + secs(at), h))
            .collect()
    }

    #[test]
    fn debouncer_starts_in_initial() {
        let d = Debouncer::new(Warn, secs(3), secs(15));
        assert_eq!(d.current(), Warn);
    }

    #[test]
    fn debouncer_zero_dwell_trips_on_the_first_differing_sample() {
        let out = run(HOk, Duration::zero(), Duration::zero(), &[(0, Crit)]);
        assert_eq!(out, vec![Some(Crit)]);
    }

    #[test]
    fn debouncer_stable_stream_never_transitions() {
        let out = run(HOk, secs(3), secs(15), &[(0, HOk), (5, HOk), (10, HOk)]);
        assert_eq!(out, vec![None, None, None]);
    }

    #[test]
    fn debouncer_single_blip_is_ignored() {
        let mut d = Debouncer::new(HOk, secs(3), secs(15));
        assert_eq!(d.update(t0(), Crit), None);
        assert_eq!(d.update(t0() + secs(1), HOk), None);
        assert_eq!(d.current(), HOk);
    }

    #[test]
    fn debouncer_trips_only_once_the_fault_has_persisted() {
        // A fault seen for 2s is still inside the 3s dwell; the sample at 3s commits it.
        let out = run(
            HOk,
            secs(3),
            secs(15),
            &[(0, Crit), (2, Crit), (3, Crit), (4, Crit)],
        );
        assert_eq!(out, vec![None, None, Some(Crit), None]);
    }

    #[test]
    fn debouncer_is_slower_to_clear_than_to_trip() {
        // The asymmetry is the whole point: a flapping link that dips healthy for a few
        // seconds must not be reported as recovered, or the log fills with round trips.
        let out = run(
            Crit,
            secs(3),
            secs(15),
            &[(0, HOk), (5, HOk), (10, HOk), (15, HOk)],
        );
        assert_eq!(out, vec![None, None, None, Some(HOk)]);
    }

    #[test]
    fn debouncer_partial_recovery_waits_the_clear_dwell_too() {
        // Crit → Warn is an improvement, so it earns the slow path even though the metric
        // is still unhealthy.
        let out = run(Crit, secs(3), secs(15), &[(0, Warn), (5, Warn), (15, Warn)]);
        assert_eq!(out, vec![None, None, Some(Warn)]);
    }

    #[test]
    fn debouncer_escalation_does_not_restart_the_clock() {
        // Warn at 0s then Crit at 3s: the fault has been present for the full dwell, and
        // getting worse is no reason to hand it a fresh grace period.
        let out = run(HOk, secs(3), secs(15), &[(0, Warn), (3, Crit)]);
        assert_eq!(out, vec![None, Some(Crit)]);
    }

    #[test]
    fn debouncer_return_to_stable_clears_pending() {
        // Crit for 2s, back to Ok, then Crit again: the clock restarts from the second run.
        let out = run(
            HOk,
            secs(3),
            secs(15),
            &[(0, Crit), (2, Crit), (3, HOk), (4, Crit), (6, Crit)],
        );
        assert_eq!(out, vec![None, None, None, None, None]);
    }

    #[test]
    fn debouncer_a_clock_that_steps_backwards_does_not_strand_a_pending_change() {
        // NTP correcting a skewed clock mid-fault must not leave `pending` anchored in the
        // future, where no later sample could ever satisfy the dwell.
        let mut d = Debouncer::new(HOk, secs(3), secs(15));
        assert_eq!(d.update(t0() + secs(600), Crit), None);
        assert_eq!(d.update(t0(), Crit), None); // clock corrected backwards
        assert_eq!(d.update(t0() + secs(3), Crit), Some(Crit));
    }

    #[test]
    fn debouncer_current_tracks_committed_state() {
        let mut d = Debouncer::new(HOk, secs(3), secs(15));
        d.update(t0(), Crit);
        assert_eq!(d.current(), HOk); // not yet committed
        d.update(t0() + secs(3), Crit);
        assert_eq!(d.current(), Crit);
    }

    // --- FlapDetector ---

    /// Four swings inside two minutes is "unstable"; the app's default shape.
    fn detector() -> FlapDetector {
        FlapDetector::new(4, secs(120))
    }

    #[test]
    fn a_metric_that_transitions_once_is_not_flapping() {
        let mut d = detector();
        assert_eq!(d.observe(t0(), true), None);
        assert!(!d.is_flapping());
    }

    #[test]
    fn enough_transitions_inside_the_window_is_flapping() {
        let mut d = detector();
        for i in 0..3 {
            assert_eq!(d.observe(t0() + secs(i * 10), true), None, "swing {i}");
        }
        assert_eq!(
            d.observe(t0() + secs(30), true),
            Some(true),
            "the fourth swing in 30s is the one that says 'unstable'"
        );
        assert!(d.is_flapping());
    }

    #[test]
    fn flapping_is_announced_once_not_on_every_further_swing() {
        let mut d = detector();
        for i in 0..4 {
            d.observe(t0() + secs(i * 10), true);
        }
        assert_eq!(d.observe(t0() + secs(50), true), None, "already said so");
        assert_eq!(d.observe(t0() + secs(60), true), None);
    }

    #[test]
    fn transitions_spread_beyond_the_window_are_not_flapping() {
        // Four swings, but one every 60s: that is a link changing state, not thrashing.
        let mut d = detector();
        for i in 0..6 {
            assert_eq!(d.observe(t0() + secs(i * 60), true), None, "swing {i}");
        }
        assert!(!d.is_flapping());
    }

    #[test]
    fn a_flapping_metric_settles_once_the_window_empties() {
        let mut d = detector();
        for i in 0..4 {
            d.observe(t0() + secs(i * 10), true);
        }
        assert!(d.is_flapping());
        // Time passes with no further swings; the last one ages out at +30s +120s.
        assert_eq!(
            d.observe(t0() + secs(100), false),
            None,
            "still within the window"
        );
        assert_eq!(d.observe(t0() + secs(151), false), Some(false), "settled");
        assert!(!d.is_flapping());
    }

    #[test]
    fn a_settled_metric_can_start_flapping_again() {
        let mut d = detector();
        for i in 0..4 {
            d.observe(t0() + secs(i * 10), true);
        }
        assert_eq!(d.observe(t0() + secs(151), false), Some(false));
        let base = 200;
        for i in 0..3 {
            assert_eq!(d.observe(t0() + secs(base + i * 10), true), None);
        }
        assert_eq!(d.observe(t0() + secs(base + 30), true), Some(true));
    }

    #[test]
    fn a_zero_threshold_detector_never_flaps() {
        // A count of 0 (or 1) would mean "every single transition is a flap", which would
        // silence the whole event feed. Treated as "disabled" instead.
        let mut d = FlapDetector::new(0, secs(120));
        for i in 0..10 {
            assert_eq!(d.observe(t0() + secs(i), true), None, "swing {i}");
        }
        assert!(!d.is_flapping());
    }

    #[test]
    fn flap_count_reports_the_swings_that_triggered_it() {
        let mut d = detector();
        for i in 0..4 {
            d.observe(t0() + secs(i * 10), true);
        }
        assert_eq!(d.recent(), 4, "the incident should be able to say how many");
    }
}
