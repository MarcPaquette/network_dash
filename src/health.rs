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
}
