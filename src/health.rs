//! Health classification for metrics.
//!
//! [`Health`] is the three-level severity used everywhere (borders, header rollup,
//! incident severity). [`Thresholds`] classifies a scalar value against warn/crit
//! bounds. The debounce/hysteresis state machine that smooths flapping is added in a
//! later phase and builds on these types.

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
/// changes once a differing value has been seen for `threshold` consecutive samples.
///
/// This prevents a single spurious sample (one slow ping, one dropped packet) from
/// flipping a panel red and logging a bogus incident. Recovery is debounced the same way.
#[derive(Debug, Clone)]
pub struct Debouncer {
    current: Health,
    /// The differing state we are currently counting toward, with its run length.
    pending: Option<(Health, usize)>,
    threshold: usize,
}

impl Debouncer {
    /// Start in `initial`, requiring `threshold` (min 1) consecutive samples to switch.
    pub fn new(initial: Health, threshold: usize) -> Self {
        Self {
            current: initial,
            pending: None,
            threshold: threshold.max(1),
        }
    }

    /// The currently reported (committed) state.
    pub fn current(&self) -> Health {
        self.current
    }

    /// Feed one raw classification. Returns `Some(new_state)` on a confirmed transition,
    /// otherwise `None`.
    pub fn update(&mut self, raw: Health) -> Option<Health> {
        if raw == self.current {
            // Back to (or still at) the committed state: abandon any pending change.
            self.pending = None;
            return None;
        }
        let count = match self.pending {
            Some((p, c)) if p == raw => c + 1,
            _ => 1,
        };
        if count >= self.threshold {
            self.current = raw;
            self.pending = None;
            Some(raw)
        } else {
            self.pending = Some((raw, count));
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

    /// Feed a sequence, collecting the transition emitted at each step.
    fn run(initial: Health, threshold: usize, seq: &[Health]) -> Vec<Option<Health>> {
        let mut d = Debouncer::new(initial, threshold);
        seq.iter().map(|&h| d.update(h)).collect()
    }

    #[test]
    fn debouncer_starts_in_initial() {
        let d = Debouncer::new(Warn, 3);
        assert_eq!(d.current(), Warn);
    }

    #[test]
    fn debouncer_threshold_clamped_to_one() {
        // threshold 0 behaves as 1: a single differing sample transitions immediately.
        let out = run(HOk, 0, &[Crit]);
        assert_eq!(out, vec![Some(Crit)]);
    }

    #[test]
    fn debouncer_stable_stream_never_transitions() {
        let out = run(HOk, 3, &[HOk, HOk, HOk]);
        assert_eq!(out, vec![None, None, None]);
    }

    #[test]
    fn debouncer_single_blip_is_ignored() {
        let mut d = Debouncer::new(HOk, 3);
        assert_eq!(d.update(Crit), None);
        assert_eq!(d.update(HOk), None);
        assert_eq!(d.current(), HOk);
    }

    #[test]
    fn debouncer_sustained_change_transitions_at_threshold() {
        let out = run(HOk, 3, &[Crit, Crit, Crit]);
        assert_eq!(out, vec![None, None, Some(Crit)]);
    }

    #[test]
    fn debouncer_threshold_one_transitions_immediately() {
        let out = run(HOk, 1, &[Crit]);
        assert_eq!(out, vec![Some(Crit)]);
    }

    #[test]
    fn debouncer_changing_candidate_resets_the_count() {
        // Two Warn then three Crit: only the Crit run of 3 should commit.
        let out = run(HOk, 3, &[Warn, Warn, Crit, Crit, Crit]);
        assert_eq!(out, vec![None, None, None, None, Some(Crit)]);
    }

    #[test]
    fn debouncer_return_to_stable_clears_pending() {
        // Crit,Crit then back to Ok resets; the next two Crit are not enough to commit.
        let out = run(HOk, 3, &[Crit, Crit, HOk, Crit, Crit]);
        assert_eq!(out, vec![None, None, None, None, None]);
    }

    #[test]
    fn debouncer_recovery_is_debounced() {
        let out = run(Crit, 2, &[HOk, HOk]);
        assert_eq!(out, vec![None, Some(HOk)]);
    }

    #[test]
    fn debouncer_current_tracks_committed_state() {
        let mut d = Debouncer::new(HOk, 2);
        d.update(Crit);
        assert_eq!(d.current(), HOk); // not yet committed
        d.update(Crit);
        assert_eq!(d.current(), Crit); // committed after 2
    }
}
