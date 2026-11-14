//! The frozen evaluation protocol, as code.
//!
//! `docs/FROZEN_EVALUATION_PROTOCOL.md` is the authoritative statement. This
//! module holds the parts of it that the experiment runner executes: seed
//! sets, the threshold grid and selection rule, and the pre-declared
//! decision rule for the primary hypothesis. Changing anything here after
//! the held-out evaluation has been run is a protocol deviation and must be
//! recorded as one.

use serde::Serialize;

use crate::stats::Summary;

pub const PROTOCOL_VERSION: &str = "1.0";

/// Units per scenario family in the development and held-out evaluations.
pub const SCALE: u32 = 30;
/// Units per trace of the controlled family in the exploratory sweeps.
pub const SWEEP_SCALE: u32 = 60;

/// Seeds that may be used for development and threshold selection.
pub fn development_seeds() -> Vec<u64> {
    (1..=20).collect()
}

/// Seeds reserved for the final evaluation. Never used for tuning.
pub fn heldout_seeds() -> Vec<u64> {
    (1001..=1040).collect()
}

/// Seeds for the exploratory sweeps. Disjoint from both sets above.
pub fn sweep_seeds() -> Vec<u64> {
    (2001..=2010).collect()
}

/// Candidate abstention thresholds, in thousandths.
pub const THRESHOLD_GRID: &[u16] = &[500, 550, 600, 650, 700, 750, 800, 850, 900, 950, 990];

/// Target for the threshold-selection rule: pooled development selective
/// risk of `continuity-abstain` at most this.
pub const TARGET_DEV_SELECTIVE_RISK: f64 = 0.01;

/// The threshold chosen by [`select_threshold`] on the development seeds,
/// recorded here before the held-out evaluation was run. See
/// `results/dev/threshold_selection.md` for the table it was chosen from.
pub const FROZEN_THRESHOLD_PER_MILLE: Option<u16> = Some(700);

/// One row of the development threshold table: a grid threshold and the
/// selective risk of `continuity-abstain` there, pooled over all
/// development seeds and scenario families (`None` if it made no confident
/// decision at an opportunity).
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct ThresholdRow {
    pub threshold_per_mille: u16,
    pub pooled_selective_risk: Option<f64>,
    pub pooled_decision_coverage: Option<f64>,
}

/// The pre-declared selection rule: the **lowest** grid threshold whose
/// pooled development selective risk is at most
/// [`TARGET_DEV_SELECTIVE_RISK`]. The lowest qualifying threshold abstains
/// least, so this maximises coverage subject to the risk target. If no grid
/// threshold qualifies, the highest grid threshold is used.
pub fn select_threshold(rows: &[ThresholdRow]) -> u16 {
    let mut sorted: Vec<&ThresholdRow> = rows.iter().collect();
    sorted.sort_by_key(|r| r.threshold_per_mille);
    sorted
        .iter()
        .find(|r| {
            r.pooled_selective_risk
                .is_some_and(|risk| risk <= TARGET_DEV_SELECTIVE_RISK)
        })
        .or(sorted.last())
        .map_or(990, |r| r.threshold_per_mille)
}

/// Abstention counts as practically useful only if it at least halves the
/// forced method's selective risk.
pub const PRACTICAL_RISK_RATIO: f64 = 0.5;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verdict {
    /// The paired risk reduction is positive with its 95% interval above
    /// zero, and abstaining at least halves the forced method's risk.
    Supported,
    /// The reduction's interval is above zero, but risk is not halved.
    Weakened,
    /// The interval includes zero.
    Inconclusive,
    /// The interval is entirely at or below zero: abstaining did not lower
    /// selective risk.
    Rejected,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Supported => "supported",
            Verdict::Weakened => "weakened",
            Verdict::Inconclusive => "inconclusive",
            Verdict::Rejected => "rejected",
        }
    }
}

/// The pre-declared decision rule for the primary hypothesis.
///
/// * `difference`: over held-out seeds, the per-seed selective risk of
///   `continuity-forced` minus that of `continuity-abstain`.
/// * `forced_mean`, `abstain_mean`: the two methods' mean selective risk.
pub fn primary_verdict(difference: &Summary, forced_mean: f64, abstain_mean: f64) -> Verdict {
    if difference.ci_high <= 0.0 {
        Verdict::Rejected
    } else if difference.ci_low <= 0.0 {
        Verdict::Inconclusive
    } else if abstain_mean <= PRACTICAL_RISK_RATIO * forced_mean {
        Verdict::Supported
    } else {
        Verdict::Weakened
    }
}

/// The pre-declared per-family reading used by the "when abstention helps"
/// table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FamilyEffect {
    /// Risk reduction interval above zero.
    Helps,
    /// Interval includes zero, or both methods made no error.
    NoMeasurableEffect,
    /// Risk reduction interval below zero.
    Hurts,
}

impl FamilyEffect {
    pub fn as_str(self) -> &'static str {
        match self {
            FamilyEffect::Helps => "helps",
            FamilyEffect::NoMeasurableEffect => "no measurable effect",
            FamilyEffect::Hurts => "hurts",
        }
    }
}

pub fn family_effect(risk_reduction: Option<&Summary>) -> FamilyEffect {
    match risk_reduction {
        Some(d) if d.ci_low > 0.0 => FamilyEffect::Helps,
        Some(d) if d.ci_high < 0.0 => FamilyEffect::Hurts,
        _ => FamilyEffect::NoMeasurableEffect,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(threshold: u16, risk: Option<f64>) -> ThresholdRow {
        ThresholdRow {
            threshold_per_mille: threshold,
            pooled_selective_risk: risk,
            pooled_decision_coverage: Some(0.9),
        }
    }

    fn diff(ci_low: f64, ci_high: f64) -> Summary {
        Summary {
            n: 40,
            mean: (ci_low + ci_high) / 2.0,
            sd: 0.01,
            min: ci_low,
            max: ci_high,
            ci_low,
            ci_high,
        }
    }

    #[test]
    fn seed_sets_are_disjoint_and_the_heldout_set_has_at_least_thirty() {
        let (dev, held, sweep) = (development_seeds(), heldout_seeds(), sweep_seeds());
        assert!(held.len() >= 30);
        assert!(dev.iter().all(|s| !held.contains(s) && !sweep.contains(s)));
        assert!(held.iter().all(|s| !sweep.contains(s)));
    }

    #[test]
    fn the_grid_is_increasing_and_within_range() {
        assert!(THRESHOLD_GRID.windows(2).all(|w| w[0] < w[1]));
        assert!(THRESHOLD_GRID.iter().all(|t| (1..=1000).contains(t)));
    }

    #[test]
    fn selection_takes_the_lowest_threshold_meeting_the_target() {
        let rows = [
            row(900, Some(0.004)),
            row(500, Some(0.20)),
            row(700, Some(0.01)),
            row(800, Some(0.006)),
        ];
        assert_eq!(select_threshold(&rows), 700);
    }

    #[test]
    fn selection_falls_back_to_the_highest_threshold() {
        let rows = [row(500, Some(0.2)), row(990, Some(0.05)), row(700, None)];
        assert_eq!(select_threshold(&rows), 990);
    }

    #[test]
    fn selection_ignores_undefined_risk() {
        let rows = [row(500, None), row(600, Some(0.0))];
        assert_eq!(select_threshold(&rows), 600);
    }

    #[test]
    fn primary_verdict_follows_the_declared_rule() {
        assert_eq!(
            primary_verdict(&diff(0.01, 0.03), 0.10, 0.04),
            Verdict::Supported
        );
        assert_eq!(
            primary_verdict(&diff(0.01, 0.03), 0.10, 0.05),
            Verdict::Supported
        );
        assert_eq!(
            primary_verdict(&diff(0.01, 0.03), 0.10, 0.08),
            Verdict::Weakened
        );
        assert_eq!(
            primary_verdict(&diff(-0.01, 0.03), 0.10, 0.01),
            Verdict::Inconclusive
        );
        assert_eq!(
            primary_verdict(&diff(-0.03, -0.01), 0.10, 0.12),
            Verdict::Rejected
        );
        assert_eq!(
            primary_verdict(&diff(0.0, 0.0), 0.0, 0.0),
            Verdict::Rejected
        );
    }

    #[test]
    fn family_effect_follows_the_declared_rule() {
        assert_eq!(family_effect(Some(&diff(0.01, 0.02))), FamilyEffect::Helps);
        assert_eq!(
            family_effect(Some(&diff(-0.02, -0.01))),
            FamilyEffect::Hurts
        );
        assert_eq!(
            family_effect(Some(&diff(-0.01, 0.02))),
            FamilyEffect::NoMeasurableEffect
        );
        assert_eq!(
            family_effect(Some(&diff(0.0, 0.0))),
            FamilyEffect::NoMeasurableEffect
        );
        assert_eq!(family_effect(None), FamilyEffect::NoMeasurableEffect);
    }
}
