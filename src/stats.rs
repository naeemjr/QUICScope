//! Summary statistics over seeds, with a deterministic percentile bootstrap.

use serde::Serialize;

use crate::rng::SplitMix64;

/// Bootstrap resamples used for every confidence interval.
pub const BOOTSTRAP_RESAMPLES: usize = 10_000;

/// Distribution of one quantity over seeds.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct Summary {
    /// Seeds for which the quantity was defined.
    pub n: usize,
    pub mean: f64,
    /// Sample standard deviation (n - 1). Zero when n is 1.
    pub sd: f64,
    pub min: f64,
    pub max: f64,
    /// 95% percentile-bootstrap interval for the mean.
    pub ci_low: f64,
    pub ci_high: f64,
}

fn mean(values: &[f64]) -> f64 {
    values.iter().sum::<f64>() / values.len() as f64
}

/// Summarise `values`. Returns `None` for an empty slice.
///
/// The interval is a percentile bootstrap of the mean: resample the seeds
/// with replacement [`BOOTSTRAP_RESAMPLES`] times and take the 2.5th and
/// 97.5th percentiles of the resampled means. `stream` seeds the resampling
/// so the interval is reproducible.
pub fn summarize(values: &[f64], stream: u64) -> Option<Summary> {
    if values.is_empty() {
        return None;
    }
    let n = values.len();
    let m = mean(values);
    let sd = if n > 1 {
        let ss: f64 = values.iter().map(|v| (v - m).powi(2)).sum();
        (ss / (n - 1) as f64).sqrt()
    } else {
        0.0
    };

    let mut rng = SplitMix64::new(stream);
    let mut means: Vec<f64> = (0..BOOTSTRAP_RESAMPLES)
        .map(|_| {
            let total: f64 = (0..n).map(|_| values[rng.below(n as u64) as usize]).sum();
            total / n as f64
        })
        .collect();
    means.sort_by(f64::total_cmp);
    let at = |q: f64| means[((BOOTSTRAP_RESAMPLES - 1) as f64 * q).round() as usize];

    Some(Summary {
        n,
        mean: m,
        sd,
        min: values.iter().copied().fold(f64::INFINITY, f64::min),
        max: values.iter().copied().fold(f64::NEG_INFINITY, f64::max),
        ci_low: at(0.025),
        ci_high: at(0.975),
    })
}

/// A stable stream id from a label, so each interval has its own stream.
pub fn stream_for(label: &str) -> u64 {
    // FNV-1a.
    label.bytes().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_has_no_summary() {
        assert_eq!(summarize(&[], 1), None);
    }

    #[test]
    fn basic_moments() {
        let s = summarize(&[1.0, 2.0, 3.0, 4.0], 1).unwrap();
        assert_eq!(s.n, 4);
        assert_eq!(s.mean, 2.5);
        assert!((s.sd - 1.290_994).abs() < 1e-6);
        assert_eq!((s.min, s.max), (1.0, 4.0));
    }

    #[test]
    fn a_single_value_or_a_constant_has_a_degenerate_interval() {
        let one = summarize(&[0.25], 1).unwrap();
        assert_eq!((one.sd, one.ci_low, one.ci_high), (0.0, 0.25, 0.25));
        let flat = summarize(&[0.5; 30], 1).unwrap();
        assert_eq!((flat.sd, flat.ci_low, flat.ci_high), (0.0, 0.5, 0.5));
    }

    #[test]
    fn the_interval_brackets_the_mean_and_narrows_with_more_seeds() {
        let few: Vec<f64> = (0..10).map(|i| (i % 5) as f64).collect();
        let many: Vec<f64> = (0..400).map(|i| (i % 5) as f64).collect();
        let (a, b) = (summarize(&few, 3).unwrap(), summarize(&many, 3).unwrap());
        for s in [a, b] {
            assert!(s.ci_low <= s.mean && s.mean <= s.ci_high);
            assert!(s.min <= s.ci_low && s.ci_high <= s.max);
        }
        assert!(b.ci_high - b.ci_low < a.ci_high - a.ci_low);
    }

    #[test]
    fn the_interval_is_close_to_the_normal_approximation() {
        // 0,1,...,99: mean 49.5, standard error about 2.9.
        let values: Vec<f64> = (0..100).map(f64::from).collect();
        let s = summarize(&values, 7).unwrap();
        let half_width = 1.96 * s.sd / 10.0;
        assert!((s.ci_low - (s.mean - half_width)).abs() < 0.5, "{s:?}");
        assert!((s.ci_high - (s.mean + half_width)).abs() < 0.5, "{s:?}");
    }

    #[test]
    fn resampling_is_reproducible_per_stream() {
        let values: Vec<f64> = (0..40).map(|i| f64::from(i * i % 17)).collect();
        assert_eq!(summarize(&values, 5), summarize(&values, 5));
        let other = summarize(&values, 6).unwrap();
        let same = summarize(&values, 5).unwrap();
        assert_eq!(other.mean, same.mean);
        assert_ne!((other.ci_low, other.ci_high), (same.ci_low, same.ci_high));
    }

    #[test]
    fn stream_ids_differ_by_label() {
        assert_eq!(stream_for("a"), stream_for("a"));
        assert_ne!(
            stream_for("selective_risk"),
            stream_for("decision_coverage")
        );
    }
}
