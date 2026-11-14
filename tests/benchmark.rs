//! Integration tests: run a small benchmark suite end to end and check the
//! properties each scenario family was built to show.
//!
//! Everything here is generated in memory from fixed development-range
//! seeds. No held-out seed is used, and no test reads a capture, opens a
//! socket, or touches a network interface.

use std::sync::OnceLock;

use quicscope::eval::{metric, Counts, METRICS};
use quicscope::experiment::{self, Row};
use quicscope::gen::Scenario;
use quicscope::tracker::{Spec, CONTINUITY_ABSTAIN, CONTINUITY_FORCED, STRICT_TUPLE};

const SEEDS: [u64; 3] = [3, 8, 14];
const SCALE: u32 = 12;
const THRESHOLD: u16 = 800;

fn rows() -> &'static [Row] {
    static ROWS: OnceLock<Vec<Row>> = OnceLock::new();
    ROWS.get_or_init(|| {
        experiment::run_families(&SEEDS, SCALE, &Spec::all(THRESHOLD)).expect("benchmark run")
    })
}

/// Counts for a tracker on a family (or on everything), pooled over seeds.
fn counts(tracker: &str, family: Option<Scenario>) -> Counts {
    Counts::pooled(
        rows()
            .iter()
            .filter(|r| r.tracker == tracker && family.is_none_or(|f| r.family == f.as_str()))
            .map(|r| &r.counts),
    )
}

fn value(c: &Counts, key: &str) -> f64 {
    metric(key).value(c).unwrap_or(f64::NAN)
}

#[test]
fn the_suite_covers_every_family_seed_and_method() {
    assert_eq!(rows().len(), SEEDS.len() * Scenario::ALL.len() * 3);
    for tracker in [STRICT_TUPLE, CONTINUITY_FORCED, CONTINUITY_ABSTAIN] {
        assert!(counts(tracker, None).observations > 5_000, "{tracker}");
    }
}

#[test]
fn every_row_is_internally_consistent() {
    for row in rows() {
        let c = &row.counts;
        let label = format!("{} on {} seed {}", row.tracker, row.family, row.seed);
        assert_eq!(c.links + c.news + c.abstentions, c.observations, "{label}");
        assert_eq!(c.correct_links + c.incorrect_links, c.links, "{label}");
        assert_eq!(c.correct_news + c.incorrect_news, c.news, "{label}");
        assert_eq!(
            c.opp_confident + c.opp_abstained,
            c.opportunities,
            "{label}"
        );
        assert_eq!(
            c.opp_ambiguous + c.opp_determined_new + c.opp_determined_link,
            c.opportunities,
            "{label}"
        );
        assert!(c.opp_incorrect <= c.opp_confident, "{label}");
        assert!(c.connections_exact <= c.connections, "{label}");
        assert!(
            c.connections_false_split <= c.connections_fragmented,
            "{label}"
        );
        assert!(c.merged_pairs <= c.connection_pairs, "{label}");
        assert!(c.abstentions_on_ambiguous <= c.abstentions, "{label}");
        assert!(
            c.cross_endpoint_incorrect <= c.cross_endpoint_links,
            "{label}"
        );
        for m in METRICS {
            if let Some(v) = m.value(c) {
                assert!((0.0..=1.0).contains(&v), "{label}: {} = {v}", m.key);
            }
        }
    }
}

#[test]
fn every_method_scores_the_same_observations_and_opportunities() {
    for chunk in rows().chunks(3) {
        let [a, b, c] = chunk else { unreachable!() };
        for other in [b, c] {
            assert_eq!(a.counts.observations, other.counts.observations);
            assert_eq!(a.counts.connections, other.counts.connections);
            assert_eq!(a.counts.opportunities, other.counts.opportunities);
            // Oracle labels do not depend on the method being scored.
            assert_eq!(a.counts.opp_ambiguous, other.counts.opp_ambiguous);
            assert_eq!(a.counts.opp_determined_new, other.counts.opp_determined_new);
        }
    }
}

#[test]
fn the_forced_methods_always_decide() {
    for tracker in [STRICT_TUPLE, CONTINUITY_FORCED] {
        let c = counts(tracker, None);
        assert_eq!(c.abstentions, 0, "{tracker}");
        assert_eq!(value(&c, "decision_coverage"), 1.0, "{tracker}");
    }
    let abstain = counts(CONTINUITY_ABSTAIN, None);
    assert!(abstain.abstentions > 0);
    assert!(value(&abstain, "decision_coverage") < 1.0);
}

#[test]
fn ordinary_sessions_are_tracked_exactly_even_where_the_oracle_calls_them_ambiguous() {
    for tracker in [STRICT_TUPLE, CONTINUITY_FORCED, CONTINUITY_ABSTAIN] {
        let c = counts(tracker, Some(Scenario::Ordinary));
        assert_eq!(c.connections_exact, c.connections, "{tracker}");
        assert_eq!(
            c.incorrect_links + c.incorrect_news + c.abstentions,
            0,
            "{tracker}"
        );
    }
    // A pause on a tuple with no connection ID is observationally ambiguous
    // under the declared model, yet deciding there is right every time
    // here. Ambiguity under the model is not the same as risk.
    let c = counts(CONTINUITY_ABSTAIN, Some(Scenario::Ordinary));
    assert!(c.opp_ambiguous > 0);
    assert_eq!(c.incorrect_on_ambiguous, 0);
    assert_eq!(value(&c, "abstention_recall"), 0.0);
}

#[test]
fn path_changes_on_an_unchanged_tuple_are_never_decided_wrongly() {
    for tracker in [STRICT_TUPLE, CONTINUITY_FORCED] {
        let c = counts(tracker, Some(Scenario::PathChange));
        assert_eq!(c.connections_exact, c.connections, "{tracker}");
        let t = c.transitions["path-change"];
        assert!(t.transitions > 0);
        assert_eq!(t.correct, t.transitions, "{tracker}");
    }
    // The abstaining method makes no error either, but it declines after
    // the longer outages when no connection ID is visible, and that costs
    // exact continuity. Here abstention has a price and buys nothing.
    let c = counts(CONTINUITY_ABSTAIN, Some(Scenario::PathChange));
    assert_eq!(c.incorrect_links + c.incorrect_news, 0);
    let t = c.transitions["path-change"];
    assert_eq!(t.correct + t.abstained, t.transitions);
    assert!(c.connections_exact <= c.connections);
    assert_eq!(c.connections_false_split, 0);
}

#[test]
fn nat_rebinding_splits_tuple_tracking_and_is_followed_by_connection_id() {
    let strict = counts(STRICT_TUPLE, Some(Scenario::NatRebinding));
    let rebinds = strict.transitions["nat-rebind"];
    assert_eq!(rebinds.incorrect_new, rebinds.transitions);
    assert_eq!(strict.connections_false_split, strict.connections);
    assert_eq!(strict.cross_endpoint_links, 0);

    for tracker in [CONTINUITY_FORCED, CONTINUITY_ABSTAIN] {
        let c = counts(tracker, Some(Scenario::NatRebinding));
        assert!(c.transitions["nat-rebind"].correct > 0, "{tracker}");
        assert!(c.cross_endpoint_links > 0, "{tracker}");
        assert!(c.connections_exact > strict.connections_exact, "{tracker}");
    }
    // Rebindings the forced method gets wrong, the abstaining one declines.
    let forced = counts(CONTINUITY_FORCED, Some(Scenario::NatRebinding));
    let abstain = counts(CONTINUITY_ABSTAIN, Some(Scenario::NatRebinding));
    assert!(abstain.opp_incorrect <= forced.opp_incorrect);
    assert_eq!(abstain.transitions["nat-rebind"].incorrect_new, 0);
}

#[test]
fn migration_is_unlinkable_forced_methods_split_and_abstain_declines() {
    for tracker in [STRICT_TUPLE, CONTINUITY_FORCED] {
        let c = counts(tracker, Some(Scenario::Migration));
        let t = c.transitions["migration"];
        assert_eq!(t.incorrect_new, t.transitions, "{tracker}");
        assert_eq!(c.connections_false_split, c.connections, "{tracker}");
        assert_eq!(c.connections_exact, 0, "{tracker}");
    }
    let c = counts(CONTINUITY_ABSTAIN, Some(Scenario::Migration));
    let t = c.transitions["migration"];
    assert_eq!(t.abstained, t.transitions);
    assert_eq!(c.opp_incorrect, 0);
    // No confident false split, but every connection is still fragmented:
    // abstaining does not recover continuity.
    assert_eq!(c.connections_false_split, 0);
    assert_eq!(c.connections_fragmented, c.connections);
    assert_eq!(c.connections_exact, 0);
    // Every migration is observationally ambiguous under the model.
    assert_eq!(c.abstentions_on_ambiguous, c.abstentions);
}

#[test]
fn tuple_reuse_merges_connections_under_tuple_tracking() {
    let strict = counts(STRICT_TUPLE, Some(Scenario::AddressReuse));
    assert!(strict.merged_pairs > 0);
    assert!(strict.connections_false_split > 0);
    let abstain = counts(CONTINUITY_ABSTAIN, Some(Scenario::AddressReuse));
    assert!(abstain.merged_pairs <= strict.merged_pairs);
    assert!(abstain.opp_incorrect < strict.opp_incorrect);
}

#[test]
fn abstaining_lowers_selective_risk_and_costs_coverage() {
    let forced = counts(CONTINUITY_FORCED, None);
    let abstain = counts(CONTINUITY_ABSTAIN, None);
    assert!(value(&abstain, "selective_risk") < value(&forced, "selective_risk") / 2.0);
    assert!(value(&abstain, "decision_coverage") < value(&forced, "decision_coverage"));
    assert!(abstain.merged_pairs < forced.merged_pairs);
    assert!(abstain.incorrect_links < forced.incorrect_links);
    assert!(abstain.connections_false_split < forced.connections_false_split);
    // The price is paid in fragmentation by abstention, which the confident
    // false-split count does not show.
    assert!(abstain.connections_fragmented > abstain.connections_false_split);
}

#[test]
fn abstentions_are_decided_by_score_not_by_the_oracle() {
    let abstain = counts(CONTINUITY_ABSTAIN, None);
    // Abstentions land on observationally ambiguous opportunities...
    assert!(value(&abstain, "abstention_precision") > 0.9);
    // ...but far from all of them: the tracker decides many ambiguous
    // opportunities confidently, so it is not a copy of the oracle.
    let recall = value(&abstain, "abstention_recall");
    assert!((0.3..0.98).contains(&recall), "recall {recall}");
    assert!(abstain.confident_on_ambiguous > 0);
    // The forced method decides every ambiguous opportunity and is wrong on
    // a large share of them.
    let forced = counts(CONTINUITY_FORCED, None);
    assert_eq!(forced.confident_on_ambiguous, forced.opp_ambiguous);
    assert!(value(&forced, "risk_on_ambiguous") > 0.2);
    assert!(value(&forced, "risk_on_determined") < 0.05);
}

#[test]
fn a_forced_guess_on_abstained_opportunities_is_often_wrong() {
    let abstain = counts(CONTINUITY_ABSTAIN, None);
    assert!(abstain.opp_abstained > 0);
    assert!(abstain.abstained_guess_correct < abstain.opp_abstained);
}

#[test]
fn results_are_reproducible() {
    let again = experiment::run_families(&SEEDS, SCALE, &Spec::all(THRESHOLD)).unwrap();
    assert_eq!(rows(), &again[..]);
    let other = experiment::run_families(&[4, 8, 14], SCALE, &Spec::all(THRESHOLD)).unwrap();
    assert_ne!(rows(), &other[..]);
}

#[test]
fn a_higher_threshold_abstains_more() {
    let run = |threshold_per_mille| {
        let specs = [Spec::ContinuityAbstain {
            threshold_per_mille,
        }];
        let rows = experiment::run_families(&SEEDS[..1], SCALE, &specs).unwrap();
        Counts::pooled(rows.iter().map(|r| &r.counts))
    };
    let (low, mid, high) = (run(500), run(800), run(990));
    assert!(low.opp_abstained <= mid.opp_abstained);
    assert!(mid.opp_abstained < high.opp_abstained);
    assert!(high.opp_incorrect <= low.opp_incorrect);
}
