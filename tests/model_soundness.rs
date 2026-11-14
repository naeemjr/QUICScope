//! The declared simulator model must over-approximate the generator, and
//! the fast oracle must agree with exhaustive enumeration.
//!
//! Three properties, on generated traces from every scenario family and the
//! controlled family:
//!
//! 1. **Forced links are sound.** Observations the oracle groups into one
//!    forced component always belong to one ground-truth connection.
//! 2. **Determined labels are sound.** "Determined new" is never given to a
//!    connection the monitor had already observed, and a forced link is
//!    never given to a connection's first observation.
//! 3. **The fast oracle matches the definition, and the definition admits
//!    the truth.** On thinned traces short enough to enumerate every
//!    history, the fast label equals the exhaustive one for every prefix,
//!    and the true history is among the consistent ones.
//!
//! Ground truth is used here only to check the oracle. The oracle itself is
//! never given it.

use std::collections::{BTreeMap, HashMap, HashSet};

use quicscope::gen::{self, ControlledParams, Scenario, Trace};
use quicscope::model::Event;
use quicscope::oracle::{self, exhaustive, Label};

/// Development-range seeds. Held-out seeds are never used in tests.
const SEEDS: [u64; 3] = [2, 9, 17];
const SCALE: u32 = 14;

fn traces() -> Vec<Trace> {
    let mut traces = Vec::new();
    for seed in SEEDS {
        for &scenario in Scenario::ALL {
            traces.push(gen::generate(scenario, seed, SCALE));
        }
        let lossy = ControlledParams {
            loss_per_mille: 300,
            hidden_handshake_per_mille: 500,
            reuse_per_mille: 400,
            reuse_gap_us: (1_000_000, 3_000_000),
            path_change_quiet_us: (100_000, 2_000_000),
        };
        traces.push(gen::generate_controlled(&lossy, seed, SCALE));
        traces.push(gen::generate_controlled(
            &ControlledParams::default(),
            seed,
            SCALE,
        ));
    }
    traces
}

#[test]
fn forced_components_never_join_two_connections() {
    for trace in traces() {
        let components = oracle::forced_components(&trace.observations());
        let mut owner: HashMap<usize, u32> = HashMap::new();
        for (event, component) in trace.events.iter().zip(components) {
            let connection = event.truth.connection;
            let first = *owner.entry(component).or_insert(connection);
            assert_eq!(
                first, connection,
                "{} seed {}: event {} forced into another connection's component",
                trace.family, trace.seed, event.seq
            );
        }
    }
}

#[test]
fn determined_labels_never_contradict_the_truth() {
    let mut determined_new = 0;
    let mut forced = 0;
    for trace in traces() {
        let annotations = oracle::annotate(&trace.observations());
        let mut seen: HashSet<u32> = HashSet::new();
        for (event, annotation) in trace.events.iter().zip(annotations) {
            let known = seen.contains(&event.truth.connection);
            let context = format!("{} seed {} event {}", trace.family, trace.seed, event.seq);
            match annotation.label {
                Label::DeterminedNew => {
                    determined_new += 1;
                    assert!(!known, "{context}: determined-new, but already observed");
                }
                Label::DeterminedLink | Label::Routine => {
                    forced += 1;
                    assert!(known, "{context}: forced link on a first observation");
                }
                Label::Ambiguous => assert!(annotation.hypotheses >= 2, "{context}"),
            }
            assert_eq!(annotation.opportunity, annotation.label != Label::Routine);
            seen.insert(event.truth.connection);
        }
    }
    assert!(determined_new > 100 && forced > 1000);
}

/// The assignment of `events` to connections in the enumerator's own
/// encoding: blocks numbered by first appearance.
fn truth_encoding(events: &[Event]) -> (Vec<u8>, u8) {
    let mut block: BTreeMap<u32, u8> = BTreeMap::new();
    let mut assignment = Vec::new();
    let mut last_is_new = false;
    for event in events {
        let next = block.len() as u8;
        let entry = block.entry(event.truth.connection);
        last_is_new = matches!(entry, std::collections::btree_map::Entry::Vacant(_));
        assignment.push(*entry.or_insert(next));
    }
    let last = assignment.pop().expect("non-empty");
    (assignment, if last_is_new { exhaustive::NEW } else { last })
}

/// Take up to nine events from `trace`, starting at `offset`, every
/// `stride`-th one. Dropping events is something the model allows (M8), so
/// a thinned trace is still a valid observation sequence.
fn thin(trace: &Trace, offset: usize, stride: usize) -> Vec<Event> {
    trace
        .events
        .iter()
        .skip(offset)
        .step_by(stride)
        .take(exhaustive::MAX_OBSERVATIONS - 1)
        .copied()
        .collect()
}

#[test]
fn the_fast_oracle_matches_exhaustive_enumeration_which_admits_the_truth() {
    let mut checked = 0;
    let mut by_label: BTreeMap<&'static str, u32> = BTreeMap::new();
    for trace in traces() {
        let n = trace.events.len();
        for (offset, stride) in [
            (0, 1),
            (n / 3, 1),
            (n / 2, 2),
            (0, 5),
            (7, 13),
            (3, 37),
            (11, 71),
        ] {
            let sample = thin(&trace, offset, stride);
            for end in 1..=sample.len() {
                let prefix = &sample[..end];
                let observations: Vec<_> = prefix.iter().map(|e| e.observed).collect();
                let context = format!(
                    "{} seed {} offset {offset} stride {stride} prefix {end}",
                    trace.family, trace.seed
                );

                let fast = *oracle::annotate(&observations).last().unwrap();
                let slow = exhaustive::enumerate(&observations).expect("within the bound");

                // The model admits the true history.
                let (past, placement) = truth_encoding(prefix);
                let admitted = slow.placements.get(&past);
                assert!(
                    admitted.is_some_and(|p| p.contains(&placement)),
                    "{context}: the true history is not consistent with the model"
                );

                // The fast label is the definition's label.
                assert_eq!(fast.is_ambiguous(), slow.ambiguous(), "{context}");
                let expected = match fast.label {
                    Label::Routine => Label::DeterminedLink,
                    other => other,
                };
                assert_eq!(expected, slow.label(), "{context}");

                *by_label.entry(fast.label.as_str()).or_default() += 1;
                checked += 1;
            }
        }
    }
    // Make sure the comparison was not vacuous.
    assert!(checked > 2000, "only {checked} prefixes checked");
    for label in ["routine", "determined-link", "determined-new", "ambiguous"] {
        assert!(
            by_label.get(label).copied().unwrap_or(0) > 20,
            "{by_label:?}"
        );
    }
}

#[test]
fn labels_are_a_function_of_the_observations_alone() {
    // Two traces with identical observations and different ground truth
    // must get identical labels: the oracle has no access to truth.
    let trace = gen::generate(Scenario::Ambiguous, 5, SCALE);
    let mut relabelled = trace.clone();
    for event in &mut relabelled.events {
        event.truth.connection = 7;
        event.truth.segment = 0;
    }
    assert_eq!(trace.observations(), relabelled.observations());
    assert_eq!(
        oracle::annotate(&trace.observations()),
        oracle::annotate(&relabelled.observations())
    );
}
