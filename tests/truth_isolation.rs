//! Trackers must not be able to see ground truth.
//!
//! The interface already guarantees it by type: `Tracker::observe` takes an
//! `&Observation`, and `Observation` has no truth in it. These tests check
//! the same thing behaviourally, so that a future change to the interface
//! cannot quietly break it.

use quicscope::eval;
use quicscope::gen::{self, ControlledParams, Scenario, Trace};
use quicscope::model::Cause;
use quicscope::tracker::{Decision, Spec};

const THRESHOLDS: [u16; 3] = [0, 800, 990];

fn all_specs() -> Vec<Spec> {
    let mut specs = vec![Spec::StrictTuple, Spec::ContinuityForced];
    specs.extend(THRESHOLDS.map(|t| Spec::ContinuityAbstain {
        threshold_per_mille: t,
    }));
    specs
}

fn decisions(spec: &Spec, trace: &Trace) -> Vec<Decision> {
    eval::run(spec.build().as_mut(), trace)
}

fn traces() -> Vec<Trace> {
    let mut traces: Vec<Trace> = Scenario::ALL
        .iter()
        .map(|s| gen::generate(*s, 6, 12))
        .collect();
    traces.push(gen::generate_controlled(
        &ControlledParams::default(),
        6,
        12,
    ));
    traces
}

#[test]
fn relabelling_hidden_truth_changes_no_decision() {
    for trace in traces() {
        // Give every event a different, wrong connection identity.
        let mut relabelled = trace.clone();
        for event in &mut relabelled.events {
            event.truth.connection = 9_999 - event.truth.connection;
        }
        for spec in all_specs() {
            assert_eq!(
                decisions(&spec, &trace),
                decisions(&spec, &relabelled),
                "{} on {}",
                spec.name(),
                trace.family
            );
        }
    }
}

#[test]
fn editing_every_truth_field_changes_no_decision() {
    for trace in traces() {
        let mut edited = trace.clone();
        for (i, event) in edited.events.iter_mut().enumerate() {
            event.truth.connection = (i % 3) as u32;
            event.truth.segment = (i % 5) as u16;
            event.truth.cause = Cause::ALL[i % Cause::ALL.len()];
            event.truth.wire_time_us = 0;
        }
        for spec in all_specs() {
            assert_eq!(
                decisions(&spec, &trace),
                decisions(&spec, &edited),
                "{} on {}",
                spec.name(),
                trace.family
            );
        }
    }
}

#[test]
fn the_scenario_label_is_not_an_input() {
    // Same observations filed under another family name.
    let trace = gen::generate(Scenario::Migration, 6, 12);
    let mut renamed = trace.clone();
    renamed.family = "ordinary".to_string();
    for spec in all_specs() {
        assert_eq!(decisions(&spec, &trace), decisions(&spec, &renamed));
    }
}

#[test]
fn decisions_do_change_when_observations_change() {
    // Guard against a vacuous pass above: the trackers are not constant.
    let trace = gen::generate(Scenario::NatRebinding, 6, 12);
    let mut stripped = trace.clone();
    for event in &mut stripped.events {
        event.observed.dcid = None;
        event.observed.scid = None;
    }
    for spec in [
        Spec::ContinuityForced,
        Spec::ContinuityAbstain {
            threshold_per_mille: 800,
        },
    ] {
        assert_ne!(decisions(&spec, &trace), decisions(&spec, &stripped));
    }
    // The tuple-only baseline never reads connection IDs.
    assert_eq!(
        decisions(&Spec::StrictTuple, &trace),
        decisions(&Spec::StrictTuple, &stripped)
    );
}

#[test]
fn scoring_does_change_when_truth_changes() {
    // The other half of the separation: truth matters to the scorer.
    let trace = gen::generate(Scenario::Ordinary, 6, 12);
    let spec = Spec::ContinuityForced;
    let made = decisions(&spec, &trace);
    let annotations = quicscope::oracle::annotate(&trace.observations());
    let honest = eval::score(spec.name(), &trace.events, &made, &annotations).unwrap();

    let mut merged = trace.clone();
    for event in &mut merged.events {
        event.truth.connection = 0;
    }
    let wrong = eval::score(spec.name(), &merged.events, &made, &annotations).unwrap();
    assert_ne!(honest.counts, wrong.counts);
    assert_eq!(wrong.counts.connections, 1);
}
