//! Trace and decision exports.
//!
//! Experiment tables and figures are produced by [`crate::experiment`].
//! This module renders the two things a reader inspects by hand: a trace,
//! with ground truth clearly separated or left out, and one tracker's
//! decisions on a trace.

use serde::Serialize;

use crate::basis::Field;
use crate::eval::Scored;
use crate::gen::Trace;
use crate::model::Observation;
use crate::oracle::Annotation;
use crate::tracker::{Decision, Guess};

fn csv_field(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

fn csv_row(fields: &[String]) -> String {
    let quoted: Vec<String> = fields.iter().map(|f| csv_field(f)).collect();
    quoted.join(",") + "\n"
}

fn optional<T: ToString>(value: Option<T>) -> String {
    value.map(|v| v.to_string()).unwrap_or_default()
}

fn to_json<T: Serialize>(value: &T) -> String {
    let mut json = serde_json::to_string_pretty(value).expect("export types always serialize");
    json.push('\n');
    json
}

/// Columns holding ground truth. Prefixed so they cannot be mistaken for
/// anything a tracker sees.
const TRUTH_COLUMNS: &[&str] = &[
    "truth_connection",
    "truth_segment",
    "truth_cause",
    "truth_wire_time_us",
];

const OBSERVED_COLUMNS: &[&str] = &[
    "seq",
    "timestamp_us",
    "src_addr",
    "src_port",
    "dst_addr",
    "dst_port",
    "direction",
    "header",
    "packet_type",
    "version",
    "size",
    "ttl",
    "dcid",
    "scid",
    "capture_gap",
    "truncated",
    "lag_us",
];

/// Render a trace as CSV. With `with_truth` false, only what a passive
/// observer could record is written.
pub fn trace_csv(trace: &Trace, with_truth: bool) -> String {
    let mut columns: Vec<String> = OBSERVED_COLUMNS.iter().map(|s| s.to_string()).collect();
    if with_truth {
        columns.extend(TRUTH_COLUMNS.iter().map(|s| s.to_string()));
    }
    let mut out = csv_row(&columns);
    for event in &trace.events {
        let o = &event.observed;
        let mut fields = vec![
            event.seq.to_string(),
            o.timestamp_us.to_string(),
            o.src.addr.to_string(),
            o.src.port.to_string(),
            o.dst.addr.to_string(),
            o.dst.port.to_string(),
            o.transport.direction.to_string(),
            o.transport.header.to_string(),
            o.transport.packet_type.to_string(),
            optional(o.transport.version),
            o.transport.size.to_string(),
            o.transport.ttl.to_string(),
            optional(o.dcid),
            optional(o.scid),
            o.quality.capture_gap.to_string(),
            o.quality.truncated.to_string(),
            o.quality.lag_us.to_string(),
        ];
        if with_truth {
            fields.extend([
                event.truth.connection.to_string(),
                event.truth.segment.to_string(),
                event.truth.cause.to_string(),
                event.truth.wire_time_us.to_string(),
            ]);
        }
        out.push_str(&csv_row(&fields));
    }
    out
}

/// Render a trace as JSON. With `with_truth` false, each record is only the
/// observation: the hidden half is left out entirely.
pub fn trace_json(trace: &Trace, with_truth: bool) -> String {
    if with_truth {
        return to_json(trace);
    }
    #[derive(Serialize)]
    struct ObserverView<'a> {
        seed: u64,
        scale: u32,
        observations: Vec<&'a Observation>,
    }
    to_json(&ObserverView {
        seed: trace.seed,
        scale: trace.scale,
        observations: trace.events.iter().map(|e| &e.observed).collect(),
    })
}

/// One row per event: the decision, how it scored, and the oracle's label.
/// For studying individual decisions; includes ground truth.
pub fn decisions_csv(
    trace: &Trace,
    decisions: &[Decision],
    scored: &Scored,
    annotations: &[Annotation],
) -> String {
    let mut out = csv_row(
        &[
            "seq",
            "timestamp_us",
            "client",
            "server",
            "direction",
            "header",
            "dcid",
            "verdict",
            "track",
            "evidence",
            "confidence_per_mille",
            "guess",
            "basis",
            "outcome",
            "opportunity",
            "oracle_label",
            "oracle_hypotheses",
            "truth_connection",
            "truth_segment",
            "truth_cause",
        ]
        .map(String::from),
    );
    let rows = trace
        .events
        .iter()
        .zip(decisions)
        .zip(&scored.outcomes)
        .zip(annotations);
    for (((event, decision), outcome), annotation) in rows {
        let o = &event.observed;
        let guess = match decision.guess {
            Some(Guess::Link(track)) => format!("link:{}", track.0),
            Some(Guess::New) => "new".to_string(),
            None => String::new(),
        };
        let basis: Vec<&str> = decision.basis.iter().map(Field::as_str).collect();
        out.push_str(&csv_row(&[
            event.seq.to_string(),
            o.timestamp_us.to_string(),
            o.client().to_string(),
            o.server().to_string(),
            o.transport.direction.to_string(),
            o.transport.header.to_string(),
            optional(o.dcid),
            decision.verdict.to_string(),
            decision.track.0.to_string(),
            decision.reason.to_string(),
            decision.confidence.to_string(),
            guess,
            basis.join("+"),
            outcome.to_string(),
            annotation.opportunity.to_string(),
            annotation.label.to_string(),
            annotation.hypotheses.to_string(),
            event.truth.connection.to_string(),
            event.truth.segment.to_string(),
            event.truth.cause.to_string(),
        ]));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gen::{generate, Scenario};
    use crate::tracker::Spec;
    use crate::{eval, oracle};

    #[test]
    fn csv_fields_are_quoted_only_when_needed() {
        assert_eq!(csv_field("plain"), "plain");
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
    }

    #[test]
    fn trace_csv_separates_truth_from_observation() {
        let trace = generate(Scenario::NatRebinding, 1, 3);
        let full = trace_csv(&trace, true);
        let observed = trace_csv(&trace, false);
        assert_eq!(full.lines().count(), trace.events.len() + 1);
        assert_eq!(observed.lines().count(), trace.events.len() + 1);

        let header = full.lines().next().unwrap();
        assert!(header.ends_with("truth_connection,truth_segment,truth_cause,truth_wire_time_us"));
        assert!(!observed.contains("truth"));
        assert!(!observed.contains("nat-rebind"));
        assert_eq!(
            observed.lines().next().unwrap().split(',').count(),
            OBSERVED_COLUMNS.len()
        );
    }

    #[test]
    fn observer_view_json_has_no_truth_and_no_scenario_name() {
        let trace = generate(Scenario::Migration, 1, 3);
        let full: serde_json::Value = serde_json::from_str(&trace_json(&trace, true)).unwrap();
        assert!(full["events"][0]["truth"]["connection"].is_number());
        assert_eq!(full["family"], "migration");

        let view = trace_json(&trace, false);
        for hidden in [
            "truth",
            "\"connection\"",
            "wire_time",
            "cause",
            "segment",
            "migration",
            "family",
        ] {
            assert!(!view.contains(hidden), "observer view contains {hidden}");
        }
        let view: serde_json::Value = serde_json::from_str(&view).unwrap();
        assert_eq!(
            view["observations"].as_array().unwrap().len(),
            trace.events.len()
        );
    }

    #[test]
    fn decisions_csv_has_a_row_per_event_with_outcome_and_oracle_label() {
        let trace = generate(Scenario::Migration, 1, 3);
        let spec = Spec::ContinuityAbstain {
            threshold_per_mille: 800,
        };
        let mut tracker = spec.build();
        let decisions = eval::run(tracker.as_mut(), &trace);
        let annotations = oracle::annotate(&trace.observations());
        let scored = eval::score(spec.name(), &trace.events, &decisions, &annotations).unwrap();
        let csv = decisions_csv(&trace, &decisions, &scored, &annotations);

        assert_eq!(csv.lines().count(), trace.events.len() + 1);
        let width = csv.lines().next().unwrap().split(',').count();
        assert!(csv.lines().all(|l| l.split(',').count() == width));
        assert!(csv.contains(",abstained,true,ambiguous,"));
        assert!(csv.contains(",correct-new,true,determined-new,1,"));
    }
}
