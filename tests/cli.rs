//! End-to-end tests of the `quicscope` binary.
//!
//! The protocol runs (`dev`, `final`) are exercised with small inputs by
//! the unit tests of `experiment`; here they are only checked for their
//! guard rails, because a full run is too slow for a debug-build test.

use std::process::{Command, Output};

use serde_json::Value;

fn quicscope(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_quicscope"))
        .args(args)
        .output()
        .expect("spawn quicscope")
}

fn stdout(args: &[&str]) -> String {
    let output = quicscope(args);
    assert!(
        output.status.success(),
        "{args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn quick_run_labels_itself_synthetic_and_shows_denominators() {
    let text = stdout(&["run", "--scale", "6", "--seed", "4"]);
    assert!(text.contains("SYNTHETIC TRACES ONLY"));
    assert!(text.contains("not a protocol run"));
    for name in ["strict-tuple", "continuity-forced", "continuity-abstain"] {
        assert!(text.contains(name), "{text}");
    }
    assert!(text.contains("Selective risk"));
    assert!(text.contains("Abstention precision vs the synthetic oracle"));
    // Every value is followed by (numerator/denominator).
    let risk_line = text
        .lines()
        .find(|l| l.starts_with("Selective risk"))
        .unwrap();
    assert_eq!(risk_line.matches('/').count(), 3, "{risk_line}");
}

#[test]
fn quick_run_filters_and_threshold() {
    let text = stdout(&[
        "run",
        "--scale",
        "6",
        "--scenario",
        "migration",
        "--tracker",
        "continuity-abstain",
        "--threshold",
        "0",
    ]);
    assert!(text.contains("1 families"));
    assert!(text.contains("threshold 0.00"));
    assert!(!text.contains("strict-tuple"));
    // With a zero threshold the abstaining method never abstains.
    let coverage = text
        .lines()
        .find(|l| l.starts_with("Decision coverage"))
        .unwrap();
    assert!(coverage.contains("100%"), "{coverage}");
}

#[test]
fn same_seed_gives_identical_output() {
    let args = ["run", "--scale", "6", "--seed", "7"];
    assert_eq!(stdout(&args), stdout(&args));
    assert_ne!(
        stdout(&args),
        stdout(&["run", "--scale", "6", "--seed", "8"])
    );
}

#[test]
fn generate_prints_a_trace_with_ground_truth_clearly_separated() {
    let args = ["generate", "--scenario", "nat-rebinding", "--scale", "3"];
    let trace: Value = serde_json::from_str(&stdout(&args)).unwrap();
    assert_eq!(trace["family"], "nat-rebinding");
    let event = &trace["events"][0];
    assert!(event["observed"]["timestamp_us"].is_number());
    assert!(event["observed"]["quality"]["capture_gap"].is_boolean());
    assert!(event["truth"]["connection"].is_number());
    assert!(event["observed"].get("truth").is_none());
    assert!(event["observed"].get("connection").is_none());
}

#[test]
fn observer_view_contains_no_ground_truth() {
    let base = ["generate", "--scenario", "migration", "--scale", "3"];
    for format in ["json", "csv"] {
        let mut args = base.to_vec();
        args.extend(["--format", format, "--observer-view"]);
        let text = stdout(&args);
        for hidden in ["truth", "wire_time", "cause", "segment", "migration"] {
            assert!(!text.contains(hidden), "{format}: contains {hidden}");
        }
        assert!(text.contains("timestamp_us"), "{format}");
    }
    let mut args = base.to_vec();
    args.extend(["--format", "csv"]);
    let with_truth = stdout(&args);
    assert!(with_truth
        .lines()
        .next()
        .unwrap()
        .ends_with("truth_connection,truth_segment,truth_cause,truth_wire_time_us"));
}

#[test]
fn generated_addresses_are_all_from_documentation_ranges() {
    for scenario in [
        "ordinary",
        "overlapping",
        "ambiguous",
        "partial-observation",
    ] {
        let csv = stdout(&["generate", "--scenario", scenario, "--format", "csv"]);
        for line in csv.lines().skip(1) {
            let fields: Vec<&str> = line.split(',').collect();
            for addr in [fields[2], fields[4]] {
                let documentation = addr.starts_with("192.0.2.")
                    || addr.starts_with("198.51.100.")
                    || addr.starts_with("203.0.113.");
                assert!(documentation, "{scenario}: {addr}");
            }
        }
    }
}

#[test]
fn inspect_lists_each_decision_with_its_score_and_oracle_label() {
    let csv = stdout(&[
        "inspect",
        "--scenario",
        "migration",
        "--tracker",
        "continuity-abstain",
        "--scale",
        "3",
        "--threshold",
        "800",
    ]);
    let header = csv.lines().next().unwrap();
    assert!(header.starts_with("seq,timestamp_us,client,server,"));
    assert!(header.contains("verdict,track,evidence,confidence_per_mille,guess,basis,outcome,opportunity,oracle_label,oracle_hypotheses,"));
    assert!(csv.contains(",uncertain,"));
    assert!(csv.contains(",abstained,true,ambiguous,"));
}

#[test]
fn list_names_families_methods_and_metric_denominators() {
    let text = stdout(&["list"]);
    for name in [
        "ordinary",
        "nat-rebinding",
        "migration",
        "path-change",
        "address-reuse",
        "packet-loss",
        "partial-observation",
        "delayed-observation",
        "overlapping",
        "ambiguous",
        "strict-tuple",
        "continuity-forced",
        "continuity-abstain",
        "Selective risk",
        "Decision coverage",
    ] {
        assert!(text.contains(name), "{name}");
    }
    assert!(text.contains("/ all association opportunities"));
}

#[test]
fn protocol_prints_the_frozen_seed_sets() {
    let text = stdout(&["protocol"]);
    assert!(text.contains("development seeds:       1..=20 (20 seeds)"));
    assert!(text.contains("held-out seeds:          1001..=1040 (40 seeds)"));
    assert!(text.contains("sweep seeds:             2001..=2010 (10 seeds)"));
    assert!(text.contains("selection rule:"));
    assert!(text.contains("frozen threshold:"));
}

#[test]
fn preliminary_tracker_names_are_rejected_with_guidance() {
    for (old, new) in [
        ("abstain", "continuity-abstain"),
        ("continuity", "continuity-forced"),
    ] {
        let output = quicscope(&["run", "--scale", "3", "--tracker", old]);
        assert_eq!(output.status.code(), Some(1));
        let message = String::from_utf8_lossy(&output.stderr).to_string();
        assert!(message.contains("preliminary version"), "{message}");
        assert!(message.contains(new), "{message}");
    }
}

#[test]
fn unknown_names_and_missing_arguments_are_errors() {
    let tracker = quicscope(&["run", "--tracker", "psychic"]);
    assert_eq!(tracker.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&tracker.stderr).contains("unknown tracker"));

    let scenario = quicscope(&["run", "--scenario", "nope"]);
    assert!(!scenario.status.success());
    assert!(String::from_utf8_lossy(&scenario.stderr).contains("expected one of"));

    for command in ["generate", "final", "dev", "inspect"] {
        assert!(!quicscope(&[command]).status.success(), "{command}");
    }
}
