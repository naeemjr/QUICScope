//! The experiment runner: development runs, the held-out evaluation, the
//! exploratory sweeps, and every table and figure derived from them.
//!
//! Everything here is a pure function of the frozen protocol and returns
//! file contents; nothing is written to disk in this module.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde::Serialize;

use crate::error::Error;
use crate::eval::{self, metric, primary_metrics, Counts, Metric, METRICS};
use crate::figures::{percent, Figure, Kind, Panel, Series, Value};
use crate::gen::{self, ControlledParams, Scenario, Trace};
use crate::oracle::{self, Annotation};
use crate::protocol::{self, FamilyEffect, ThresholdRow, Verdict};
use crate::stats::{stream_for, summarize, Summary, BOOTSTRAP_RESAMPLES};
use crate::tracker::{Spec, CONTINUITY_ABSTAIN, CONTINUITY_FORCED, STRICT_TUPLE};

/// Scope label for results pooled over all scenario families.
pub const ALL: &str = "all";

/// One method's counts on one trace.
#[derive(Debug, Clone, PartialEq)]
pub struct Row {
    pub seed: u64,
    pub family: String,
    pub tracker: &'static str,
    pub threshold_per_mille: Option<u16>,
    pub counts: Counts,
}

/// Files produced by an experiment, as (relative path, contents).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Artifacts {
    pub files: Vec<(String, String)>,
    /// A short plain-text account for the terminal.
    pub headline: String,
}

impl Artifacts {
    fn add(&mut self, path: &str, contents: String) {
        self.files.push((path.to_string(), contents));
    }
}

/// Run one method on one trace and score it.
pub fn score_method(
    spec: &Spec,
    trace: &Trace,
    annotations: &[Annotation],
) -> Result<Counts, Error> {
    let mut tracker = spec.build();
    let decisions = eval::run(tracker.as_mut(), trace);
    Ok(eval::score(spec.name(), &trace.events, &decisions, annotations)?.counts)
}

fn rows_for(trace: &Trace, specs: &[Spec]) -> Result<Vec<Row>, Error> {
    // The oracle is given the observations and nothing else.
    let annotations = oracle::annotate(&trace.observations());
    specs
        .iter()
        .map(|spec| {
            Ok(Row {
                seed: trace.seed,
                family: trace.family.clone(),
                tracker: spec.name(),
                threshold_per_mille: spec.threshold_per_mille(),
                counts: score_method(spec, trace, &annotations)?,
            })
        })
        .collect()
}

/// Run `specs` on every scenario family for every seed.
pub fn run_families(seeds: &[u64], scale: u32, specs: &[Spec]) -> Result<Vec<Row>, Error> {
    let mut rows = Vec::new();
    for &seed in seeds {
        for &scenario in Scenario::ALL {
            rows.extend(rows_for(&gen::generate(scenario, seed, scale), specs)?);
        }
    }
    Ok(rows)
}

fn grid_specs() -> Vec<Spec> {
    protocol::THRESHOLD_GRID
        .iter()
        .map(|t| Spec::ContinuityAbstain {
            threshold_per_mille: *t,
        })
        .collect()
}

// --- aggregation -----------------------------------------------------------

/// Pool rows per seed.
fn by_seed<'a>(rows: impl Iterator<Item = &'a Row>) -> BTreeMap<u64, Counts> {
    let mut pooled: BTreeMap<u64, Counts> = BTreeMap::new();
    for row in rows {
        pooled.entry(row.seed).or_default().add(&row.counts);
    }
    pooled
}

fn values(per_seed: &BTreeMap<u64, Counts>, m: &Metric) -> BTreeMap<u64, f64> {
    per_seed
        .iter()
        .filter_map(|(seed, counts)| m.value(counts).map(|v| (*seed, v)))
        .collect()
}

fn summary(per_seed: &BTreeMap<u64, Counts>, m: &Metric, label: &str) -> Option<Summary> {
    let v: Vec<f64> = values(per_seed, m).into_values().collect();
    summarize(&v, stream_for(&format!("{label}/{}", m.key)))
}

/// Per-seed `a - b`, over seeds where the metric is defined for both.
fn paired(
    a: &BTreeMap<u64, Counts>,
    b: &BTreeMap<u64, Counts>,
    m: &Metric,
    label: &str,
) -> Option<Summary> {
    let (va, vb) = (values(a, m), values(b, m));
    let d: Vec<f64> = va
        .iter()
        .filter_map(|(seed, x)| vb.get(seed).map(|y| x - y))
        .collect();
    summarize(&d, stream_for(&format!("paired/{label}/{}", m.key)))
}

/// Summaries for every scope (each family, and all pooled) x tracker x metric.
struct Stats {
    scopes: Vec<String>,
    trackers: Vec<&'static str>,
    per_seed: BTreeMap<(String, String), BTreeMap<u64, Counts>>,
    summaries: BTreeMap<(String, String, String), Option<Summary>>,
}

impl Stats {
    fn of(rows: &[Row], trackers: &[&'static str]) -> Self {
        let mut scopes: Vec<String> = Scenario::ALL
            .iter()
            .map(|s| s.to_string())
            .filter(|s| rows.iter().any(|r| &r.family == s))
            .collect();
        if scopes.is_empty() {
            scopes = rows.iter().map(|r| r.family.clone()).collect();
            scopes.dedup();
        }
        scopes.push(ALL.to_string());

        let mut per_seed = BTreeMap::new();
        let mut summaries = BTreeMap::new();
        for scope in &scopes {
            for &tracker in trackers {
                let pooled = by_seed(
                    rows.iter()
                        .filter(|r| r.tracker == tracker && (scope == ALL || &r.family == scope)),
                );
                for m in METRICS {
                    let label = format!("{scope}/{tracker}");
                    let key = (scope.clone(), tracker.to_string(), m.key.to_string());
                    summaries.insert(key, summary(&pooled, m, &label));
                }
                per_seed.insert((scope.clone(), tracker.to_string()), pooled);
            }
        }
        Stats {
            scopes,
            trackers: trackers.to_vec(),
            per_seed,
            summaries,
        }
    }

    fn get(&self, scope: &str, tracker: &str, key: &str) -> Option<&Summary> {
        self.summaries
            .get(&(scope.to_string(), tracker.to_string(), key.to_string()))
            .and_then(Option::as_ref)
    }

    fn seeds(&self, scope: &str, tracker: &str) -> &BTreeMap<u64, Counts> {
        &self.per_seed[&(scope.to_string(), tracker.to_string())]
    }

    /// Per-seed `forced - abstain` for a metric in a scope.
    fn forced_minus_abstain(&self, scope: &str, key: &str) -> Option<Summary> {
        paired(
            self.seeds(scope, CONTINUITY_FORCED),
            self.seeds(scope, CONTINUITY_ABSTAIN),
            metric(key),
            scope,
        )
    }
}

// --- formatting ------------------------------------------------------------

fn num(value: Option<f64>) -> String {
    value.map(|v| format!("{v:.6}")).unwrap_or_default()
}

fn cell(s: Option<&Summary>) -> String {
    match s {
        Some(s) => format!(
            "{} [{}, {}]",
            percent(s.mean),
            percent(s.ci_low),
            percent(s.ci_high)
        ),
        None => "n/a".to_string(),
    }
}

/// A signed difference in percentage points.
fn points(s: Option<&Summary>) -> String {
    let pp = |v: f64| format!("{:+.2}", v * 100.0);
    match s {
        Some(s) => format!("{} [{}, {}] pp", pp(s.mean), pp(s.ci_low), pp(s.ci_high)),
        None => "n/a".to_string(),
    }
}

fn csv_line(fields: &[String]) -> String {
    let quoted: Vec<String> = fields
        .iter()
        .map(|f| {
            if f.contains([',', '"', '\n']) {
                format!("\"{}\"", f.replace('"', "\"\""))
            } else {
                f.clone()
            }
        })
        .collect();
    quoted.join(",") + "\n"
}

fn summary_fields(s: Option<&Summary>) -> Vec<String> {
    match s {
        Some(s) => vec![
            s.n.to_string(),
            format!("{:.6}", s.mean),
            format!("{:.6}", s.sd),
            format!("{:.6}", s.min),
            format!("{:.6}", s.max),
            format!("{:.6}", s.ci_low),
            format!("{:.6}", s.ci_high),
        ],
        None => vec![
            "0".to_string(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
        ],
    }
}

const SUMMARY_COLUMNS: &str = "n_seeds,mean,sd,min,max,ci95_low,ci95_high";

/// The scalar count fields of [`Counts`], in a fixed order.
fn count_fields(counts: &Counts) -> Vec<(String, u64)> {
    let value = serde_json::to_value(counts).expect("counts serialize");
    let object = value.as_object().expect("counts are an object");
    object
        .iter()
        .filter_map(|(k, v)| v.as_u64().map(|n| (k.clone(), n)))
        .collect()
}

const DENOMINATOR_NOTE: &str = "Each cell is the mean over seeds of the per-seed ratio, with a 95% percentile-bootstrap interval for that mean in brackets.";

fn metric_definitions(metrics: impl Iterator<Item = &'static Metric>) -> String {
    let mut out = String::from("\n| Metric | Numerator | Denominator |\n|---|---|---|\n");
    for m in metrics {
        let _ = writeln!(out, "| {} | {} | {} |", m.label, m.numerator, m.denominator);
    }
    out
}

// --- held-out outputs ------------------------------------------------------

fn per_seed_family_csv(rows: &[Row]) -> String {
    let mut out = String::new();
    for (i, row) in rows.iter().enumerate() {
        let counts = count_fields(&row.counts);
        if i == 0 {
            let mut header = vec![
                "seed".to_string(),
                "family".into(),
                "tracker".into(),
                "threshold_per_mille".into(),
            ];
            header.extend(counts.iter().map(|(k, _)| k.clone()));
            header.extend(METRICS.iter().map(|m| m.key.to_string()));
            out.push_str(&csv_line(&header));
        }
        let mut fields = vec![
            row.seed.to_string(),
            row.family.clone(),
            row.tracker.to_string(),
            row.threshold_per_mille
                .map(|t| t.to_string())
                .unwrap_or_default(),
        ];
        fields.extend(counts.iter().map(|(_, v)| v.to_string()));
        fields.extend(METRICS.iter().map(|m| num(m.value(&row.counts))));
        out.push_str(&csv_line(&fields));
    }
    out
}

fn per_seed_csv(stats: &Stats) -> String {
    let mut header = vec!["seed".to_string(), "tracker".into()];
    for m in primary_metrics() {
        header.extend([
            m.key.to_string(),
            format!("{}_numerator", m.key),
            format!("{}_denominator", m.key),
        ]);
    }
    let mut out = csv_line(&header);
    let seeds: Vec<u64> = stats
        .seeds(ALL, stats.trackers[0])
        .keys()
        .copied()
        .collect();
    for seed in seeds {
        for &tracker in &stats.trackers {
            let counts = &stats.seeds(ALL, tracker)[&seed];
            let mut fields = vec![seed.to_string(), tracker.to_string()];
            for m in primary_metrics() {
                let (n, d) = (m.parts)(counts);
                fields.extend([num(m.value(counts)), n.to_string(), d.to_string()]);
            }
            out.push_str(&csv_line(&fields));
        }
    }
    out
}

fn summary_csv(stats: &Stats) -> String {
    let mut out =
        format!("scope,tracker,metric,level,primary,{SUMMARY_COLUMNS},numerator,denominator\n");
    for scope in &stats.scopes {
        for &tracker in &stats.trackers {
            for m in METRICS {
                let mut fields = vec![
                    scope.clone(),
                    tracker.to_string(),
                    m.key.to_string(),
                    m.level.to_string(),
                    m.primary.to_string(),
                ];
                fields.extend(summary_fields(stats.get(scope, tracker, m.key)));
                fields.extend([m.numerator.to_string(), m.denominator.to_string()]);
                out.push_str(&csv_line(&fields));
            }
        }
    }
    out
}

fn paired_csv(stats: &Stats) -> String {
    let mut out = format!("scope,metric,comparison,{SUMMARY_COLUMNS}\n");
    for scope in &stats.scopes {
        for m in METRICS {
            let d = stats.forced_minus_abstain(scope, m.key);
            let mut fields = vec![
                scope.clone(),
                m.key.to_string(),
                format!("{CONTINUITY_FORCED} minus {CONTINUITY_ABSTAIN}"),
            ];
            fields.extend(summary_fields(d.as_ref()));
            out.push_str(&csv_line(&fields));
        }
    }
    out
}

fn table_primary(stats: &Stats, caption: &str) -> String {
    let mut out = format!("# Primary metrics\n\n{caption}\n\n{DENOMINATOR_NOTE}\n\n");
    let _ = writeln!(
        out,
        "| Metric | {} | {} | {} |",
        STRICT_TUPLE, CONTINUITY_FORCED, CONTINUITY_ABSTAIN
    );
    out.push_str("|---|---|---|---|\n");
    for m in primary_metrics() {
        let cells: Vec<String> = stats
            .trackers
            .iter()
            .map(|t| cell(stats.get(ALL, t, m.key)))
            .collect();
        let _ = writeln!(out, "| {} | {} |", m.label, cells.join(" | "));
    }
    out.push_str(&metric_definitions(primary_metrics()));
    out.push_str("\nAbstention precision and recall are agreement with the synthetic observation-equivalence oracle. They are not real-world ambiguity-detection rates.\n");
    out
}

fn table_levels(stats: &Stats, caption: &str) -> String {
    let mut out = format!("# Table 5. Connection-level, edge-level, decision-level, and event-level metrics\n\n{caption}\n\n{DENOMINATOR_NOTE}\n");
    let levels = [
        (
            "connection",
            "Connection level (unit: one ground-truth connection, or one pair of them)",
        ),
        ("edge", "Edge level (unit: one confident `link` decision)"),
        (
            "decision",
            "Decision level (unit: one association opportunity)",
        ),
        (
            "event",
            "Event level (unit: one observation; secondary diagnostic only)",
        ),
    ];
    for (level, heading) in levels {
        let _ = write!(out, "\n## {heading}\n\n| Metric | {STRICT_TUPLE} | {CONTINUITY_FORCED} | {CONTINUITY_ABSTAIN} |\n|---|---|---|---|\n");
        for m in METRICS.iter().filter(|m| m.level == level) {
            let cells: Vec<String> = stats
                .trackers
                .iter()
                .map(|t| cell(stats.get(ALL, t, m.key)))
                .collect();
            let mark = if m.primary { "" } else { " (secondary)" };
            let _ = writeln!(out, "| {}{} | {} |", m.label, mark, cells.join(" | "));
        }
    }
    out.push_str(&metric_definitions(METRICS.iter()));
    out
}

fn table_by_family(stats: &Stats, caption: &str) -> String {
    let mut out = format!(
        "# Connection-level metrics by scenario family\n\n{caption}\n\n{DENOMINATOR_NOTE}\n"
    );
    for key in [
        "exact_continuity_rate",
        "false_merge_pair_rate",
        "false_split_rate",
        "fragmentation_rate",
        "selective_risk",
        "decision_coverage",
    ] {
        let m = metric(key);
        let _ = write!(out, "\n## {}\n\nNumerator: {}. Denominator: {}.\n\n| Family | {STRICT_TUPLE} | {CONTINUITY_FORCED} | {CONTINUITY_ABSTAIN} |\n|---|---|---|---|\n", m.label, m.numerator, m.denominator);
        for scope in &stats.scopes {
            let cells: Vec<String> = stats
                .trackers
                .iter()
                .map(|t| cell(stats.get(scope, t, key)))
                .collect();
            let _ = writeln!(out, "| {} | {} |", scope, cells.join(" | "));
        }
    }
    out
}

fn table_per_seed(stats: &Stats, caption: &str) -> String {
    let keys = [
        "exact_continuity_rate",
        "false_merge_pair_rate",
        "false_split_rate",
        "incorrect_edge_rate",
        "decision_coverage",
        "selective_risk",
    ];
    let mut out = format!("# Table 6. Held-out results per seed\n\n{caption}\n\nEach cell lists `{STRICT_TUPLE}` / `{CONTINUITY_FORCED}` / `{CONTINUITY_ABSTAIN}`, all scenario families pooled within the seed. Numerators and denominators for every cell are in `heldout/per_seed.csv`.\n\n| Seed |");
    for key in keys {
        let _ = write!(out, " {} |", metric(key).label);
    }
    out.push_str("\n|---|");
    out.push_str(&"---|".repeat(keys.len()));
    out.push('\n');
    let seeds: Vec<u64> = stats
        .seeds(ALL, stats.trackers[0])
        .keys()
        .copied()
        .collect();
    for seed in seeds {
        let _ = write!(out, "| {seed} |");
        for key in keys {
            let cells: Vec<String> = stats
                .trackers
                .iter()
                .map(|t| {
                    metric(key)
                        .value(&stats.seeds(ALL, t)[&seed])
                        .map_or("n/a".to_string(), percent)
                })
                .collect();
            let _ = write!(out, " {} |", cells.join(" / "));
        }
        out.push('\n');
    }
    out
}

fn table_helps(stats: &Stats, caption: &str) -> String {
    let mut out = format!(
        "# Table 7. When abstention helps and when it does not\n\n{caption}\n\n\
Comparison: `{CONTINUITY_ABSTAIN}` against `{CONTINUITY_FORCED}`, which share one evidence computation.\n\n\
* Selective risk: incorrect confident decisions at association opportunities / confident decisions at association opportunities.\n\
* Risk reduction: per-seed (forced minus abstain) selective risk, in percentage points, mean with 95% bootstrap interval. Positive means abstaining lowered risk.\n\
* Continuity cost: per-seed (forced minus abstain) connection-level exact continuity rate. Positive means abstaining left fewer connections exactly tracked.\n\
* Coverage: association opportunities given a confident decision / all association opportunities.\n\
* Reading (pre-declared): **helps** if the risk-reduction interval is above zero, **hurts** if below, otherwise **no measurable effect**.\n\n\
| Family | Forced risk | Abstain risk | Risk reduction | Continuity cost | Abstain coverage | Reading |\n|---|---|---|---|---|---|---|\n"
    );
    for scope in &stats.scopes {
        let reduction = stats.forced_minus_abstain(scope, "selective_risk");
        let cost = stats.forced_minus_abstain(scope, "exact_continuity_rate");
        let effect: FamilyEffect = protocol::family_effect(reduction.as_ref());
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} | {} | {} | {} |",
            scope,
            cell(stats.get(scope, CONTINUITY_FORCED, "selective_risk")),
            cell(stats.get(scope, CONTINUITY_ABSTAIN, "selective_risk")),
            points(reduction.as_ref()),
            points(cost.as_ref()),
            cell(stats.get(scope, CONTINUITY_ABSTAIN, "decision_coverage")),
            effect.as_str(),
        );
    }
    out
}

fn bar_value(s: Option<&Summary>, what: &str) -> Option<Value> {
    s.map(|s| Value {
        y: s.mean,
        low: Some(s.ci_low),
        high: Some(s.ci_high),
        tip: format!(
            "{what}: {} (95% CI {} to {})",
            percent(s.mean),
            percent(s.ci_low),
            percent(s.ci_high)
        ),
    })
}

fn family_bars(stats: &Stats, key: &'static str) -> Panel {
    let m = metric(key);
    let families: Vec<String> = stats.scopes.iter().filter(|s| *s != ALL).cloned().collect();
    let series = stats
        .trackers
        .iter()
        .enumerate()
        .map(|(slot, tracker)| Series {
            name: tracker.to_string(),
            slot,
            values: families
                .iter()
                .map(|f| bar_value(stats.get(f, tracker, key), &format!("{tracker}, {f}")))
                .collect(),
            callouts: Vec::new(),
        })
        .collect();
    Panel {
        heading: m.label.to_string(),
        y_label: format!(
            "share of {}",
            if m.key.contains("pair") {
                "connection pairs"
            } else {
                "eligible connections"
            }
        ),
        kind: Kind::Bars {
            categories: families,
        },
        series,
    }
}

/// Mean over seeds of a metric for each grid threshold.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CurvePoint {
    pub threshold_per_mille: u16,
    pub decision_coverage: Option<Summary>,
    pub selective_risk: Option<Summary>,
    pub exact_continuity_rate: Option<Summary>,
    pub abstention_precision: Option<Summary>,
    pub abstention_recall: Option<Summary>,
}

fn curve(grid_rows: &[Row]) -> Vec<CurvePoint> {
    protocol::THRESHOLD_GRID
        .iter()
        .map(|&t| {
            let pooled = by_seed(
                grid_rows
                    .iter()
                    .filter(|r| r.threshold_per_mille == Some(t)),
            );
            let s = |key| summary(&pooled, metric(key), &format!("curve/{t}"));
            CurvePoint {
                threshold_per_mille: t,
                decision_coverage: s("decision_coverage"),
                selective_risk: s("selective_risk"),
                exact_continuity_rate: s("exact_continuity_rate"),
                abstention_precision: s("abstention_precision"),
                abstention_recall: s("abstention_recall"),
            }
        })
        .collect()
}

fn curve_csv(points: &[CurvePoint]) -> String {
    let mut header = vec!["threshold_per_mille".to_string()];
    for key in [
        "decision_coverage",
        "selective_risk",
        "exact_continuity_rate",
        "abstention_precision",
        "abstention_recall",
    ] {
        header.extend(["mean", "ci95_low", "ci95_high"].map(|s| format!("{key}_{s}")));
    }
    let mut out = csv_line(&header);
    for p in points {
        let mut fields = vec![p.threshold_per_mille.to_string()];
        for s in [
            &p.decision_coverage,
            &p.selective_risk,
            &p.exact_continuity_rate,
            &p.abstention_precision,
            &p.abstention_recall,
        ] {
            fields.extend(match s {
                Some(s) => [s.mean, s.ci_low, s.ci_high].map(|v| format!("{v:.6}")),
                None => [String::new(), String::new(), String::new()],
            });
        }
        out.push_str(&csv_line(&fields));
    }
    out
}

fn figure_risk_coverage(
    points: &[CurvePoint],
    stats: &Stats,
    threshold: u16,
    caption: &str,
) -> Figure {
    let usable: Vec<&CurvePoint> = points
        .iter()
        .filter(|p| p.decision_coverage.is_some() && p.selective_risk.is_some())
        .collect();
    let shown = |t: u16| format!("{:.2}", f64::from(t) / 1000.0);
    let curve = |with_intervals: bool, callouts: Vec<(usize, String)>| Series {
        name: format!("{CONTINUITY_ABSTAIN}, threshold 0.50 to 0.99"),
        slot: 2,
        values: usable
            .iter()
            .map(|p| {
                let (c, r) = (p.decision_coverage.unwrap(), p.selective_risk.unwrap());
                Some(Value {
                    y: r.mean,
                    low: with_intervals.then_some(r.ci_low),
                    high: with_intervals.then_some(r.ci_high),
                    tip: format!(
                        "threshold {}: coverage {}, selective risk {} (95% CI {} to {})",
                        shown(p.threshold_per_mille),
                        percent(c.mean),
                        percent(r.mean),
                        percent(r.ci_low),
                        percent(r.ci_high)
                    ),
                })
            })
            .collect(),
        callouts,
    };
    let coverage: Vec<f64> = usable
        .iter()
        .map(|p| p.decision_coverage.unwrap().mean)
        .collect();

    // Panel 1: all three methods on one scale.
    let mut xs = vec![coverage.clone()];
    let mut series = vec![curve(false, Vec::new())];
    for (slot, tracker) in [(0, STRICT_TUPLE), (1, CONTINUITY_FORCED)] {
        if let (Some(c), Some(r)) = (
            stats.get(ALL, tracker, "decision_coverage"),
            stats.get(ALL, tracker, "selective_risk"),
        ) {
            xs.push(vec![c.mean]);
            series.push(Series {
                name: tracker.to_string(),
                slot,
                values: vec![Some(Value {
                    y: r.mean,
                    low: Some(r.ci_low),
                    high: Some(r.ci_high),
                    tip: format!(
                        "{tracker}: coverage {}, selective risk {}",
                        percent(c.mean),
                        percent(r.mean)
                    ),
                })],
                callouts: Vec::new(),
            });
        }
    }

    // Panel 2: the abstaining method alone, on its own scale, with the
    // loosest, frozen, and tightest thresholds labelled.
    let mut callouts = Vec::new();
    for (i, p) in usable.iter().enumerate() {
        let t = p.threshold_per_mille;
        if t == threshold {
            callouts.push((i, format!("{} (frozen)", shown(t))));
        } else if i == 0 || i + 1 == usable.len() {
            callouts.push((i, shown(t)));
        }
    }
    let x_label = "decision coverage (confident decisions / association opportunities)";
    Figure {
        title: "Figure 3. Decision coverage versus selective risk".into(),
        subtitle: format!("{caption}\nEach point is a mean over held-out seeds, all scenario families pooled. Whiskers: 95% bootstrap interval."),
        panels: vec![
            Panel {
                heading: "All three methods".into(),
                y_label: "selective risk".into(),
                kind: Kind::Scatter {
                    x_label: x_label.into(),
                    xs,
                    connect: Some(0),
                },
                series,
            },
            Panel {
                heading: format!("{CONTINUITY_ABSTAIN} alone, by abstention threshold (own scale)"),
                y_label: "selective risk".into(),
                kind: Kind::Scatter {
                    x_label: x_label.into(),
                    xs: vec![coverage],
                    connect: Some(0),
                },
                series: vec![curve(true, callouts)],
            },
        ],
    }
}

// --- sweeps ----------------------------------------------------------------

pub struct SweepLevel {
    pub label: String,
    pub x: f64,
    pub params: ControlledParams,
}

pub struct Sweep {
    pub key: &'static str,
    pub title: &'static str,
    pub x_label: &'static str,
    pub levels: Vec<SweepLevel>,
}

const SEC: u64 = 1_000_000;

fn seconds_levels(
    ranges: &[(u64, u64)],
    set: impl Fn(&mut ControlledParams, (u64, u64)),
) -> Vec<SweepLevel> {
    ranges
        .iter()
        .enumerate()
        .map(|(i, &(lo, hi))| {
            let mut params = ControlledParams::default();
            set(&mut params, (lo, hi));
            let show = |us: u64| {
                if us.is_multiple_of(SEC) {
                    format!("{}", us / SEC)
                } else {
                    format!("{:.1}", us as f64 / SEC as f64)
                }
            };
            SweepLevel {
                label: format!("{}-{} s", show(lo), show(hi)),
                x: i as f64,
                params,
            }
        })
        .collect()
}

fn per_mille_levels(
    levels: &[u32],
    invert: bool,
    set: impl Fn(&mut ControlledParams, u32),
) -> Vec<SweepLevel> {
    levels
        .iter()
        .map(|&level| {
            let mut params = ControlledParams::default();
            set(&mut params, level);
            let shown = if invert { 1000 - level } else { level };
            SweepLevel {
                label: format!("{}%", shown / 10),
                x: f64::from(shown) / 1000.0,
                params,
            }
        })
        .collect()
}

/// The exploratory sweeps over the controlled family. One knob moves per
/// sweep; the others stay at [`ControlledParams::default`].
pub fn sweeps() -> Vec<Sweep> {
    vec![
        Sweep {
            key: "observation_loss",
            title: "Observation loss",
            x_label: "share of packets the monitor drops",
            levels: per_mille_levels(&[0, 50, 100, 200, 300, 400], false, |p, v| {
                p.loss_per_mille = v
            }),
        },
        Sweep {
            key: "handshake_visibility",
            title: "Handshake visibility",
            x_label: "share of connections whose handshake the monitor sees",
            levels: per_mille_levels(&[1000, 750, 500, 250, 0], true, |p, v| {
                p.hidden_handshake_per_mille = v
            }),
        },
        Sweep {
            key: "tuple_reuse_rate",
            title: "Address/port reuse rate",
            x_label: "share of units that reuse a 4-tuple",
            levels: per_mille_levels(&[0, 100, 250, 500, 750], false, |p, v| {
                p.reuse_per_mille = v
            }),
        },
        Sweep {
            key: "tuple_reuse_gap",
            title: "Tuple-reuse quiet time",
            x_label: "silence before a 4-tuple is reused",
            levels: seconds_levels(
                &[
                    (SEC, 2 * SEC),
                    (2 * SEC, 5 * SEC),
                    (5 * SEC, 15 * SEC),
                    (15 * SEC, 45 * SEC),
                    (45 * SEC, 90 * SEC),
                ],
                |p, r| p.reuse_gap_us = r,
            ),
        },
        Sweep {
            key: "path_change_timing",
            title: "Rebinding/migration timing",
            x_label: "silence before a rebinding or migration",
            levels: seconds_levels(
                &[
                    (SEC / 10, SEC),
                    (SEC, 3 * SEC),
                    (3 * SEC, 10 * SEC),
                    (10 * SEC, 30 * SEC),
                    (30 * SEC, 90 * SEC),
                ],
                |p, r| p.path_change_quiet_us = r,
            ),
        },
    ]
}

/// Metrics reported for every sweep level.
pub const SWEEP_METRICS: &[&str] = &[
    "selective_risk",
    "decision_coverage",
    "exact_continuity_rate",
    "false_merge_pair_rate",
    "false_split_rate",
    "incorrect_edge_rate",
    "opportunity_abstention_rate",
    "ambiguous_opportunity_share",
    "abstention_precision",
    "abstention_recall",
];

struct SweepResult {
    sweep: Sweep,
    /// level index -> tracker -> metric -> summary
    levels: Vec<BTreeMap<(&'static str, &'static str), Option<Summary>>>,
}

fn run_sweeps(threshold: u16) -> Result<Vec<SweepResult>, Error> {
    let specs = Spec::all(threshold);
    let seeds = protocol::sweep_seeds();
    let mut results = Vec::new();
    for sweep in sweeps() {
        let mut levels = Vec::new();
        for level in &sweep.levels {
            let mut rows = Vec::new();
            for &seed in &seeds {
                let trace = gen::generate_controlled(&level.params, seed, protocol::SWEEP_SCALE);
                rows.extend(rows_for(&trace, &specs)?);
            }
            let mut table = BTreeMap::new();
            for spec in &specs {
                let pooled = by_seed(rows.iter().filter(|r| r.tracker == spec.name()));
                for &key in SWEEP_METRICS {
                    let label = format!("sweep/{}/{}/{}", sweep.key, level.label, spec.name());
                    table.insert((spec.name(), key), summary(&pooled, metric(key), &label));
                }
            }
            levels.push(table);
        }
        results.push(SweepResult { sweep, levels });
    }
    Ok(results)
}

fn sweeps_csv(results: &[SweepResult]) -> String {
    let mut out = format!("sweep,level,tracker,metric,{SUMMARY_COLUMNS}\n");
    for result in results {
        for (level, table) in result.sweep.levels.iter().zip(&result.levels) {
            for ((tracker, key), s) in table {
                let mut fields = vec![
                    result.sweep.key.to_string(),
                    level.label.clone(),
                    tracker.to_string(),
                    key.to_string(),
                ];
                fields.extend(summary_fields(s.as_ref()));
                out.push_str(&csv_line(&fields));
            }
        }
    }
    out
}

fn table_sweeps(results: &[SweepResult], caption: &str) -> String {
    let mut out = format!("# Exploratory sweeps\n\n{caption}\n\n**Exploratory.** These runs use the controlled scenario family and the sweep seeds. They are not part of the held-out evaluation and no hypothesis was pre-declared for them. One knob moves per sweep; the others stay at their defaults (loss 0%, 15% of handshakes unseen, 20% tuple-reuse units, reuse after 2-90 s, path change after 2-25 s of silence).\n\n{DENOMINATOR_NOTE}\n");
    for result in results {
        let _ = write!(out, "\n## {}\n\nx: {}.\n\n| Level | Oracle-ambiguous share of opportunities | Forced: selective risk | Abstain: selective risk | Abstain: decision coverage | Abstain: abstention rate at opportunities | Forced: exact continuity | Abstain: exact continuity |\n|---|---|---|---|---|---|---|---|\n", result.sweep.title, result.sweep.x_label);
        for (level, table) in result.sweep.levels.iter().zip(&result.levels) {
            let get = |tracker, key| cell(table.get(&(tracker, key)).and_then(Option::as_ref));
            let _ = writeln!(
                out,
                "| {} | {} | {} | {} | {} | {} | {} | {} |",
                level.label,
                get(CONTINUITY_FORCED, "ambiguous_opportunity_share"),
                get(CONTINUITY_FORCED, "selective_risk"),
                get(CONTINUITY_ABSTAIN, "selective_risk"),
                get(CONTINUITY_ABSTAIN, "decision_coverage"),
                get(CONTINUITY_ABSTAIN, "opportunity_abstention_rate"),
                get(CONTINUITY_FORCED, "exact_continuity_rate"),
                get(CONTINUITY_ABSTAIN, "exact_continuity_rate"),
            );
        }
    }
    out.push_str(&metric_definitions(SWEEP_METRICS.iter().map(|k| metric(k))));
    out
}

fn figure_loss(results: &[SweepResult], caption: &str) -> Option<Figure> {
    let result = results.iter().find(|r| r.sweep.key == "observation_loss")?;
    let x: Vec<f64> = result.sweep.levels.iter().map(|l| l.x).collect();
    let ticks: Vec<String> = result
        .sweep
        .levels
        .iter()
        .map(|l| l.label.clone())
        .collect();
    let line = |name: &str, slot: usize, tracker: &'static str, key: &'static str| Series {
        name: name.to_string(),
        slot,
        values: result
            .levels
            .iter()
            .zip(&result.sweep.levels)
            .map(|(table, level)| {
                bar_value(
                    table.get(&(tracker, key)).and_then(Option::as_ref),
                    &format!("{name}, loss {}", level.label),
                )
            })
            .collect(),
        callouts: Vec::new(),
    };
    let kind = || Kind::Lines {
        x: x.clone(),
        x_ticks: ticks.clone(),
        x_label: result.sweep.x_label.to_string(),
    };
    Some(Figure {
        title: "Figure 4. Abstention and incorrect association edges versus observation loss".into(),
        subtitle: caption.to_string(),
        panels: vec![
            Panel {
                heading: "Abstention rate at association opportunities, with the oracle-ambiguous share for reference".into(),
                y_label: "share of opportunities".into(),
                kind: kind(),
                series: vec![
                    line("continuity-abstain: abstained", 2, CONTINUITY_ABSTAIN, "opportunity_abstention_rate"),
                    line("oracle: observationally ambiguous", 3, CONTINUITY_ABSTAIN, "ambiguous_opportunity_share"),
                ],
            },
            Panel {
                heading: "Incorrect confident association-edge rate".into(),
                y_label: "share of confident edges".into(),
                kind: kind(),
                series: vec![
                    line(STRICT_TUPLE, 0, STRICT_TUPLE, "incorrect_edge_rate"),
                    line(CONTINUITY_FORCED, 1, CONTINUITY_FORCED, "incorrect_edge_rate"),
                    line(CONTINUITY_ABSTAIN, 2, CONTINUITY_ABSTAIN, "incorrect_edge_rate"),
                ],
            },
        ],
    })
}

// --- hypothesis ------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct HypothesisResult {
    pub hypothesis: &'static str,
    pub null_hypothesis: &'static str,
    pub decision_rule: &'static str,
    pub seeds: usize,
    pub forced_selective_risk: Option<Summary>,
    pub abstain_selective_risk: Option<Summary>,
    /// Per-seed forced minus abstain.
    pub risk_reduction: Option<Summary>,
    /// Abstain mean risk divided by forced mean risk.
    pub risk_ratio: Option<f64>,
    pub verdict: Verdict,
    /// Per-seed forced minus abstain, for the costs and the secondary claim.
    pub coverage_cost: Option<Summary>,
    pub exact_continuity_cost: Option<Summary>,
    pub false_merge_pair_reduction: Option<Summary>,
}

pub const HYPOTHESIS: &str = "On held-out seeds, pooled over all scenario families, continuity-abstain has lower selective risk than continuity-forced.";
pub const NULL_HYPOTHESIS: &str = "Abstaining does not lower selective risk: the mean per-seed difference (forced minus abstain) is zero or negative.";
pub const DECISION_RULE: &str = "supported: 95% bootstrap interval of the per-seed difference is above zero and abstain's mean risk is at most half of forced's; weakened: interval above zero but risk not halved; inconclusive: interval includes zero; rejected: interval at or below zero.";

fn hypothesis(stats: &Stats) -> HypothesisResult {
    let forced = stats.get(ALL, CONTINUITY_FORCED, "selective_risk").copied();
    let abstain = stats
        .get(ALL, CONTINUITY_ABSTAIN, "selective_risk")
        .copied();
    let reduction = stats.forced_minus_abstain(ALL, "selective_risk");
    let verdict = match (&reduction, &forced, &abstain) {
        (Some(d), Some(f), Some(a)) => protocol::primary_verdict(d, f.mean, a.mean),
        _ => Verdict::Inconclusive,
    };
    HypothesisResult {
        hypothesis: HYPOTHESIS,
        null_hypothesis: NULL_HYPOTHESIS,
        decision_rule: DECISION_RULE,
        seeds: reduction.map_or(0, |d| d.n),
        risk_ratio: match (&forced, &abstain) {
            (Some(f), Some(a)) if f.mean > 0.0 => Some(a.mean / f.mean),
            _ => None,
        },
        forced_selective_risk: forced,
        abstain_selective_risk: abstain,
        risk_reduction: reduction,
        verdict,
        coverage_cost: stats.forced_minus_abstain(ALL, "decision_coverage"),
        exact_continuity_cost: stats.forced_minus_abstain(ALL, "exact_continuity_rate"),
        false_merge_pair_reduction: stats.forced_minus_abstain(ALL, "false_merge_pair_rate"),
    }
}

#[derive(Debug, Clone, Serialize)]
struct Manifest {
    tool: &'static str,
    version: &'static str,
    protocol_version: &'static str,
    synthetic_only: bool,
    evaluation: &'static str,
    seeds: Vec<u64>,
    sweep_seeds: Vec<u64>,
    scale: u32,
    sweep_scale: u32,
    scenario_families: Vec<String>,
    methods: Vec<&'static str>,
    abstention_threshold_per_mille: u16,
    threshold_grid: Vec<u16>,
    threshold_selection_target_risk: f64,
    bootstrap_resamples: usize,
    primary_metrics: Vec<&'static str>,
    traces: usize,
    files: Vec<String>,
}

fn manifest(
    evaluation: &'static str,
    seeds: Vec<u64>,
    sweep_seeds: Vec<u64>,
    threshold: u16,
    traces: usize,
    artifacts: &Artifacts,
) -> String {
    let manifest = Manifest {
        tool: env!("CARGO_PKG_NAME"),
        version: env!("CARGO_PKG_VERSION"),
        protocol_version: protocol::PROTOCOL_VERSION,
        synthetic_only: true,
        evaluation,
        seeds,
        sweep_seeds,
        scale: protocol::SCALE,
        sweep_scale: protocol::SWEEP_SCALE,
        scenario_families: Scenario::ALL.iter().map(|s| s.to_string()).collect(),
        methods: vec![STRICT_TUPLE, CONTINUITY_FORCED, CONTINUITY_ABSTAIN],
        abstention_threshold_per_mille: threshold,
        threshold_grid: protocol::THRESHOLD_GRID.to_vec(),
        threshold_selection_target_risk: protocol::TARGET_DEV_SELECTIVE_RISK,
        bootstrap_resamples: BOOTSTRAP_RESAMPLES,
        primary_metrics: primary_metrics().map(|m| m.key).collect(),
        traces,
        files: artifacts
            .files
            .iter()
            .map(|(path, _)| path.clone())
            .collect(),
    };
    let mut json = serde_json::to_string_pretty(&manifest).expect("manifest serializes");
    json.push('\n');
    json
}

fn headline(stats: &Stats, title: &str) -> String {
    let mut out = format!("{title}\n\n");
    let _ = writeln!(
        out,
        "{:<46} {:>24} {:>24} {:>24}",
        "primary metric (mean [95% CI] over seeds)",
        STRICT_TUPLE,
        CONTINUITY_FORCED,
        CONTINUITY_ABSTAIN
    );
    for m in primary_metrics() {
        let cells: Vec<String> = stats
            .trackers
            .iter()
            .map(|t| cell(stats.get(ALL, t, m.key)))
            .collect();
        let _ = writeln!(
            out,
            "{:<46} {:>24} {:>24} {:>24}",
            m.label, cells[0], cells[1], cells[2]
        );
    }
    out
}

const TRACKERS: [&str; 3] = [STRICT_TUPLE, CONTINUITY_FORCED, CONTINUITY_ABSTAIN];

/// The held-out evaluation at `threshold`, plus the exploratory sweeps.
/// Used by [`final_evaluation`] with the frozen protocol and by the tests
/// with small inputs.
pub fn evaluation(
    seeds: &[u64],
    scale: u32,
    threshold: u16,
    with_sweeps: bool,
) -> Result<Artifacts, Error> {
    let mut specs = Spec::all(threshold).to_vec();
    let main_count = specs.len();
    specs.extend(grid_specs());
    let all_rows = run_families(seeds, scale, &specs)?;

    // Each trace contributed `specs.len()` rows: the three methods, then
    // the threshold grid.
    let (mut rows, mut grid_rows) = (Vec::new(), Vec::new());
    for (i, row) in all_rows.into_iter().enumerate() {
        if i % specs.len() < main_count {
            rows.push(row);
        } else {
            grid_rows.push(row);
        }
    }

    let stats = Stats::of(&rows, &TRACKERS);
    let curve_points = curve(&grid_rows);
    let result = hypothesis(&stats);
    let caption = format!(
        "Held-out evaluation: {} seeds ({}..={}), {} scenario families, scale {}, abstention threshold {:.2}. Synthetic traces only.",
        seeds.len(),
        seeds.first().copied().unwrap_or(0),
        seeds.last().copied().unwrap_or(0),
        Scenario::ALL.len(),
        scale,
        f64::from(threshold) / 1000.0,
    );

    let mut a = Artifacts::default();
    a.add("heldout/per_seed_family.csv", per_seed_family_csv(&rows));
    a.add("heldout/per_seed.csv", per_seed_csv(&stats));
    a.add("heldout/summary.csv", summary_csv(&stats));
    a.add("heldout/paired_differences.csv", paired_csv(&stats));
    a.add("heldout/risk_coverage.csv", curve_csv(&curve_points));
    let mut json = serde_json::to_string_pretty(&result).expect("result serializes");
    json.push('\n');
    a.add("heldout/hypothesis.json", json);

    a.add(
        "tables/table_primary_metrics.md",
        table_primary(&stats, &caption),
    );
    a.add(
        "tables/table_by_family.md",
        table_by_family(&stats, &caption),
    );
    a.add(
        "tables/table5_metric_levels.md",
        table_levels(&stats, &caption),
    );
    a.add(
        "tables/table6_per_seed.md",
        table_per_seed(&stats, &caption),
    );
    a.add(
        "tables/table7_when_abstention_helps.md",
        table_helps(&stats, &caption),
    );

    let fig1 = Figure {
        title: "Figure 1. Connection-level exact continuity by tracker and scenario family".into(),
        subtitle: format!("{caption}\nBars: mean over seeds. Whiskers: 95% bootstrap interval."),
        panels: vec![family_bars(&stats, "exact_continuity_rate")],
    };
    a.add("figures/fig1_exact_continuity.svg", fig1.to_svg());
    let fig2 = Figure {
        title: "Figure 2. False merge, false split, and fragmentation rates by tracker and scenario family".into(),
        subtitle: format!("{caption}\nBars: mean over seeds. Whiskers: 95% bootstrap interval. An abstention fragments a connection without being a confident false split, so both are shown."),
        panels: vec![
            family_bars(&stats, "false_merge_pair_rate"),
            family_bars(&stats, "false_split_rate"),
            family_bars(&stats, "fragmentation_rate"),
        ],
    };
    a.add("figures/fig2_false_merge_split.svg", fig2.to_svg());
    a.add(
        "figures/fig3_risk_coverage.svg",
        figure_risk_coverage(&curve_points, &stats, threshold, &caption).to_svg(),
    );

    let mut sweep_seeds = Vec::new();
    if with_sweeps {
        sweep_seeds = protocol::sweep_seeds();
        let results = run_sweeps(threshold)?;
        let sweep_caption = format!(
            "Exploratory sweeps: controlled family, {} sweep seeds ({}..={}), scale {}, abstention threshold {:.2}. Synthetic traces only.",
            sweep_seeds.len(),
            sweep_seeds[0],
            sweep_seeds[sweep_seeds.len() - 1],
            protocol::SWEEP_SCALE,
            f64::from(threshold) / 1000.0,
        );
        a.add("sweeps/sweeps.csv", sweeps_csv(&results));
        a.add(
            "tables/table_sweeps.md",
            table_sweeps(&results, &sweep_caption),
        );
        if let Some(figure) = figure_loss(&results, &sweep_caption) {
            a.add("figures/fig4_loss_sweep.svg", figure.to_svg());
        }
    }

    let traces = seeds.len() * Scenario::ALL.len();
    let listing = manifest(
        "held-out",
        seeds.to_vec(),
        sweep_seeds,
        threshold,
        traces,
        &a,
    );
    a.add("manifest.json", listing);

    a.headline = headline(&stats, &caption);
    let _ = write!(
        a.headline,
        "\nprimary hypothesis: {}\nforced minus abstain selective risk: {}\nabstain/forced risk ratio: {}\n",
        result.verdict.as_str(),
        points(result.risk_reduction.as_ref()),
        result.risk_ratio.map_or("n/a".to_string(), |r| format!("{r:.3}")),
    );
    Ok(a)
}

/// The frozen held-out evaluation. Fails if no threshold has been frozen.
pub fn final_evaluation() -> Result<Artifacts, Error> {
    let threshold = protocol::FROZEN_THRESHOLD_PER_MILLE.ok_or(Error::ThresholdNotFrozen)?;
    evaluation(&protocol::heldout_seeds(), protocol::SCALE, threshold, true)
}

/// The development run: the threshold table on development seeds and the
/// threshold the pre-declared rule selects from it.
pub fn development_run(seeds: &[u64], scale: u32) -> Result<(u16, Artifacts), Error> {
    let mut specs = vec![Spec::StrictTuple, Spec::ContinuityForced];
    specs.extend(grid_specs());
    let rows = run_families(seeds, scale, &specs)?;

    let pooled_at = |t: u16| {
        Counts::pooled(
            rows.iter()
                .filter(|r| r.threshold_per_mille == Some(t))
                .map(|r| &r.counts),
        )
    };
    let table: Vec<(ThresholdRow, Counts)> = protocol::THRESHOLD_GRID
        .iter()
        .map(|&t| {
            let counts = pooled_at(t);
            let row = ThresholdRow {
                threshold_per_mille: t,
                pooled_selective_risk: metric("selective_risk").value(&counts),
                pooled_decision_coverage: metric("decision_coverage").value(&counts),
            };
            (row, counts)
        })
        .collect();
    let threshold_rows: Vec<ThresholdRow> = table.iter().map(|(r, _)| *r).collect();
    let selected = protocol::select_threshold(&threshold_rows);

    let mut csv = String::from("threshold_per_mille,incorrect_confident_decisions_at_opportunities,confident_decisions_at_opportunities,opportunities,pooled_selective_risk,pooled_decision_coverage,pooled_exact_continuity_rate,meets_target,selected\n");
    let mut md = format!(
        "# Development threshold selection\n\nDevelopment seeds {}..={} ({} seeds), {} scenario families, scale {}. Synthetic traces only. **No held-out seed is used here.**\n\nRule (declared before this run): the lowest grid threshold whose pooled development selective risk is at most {}. Pooled means summed over all development seeds and families before dividing.\n\n| Threshold | Incorrect / confident decisions at opportunities | Pooled selective risk | Pooled decision coverage | Pooled exact continuity | Meets target | Selected |\n|---|---|---|---|---|---|---|\n",
        seeds.first().copied().unwrap_or(0),
        seeds.last().copied().unwrap_or(0),
        seeds.len(),
        Scenario::ALL.len(),
        scale,
        percent(protocol::TARGET_DEV_SELECTIVE_RISK),
    );
    for (row, counts) in &table {
        let meets = row
            .pooled_selective_risk
            .is_some_and(|r| r <= protocol::TARGET_DEV_SELECTIVE_RISK);
        let chosen = row.threshold_per_mille == selected;
        let exact = metric("exact_continuity_rate").value(counts);
        csv.push_str(&csv_line(&[
            row.threshold_per_mille.to_string(),
            counts.opp_incorrect.to_string(),
            counts.opp_confident.to_string(),
            counts.opportunities.to_string(),
            num(row.pooled_selective_risk),
            num(row.pooled_decision_coverage),
            num(exact),
            meets.to_string(),
            chosen.to_string(),
        ]));
        let _ = writeln!(
            md,
            "| {:.2} | {} / {} | {} | {} | {} | {} | {} |",
            f64::from(row.threshold_per_mille) / 1000.0,
            counts.opp_incorrect,
            counts.opp_confident,
            row.pooled_selective_risk.map_or("n/a".into(), percent),
            row.pooled_decision_coverage.map_or("n/a".into(), percent),
            exact.map_or("n/a".into(), percent),
            if meets { "yes" } else { "no" },
            if chosen { "**selected**" } else { "" },
        );
    }
    for tracker in [STRICT_TUPLE, CONTINUITY_FORCED] {
        let counts = Counts::pooled(
            rows.iter()
                .filter(|r| r.tracker == tracker)
                .map(|r| &r.counts),
        );
        let _ = writeln!(
            md,
            "\nFor reference, `{tracker}` on the same seeds: pooled selective risk {}, decision coverage {}, exact continuity {}.",
            metric("selective_risk").value(&counts).map_or("n/a".into(), percent),
            metric("decision_coverage").value(&counts).map_or("n/a".into(), percent),
            metric("exact_continuity_rate").value(&counts).map_or("n/a".into(), percent),
        );
    }

    let mut a = Artifacts::default();
    a.add("threshold_selection.csv", csv);
    a.add("threshold_selection.md", md.clone());
    let traces = seeds.len() * Scenario::ALL.len();
    let listing = manifest(
        "development",
        seeds.to_vec(),
        Vec::new(),
        selected,
        traces,
        &a,
    );
    a.add("manifest.json", listing);
    a.headline = format!("{md}\nselected threshold: {selected} per mille\n");
    Ok((selected, a))
}

/// A quick look at one seed: counts and primary metrics per family.
pub fn quick_run(
    seed: u64,
    scale: u32,
    specs: &[Spec],
    scenarios: &[Scenario],
) -> Result<Vec<Row>, Error> {
    let mut rows = Vec::new();
    for &scenario in scenarios {
        rows.extend(rows_for(&gen::generate(scenario, seed, scale), specs)?);
    }
    Ok(rows)
}

/// Plain-text table of primary metrics for [`quick_run`] rows, pooled.
pub fn quick_summary(rows: &[Row]) -> String {
    let mut trackers: Vec<&'static str> = Vec::new();
    for row in rows {
        if !trackers.contains(&row.tracker) {
            trackers.push(row.tracker);
        }
    }
    let mut out = String::new();
    let _ = write!(out, "{:<46}", "primary metric (numerator/denominator)");
    for t in &trackers {
        let _ = write!(out, " {t:>26}");
    }
    out.push('\n');
    for m in primary_metrics() {
        let _ = write!(out, "{:<46}", m.label);
        for t in &trackers {
            let counts = Counts::pooled(rows.iter().filter(|r| r.tracker == *t).map(|r| &r.counts));
            let (n, d) = (m.parts)(&counts);
            let shown = m.value(&counts).map_or("n/a".to_string(), percent);
            let _ = write!(out, " {:>26}", format!("{shown} ({n}/{d})"));
        }
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEEDS: [u64; 4] = [1, 2, 3, 4];

    fn small() -> Artifacts {
        evaluation(&SEEDS, 6, 800, false).unwrap()
    }

    fn file<'a>(a: &'a Artifacts, path: &str) -> &'a str {
        &a.files
            .iter()
            .find(|(p, _)| p == path)
            .unwrap_or_else(|| panic!("no file {path}"))
            .1
    }

    #[test]
    fn an_evaluation_produces_every_table_and_figure() {
        let a = small();
        for path in [
            "heldout/per_seed_family.csv",
            "heldout/per_seed.csv",
            "heldout/summary.csv",
            "heldout/paired_differences.csv",
            "heldout/risk_coverage.csv",
            "heldout/hypothesis.json",
            "tables/table_primary_metrics.md",
            "tables/table_by_family.md",
            "tables/table5_metric_levels.md",
            "tables/table6_per_seed.md",
            "tables/table7_when_abstention_helps.md",
            "figures/fig1_exact_continuity.svg",
            "figures/fig2_false_merge_split.svg",
            "figures/fig3_risk_coverage.svg",
            "manifest.json",
        ] {
            assert!(!file(&a, path).is_empty(), "{path}");
        }
        assert!(a.headline.contains("primary hypothesis:"));
    }

    #[test]
    fn csv_files_are_rectangular_and_sized_by_the_design() {
        let a = small();
        let rect = |path: &str| {
            let text = file(&a, path);
            let width = text.lines().next().unwrap().split(',').count();
            // Metric definitions contain commas and are quoted, so only
            // check the files without free text.
            assert!(
                text.lines().all(|l| l.split(',').count() == width),
                "{path}"
            );
            text.lines().count() - 1
        };
        // seeds x families x methods
        assert_eq!(rect("heldout/per_seed_family.csv"), 4 * 10 * 3);
        assert_eq!(rect("heldout/per_seed.csv"), 4 * 3);
        assert_eq!(
            rect("heldout/risk_coverage.csv"),
            protocol::THRESHOLD_GRID.len()
        );
        // (families + all) x metrics
        assert_eq!(rect("heldout/paired_differences.csv"), 11 * METRICS.len());
        let summary = file(&a, "heldout/summary.csv");
        assert_eq!(summary.lines().count() - 1, 11 * 3 * METRICS.len());
    }

    #[test]
    fn every_table_states_its_denominators() {
        let a = small();
        for path in [
            "tables/table_primary_metrics.md",
            "tables/table5_metric_levels.md",
            "tables/table_by_family.md",
        ] {
            let text = file(&a, path);
            assert!(text.contains("Denominator"), "{path}");
            assert!(text.contains("Synthetic traces only"), "{path}");
        }
        let helps = file(&a, "tables/table7_when_abstention_helps.md");
        assert!(helps.contains("confident decisions at association opportunities"));
        assert!(file(&a, "tables/table_primary_metrics.md").contains("not real-world"));
    }

    #[test]
    fn the_abstain_row_matches_the_grid_row_at_the_same_threshold() {
        let specs = [Spec::ContinuityAbstain {
            threshold_per_mille: 800,
        }];
        let direct = run_families(&SEEDS, 6, &specs).unwrap();
        let pooled = Counts::pooled(direct.iter().map(|r| &r.counts));

        let a = small();
        let csv = file(&a, "heldout/per_seed_family.csv");
        let header: Vec<&str> = csv.lines().next().unwrap().split(',').collect();
        let column = |name: &str| header.iter().position(|h| *h == name).unwrap();
        let (opportunities, incorrect) = (column("opportunities"), column("opp_incorrect"));
        let rows: Vec<Vec<&str>> = csv
            .lines()
            .skip(1)
            .filter(|l| l.contains(",continuity-abstain,800,"))
            .map(|l| l.split(',').collect())
            .collect();
        assert_eq!(rows.len(), 40);
        let total = |i: usize| {
            rows.iter()
                .map(|r| r[i].parse::<u64>().unwrap())
                .sum::<u64>()
        };
        assert_eq!(total(opportunities), pooled.opportunities);
        assert_eq!(total(incorrect), pooled.opp_incorrect);
    }

    #[test]
    fn a_zero_threshold_makes_the_two_continuity_methods_identical() {
        let rows = run_families(&SEEDS, 6, &Spec::all(0)).unwrap();
        for pair in rows.chunks(3) {
            assert_eq!(pair[1].tracker, CONTINUITY_FORCED);
            assert_eq!(pair[2].tracker, CONTINUITY_ABSTAIN);
            assert_eq!(
                pair[1].counts, pair[2].counts,
                "{} seed {}",
                pair[1].family, pair[1].seed
            );
        }
    }

    #[test]
    fn evaluations_are_reproducible() {
        assert_eq!(small(), small());
    }

    #[test]
    fn the_manifest_lists_the_protocol_and_the_files() {
        let a = small();
        let manifest: serde_json::Value = serde_json::from_str(file(&a, "manifest.json")).unwrap();
        assert_eq!(manifest["synthetic_only"], true);
        assert_eq!(manifest["abstention_threshold_per_mille"], 800);
        assert_eq!(manifest["seeds"], serde_json::json!([1, 2, 3, 4]));
        assert_eq!(manifest["methods"].as_array().unwrap().len(), 3);
        assert_eq!(manifest["primary_metrics"].as_array().unwrap().len(), 8);
        assert_eq!(manifest["traces"], 40);
        assert_eq!(
            manifest["files"].as_array().unwrap().len(),
            a.files.len() - 1
        );
    }

    #[test]
    fn the_hypothesis_file_records_the_rule_and_a_verdict() {
        let a = small();
        let h: serde_json::Value =
            serde_json::from_str(file(&a, "heldout/hypothesis.json")).unwrap();
        assert_eq!(h["seeds"], 4);
        assert!(h["decision_rule"].as_str().unwrap().contains("supported"));
        let verdict = h["verdict"].as_str().unwrap();
        assert!(["supported", "weakened", "inconclusive", "rejected"].contains(&verdict));
    }

    #[test]
    fn development_selects_a_grid_threshold_by_the_declared_rule() {
        let (selected, a) = development_run(&[1, 2], 6).unwrap();
        assert!(protocol::THRESHOLD_GRID.contains(&selected));
        let csv = file(&a, "threshold_selection.csv");
        assert_eq!(csv.lines().count() - 1, protocol::THRESHOLD_GRID.len());
        assert_eq!(csv.lines().filter(|l| l.ends_with(",true")).count(), 1);
        // Recompute the rule from the published table.
        let rows: Vec<ThresholdRow> = csv
            .lines()
            .skip(1)
            .map(|l| {
                let f: Vec<&str> = l.split(',').collect();
                ThresholdRow {
                    threshold_per_mille: f[0].parse().unwrap(),
                    pooled_selective_risk: f[4].parse().ok(),
                    pooled_decision_coverage: f[5].parse().ok(),
                }
            })
            .collect();
        assert_eq!(protocol::select_threshold(&rows), selected);
        assert!(file(&a, "threshold_selection.md").contains("No held-out seed"));
    }

    #[test]
    fn coverage_never_rises_with_the_threshold() {
        let (_, a) = development_run(&[1, 2, 3], 8).unwrap();
        let coverage: Vec<f64> = file(&a, "threshold_selection.csv")
            .lines()
            .skip(1)
            .map(|l| l.split(',').nth(5).unwrap().parse().unwrap())
            .collect();
        assert!(
            coverage.windows(2).all(|w| w[0] >= w[1] - 1e-9),
            "{coverage:?}"
        );
        assert!(coverage.first() > coverage.last());
    }

    #[test]
    fn sweeps_cover_the_declared_knobs_and_move_one_at_a_time() {
        let all = sweeps();
        let keys: Vec<&str> = all.iter().map(|s| s.key).collect();
        assert_eq!(
            keys,
            [
                "observation_loss",
                "handshake_visibility",
                "tuple_reuse_rate",
                "tuple_reuse_gap",
                "path_change_timing"
            ]
        );
        let base = ControlledParams::default();
        for sweep in &all {
            assert!(sweep.levels.len() >= 5, "{}", sweep.key);
            for level in &sweep.levels {
                let p = level.params;
                let changed = [
                    p.loss_per_mille != base.loss_per_mille,
                    p.hidden_handshake_per_mille != base.hidden_handshake_per_mille,
                    p.reuse_per_mille != base.reuse_per_mille,
                    p.reuse_gap_us != base.reuse_gap_us,
                    p.path_change_quiet_us != base.path_change_quiet_us,
                ];
                assert!(changed.iter().filter(|c| **c).count() <= 1, "{}", sweep.key);
            }
        }
        // Reuse gaps never go below the declared model's minimum.
        let gap = all.iter().find(|s| s.key == "tuple_reuse_gap").unwrap();
        assert!(gap
            .levels
            .iter()
            .all(|l| l.params.reuse_gap_us.0 >= crate::simmodel::MIN_TUPLE_REUSE_GAP_US));
    }

    #[test]
    fn quick_summary_shows_numerators_and_denominators() {
        let rows = quick_run(1, 5, &Spec::all(800), &[Scenario::Migration]).unwrap();
        let text = quick_summary(&rows);
        assert!(text.contains("continuity-abstain"));
        assert!(text.contains('/'));
        assert_eq!(text.lines().count(), 9);
    }

    #[test]
    fn the_final_evaluation_refuses_to_run_without_a_frozen_threshold() {
        if protocol::FROZEN_THRESHOLD_PER_MILLE.is_none() {
            assert_eq!(final_evaluation(), Err(Error::ThresholdNotFrozen));
        }
    }
}
