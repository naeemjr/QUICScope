//! Scoring: compare a tracker's decisions with ground truth and with the
//! oracle's labels. This module is the only one that reads [`Truth`].
//!
//! Definitions used throughout (see `docs/METRICS.md`):
//!
//! * A decision is **confident** if it is `link` or `new`.
//! * A `link` asserts an **association edge** between the observation and
//!   its *predecessor in the track*: the latest earlier observation of that
//!   track on the same 4-tuple, or failing that the latest earlier
//!   observation of the track. The edge is incorrect if the two belong to
//!   different ground-truth connections.
//! * A `new` is incorrect if the connection had been observed before.
//! * An **association opportunity** is an observation the oracle marks as
//!   starting a run (nothing on its 4-tuple within the declared minimum
//!   reuse gap). Decision-level metrics are taken over opportunities.
//!
//! [`Truth`]: crate::model::Truth

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use serde::Serialize;

use crate::basis::Field;
use crate::error::Error;
use crate::gen::Trace;
use crate::model::{labelled_enum, Cause, Endpoint, Event, FlowKey};
use crate::oracle::{Annotation, Label};
use crate::tracker::{Decision, Guess, TrackId, Tracker, Verdict};

/// Feed a trace to a tracker. The tracker receives only the observed half
/// of each event.
pub fn run(tracker: &mut dyn Tracker, trace: &Trace) -> Vec<Decision> {
    trace
        .events
        .iter()
        .map(|event| tracker.observe(&event.observed))
        .collect()
}

labelled_enum! {
    /// How one decision compares with ground truth.
    pub enum Outcome {
        CorrectLink => "correct-link",
        /// The association edge joins two different connections.
        IncorrectLink => "incorrect-link",
        CorrectNew => "correct-new",
        /// Declared new, but the connection had been observed before.
        IncorrectNew => "incorrect-new",
        Abstained => "abstained",
    }
}

/// Outcomes at the first observed event of each ground-truth path segment.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct TransitionCounts {
    pub transitions: u64,
    pub correct: u64,
    pub incorrect_new: u64,
    pub incorrect_link: u64,
    pub abstained: u64,
}

/// Additive counts. Sum them across traces to pool.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Counts {
    // --- event level: every observation ---------------------------------
    pub observations: u64,
    pub links: u64,
    pub news: u64,
    pub abstentions: u64,
    pub correct_links: u64,
    /// Incorrect confident association edges.
    pub incorrect_links: u64,
    pub correct_news: u64,
    pub incorrect_news: u64,

    // --- decision level: association opportunities only -----------------
    pub opportunities: u64,
    pub opp_confident: u64,
    pub opp_incorrect: u64,
    pub opp_abstained: u64,
    /// Opportunities by oracle label.
    pub opp_ambiguous: u64,
    pub opp_determined_new: u64,
    pub opp_determined_link: u64,
    /// Abstentions (anywhere) on events the oracle labels ambiguous.
    pub abstentions_on_ambiguous: u64,
    pub confident_on_ambiguous: u64,
    pub incorrect_on_ambiguous: u64,
    pub confident_on_determined: u64,
    pub incorrect_on_determined: u64,
    /// Abstentions at opportunities whose forced choice would have been
    /// correct: claims that were right and were not made.
    pub abstained_guess_correct: u64,

    // --- connection level -------------------------------------------------
    /// Eligible connections: every ground-truth connection with at least
    /// one observed event.
    pub connections: u64,
    /// One tracker identity, shared with no other connection.
    pub connections_exact: u64,
    /// At least one confident `new` after the connection was observed.
    pub connections_false_split: u64,
    /// Observations spread over two or more tracker identities, whether by
    /// a confident `new` or by an abstention.
    pub connections_fragmented: u64,
    /// Shares a tracker identity with another connection.
    pub connections_merge_involved: u64,
    /// Unordered pairs of distinct connections sharing a tracker identity.
    pub merged_pairs: u64,
    /// All unordered pairs of eligible connections within a trace.
    pub connection_pairs: u64,

    // --- descriptive --------------------------------------------------------
    /// Confident links that brought a new client endpoint into a track.
    pub cross_endpoint_links: u64,
    pub cross_endpoint_incorrect: u64,
    /// Confident decisions that depended on each metadata field.
    pub field_uses: BTreeMap<String, u64>,
    pub transitions: BTreeMap<String, TransitionCounts>,
}

impl Counts {
    pub fn add(&mut self, other: &Counts) {
        macro_rules! sum {
            ($($field:ident),+ $(,)?) => { $(self.$field += other.$field;)+ };
        }
        sum!(
            observations,
            links,
            news,
            abstentions,
            correct_links,
            incorrect_links,
            correct_news,
            incorrect_news,
            opportunities,
            opp_confident,
            opp_incorrect,
            opp_abstained,
            opp_ambiguous,
            opp_determined_new,
            opp_determined_link,
            abstentions_on_ambiguous,
            confident_on_ambiguous,
            incorrect_on_ambiguous,
            confident_on_determined,
            incorrect_on_determined,
            abstained_guess_correct,
            connections,
            connections_exact,
            connections_false_split,
            connections_fragmented,
            connections_merge_involved,
            merged_pairs,
            connection_pairs,
            cross_endpoint_links,
            cross_endpoint_incorrect,
        );
        for (field, uses) in &other.field_uses {
            *self.field_uses.entry(field.clone()).or_default() += uses;
        }
        for (cause, counts) in &other.transitions {
            let mine = self.transitions.entry(cause.clone()).or_default();
            mine.transitions += counts.transitions;
            mine.correct += counts.correct;
            mine.incorrect_new += counts.incorrect_new;
            mine.incorrect_link += counts.incorrect_link;
            mine.abstained += counts.abstained;
        }
    }

    pub fn pooled<'a>(parts: impl IntoIterator<Item = &'a Counts>) -> Counts {
        let mut total = Counts::default();
        for part in parts {
            total.add(part);
        }
        total
    }
}

/// A named ratio with its numerator and denominator spelled out.
#[derive(Debug, Clone, Copy)]
pub struct Metric {
    pub key: &'static str,
    pub label: &'static str,
    pub level: &'static str,
    pub numerator: &'static str,
    pub denominator: &'static str,
    /// Whether a larger value is better, worse, or neither.
    pub better: Better,
    pub primary: bool,
    pub parts: fn(&Counts) -> (u64, u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Better {
    Higher,
    Lower,
    Neither,
}

impl Metric {
    /// The metric's value, or `None` when its denominator is zero.
    pub fn value(&self, counts: &Counts) -> Option<f64> {
        let (numerator, denominator) = (self.parts)(counts);
        (denominator > 0).then(|| numerator as f64 / denominator as f64)
    }
}

/// Every reported ratio. The first eight are the frozen primary metrics.
pub const METRICS: &[Metric] = &[
    Metric {
        key: "exact_continuity_rate",
        label: "Connection-level exact continuity rate",
        level: "connection",
        numerator: "eligible connections whose observations all lie in one tracker identity that holds no other connection",
        denominator: "eligible connections (ground-truth connections with at least one observed event)",
        better: Better::Higher,
        primary: true,
        parts: |c| (c.connections_exact, c.connections),
    },
    Metric {
        key: "false_merge_pair_rate",
        label: "False merge rate (connection pairs)",
        level: "connection",
        numerator: "unordered pairs of distinct eligible connections that share a tracker identity",
        denominator: "all unordered pairs of eligible connections within the same trace",
        better: Better::Lower,
        primary: true,
        parts: |c| (c.merged_pairs, c.connection_pairs),
    },
    Metric {
        key: "false_split_rate",
        label: "False split rate (confident)",
        level: "connection",
        numerator: "eligible connections for which the tracker confidently declared `new` after the connection had already been observed",
        denominator: "eligible connections",
        better: Better::Lower,
        primary: true,
        parts: |c| (c.connections_false_split, c.connections),
    },
    Metric {
        key: "incorrect_edge_rate",
        label: "Incorrect confident association-edge rate",
        level: "edge",
        numerator: "confident association edges (`link` decisions) joining observations of distinct ground-truth connections",
        denominator: "all confident association edges (`link` decisions), on all observations",
        better: Better::Lower,
        primary: true,
        parts: |c| (c.incorrect_links, c.links),
    },
    Metric {
        key: "decision_coverage",
        label: "Decision coverage",
        level: "decision",
        numerator: "association opportunities answered with a confident decision (`link` or `new`)",
        denominator: "all association opportunities",
        better: Better::Higher,
        primary: true,
        parts: |c| (c.opp_confident, c.opportunities),
    },
    Metric {
        key: "selective_risk",
        label: "Selective risk",
        level: "decision",
        numerator: "confident decisions at association opportunities that are incorrect (an incorrect edge, or `new` for an already-observed connection)",
        denominator: "confident decisions at association opportunities",
        better: Better::Lower,
        primary: true,
        parts: |c| (c.opp_incorrect, c.opp_confident),
    },
    Metric {
        key: "abstention_precision",
        label: "Abstention precision vs the synthetic oracle",
        level: "decision",
        numerator: "abstentions on observations the oracle labels observationally ambiguous",
        denominator: "all abstentions",
        better: Better::Neither,
        primary: true,
        parts: |c| (c.abstentions_on_ambiguous, c.abstentions),
    },
    Metric {
        key: "abstention_recall",
        label: "Abstention recall vs the synthetic oracle",
        level: "decision",
        numerator: "abstentions on observations the oracle labels observationally ambiguous",
        denominator: "all association opportunities the oracle labels observationally ambiguous",
        better: Better::Neither,
        primary: true,
        parts: |c| (c.abstentions_on_ambiguous, c.opp_ambiguous),
    },
    // --- secondary and descriptive ---------------------------------------
    Metric {
        key: "fragmentation_rate",
        label: "Fragmentation rate (any cause)",
        level: "connection",
        numerator: "eligible connections whose observations lie in two or more tracker identities, by a confident `new` or by an abstention",
        denominator: "eligible connections",
        better: Better::Lower,
        primary: false,
        parts: |c| (c.connections_fragmented, c.connections),
    },
    Metric {
        key: "merge_involved_rate",
        label: "Merge-involved connection rate",
        level: "connection",
        numerator: "eligible connections that share a tracker identity with another connection",
        denominator: "eligible connections",
        better: Better::Lower,
        primary: false,
        parts: |c| (c.connections_merge_involved, c.connections),
    },
    Metric {
        key: "opportunity_abstention_rate",
        label: "Abstention rate at opportunities",
        level: "decision",
        numerator: "association opportunities answered `uncertain`",
        denominator: "all association opportunities",
        better: Better::Neither,
        primary: false,
        parts: |c| (c.opp_abstained, c.opportunities),
    },
    Metric {
        key: "ambiguous_opportunity_share",
        label: "Oracle-ambiguous share of opportunities",
        level: "decision",
        numerator: "association opportunities the oracle labels observationally ambiguous",
        denominator: "all association opportunities",
        better: Better::Neither,
        primary: false,
        parts: |c| (c.opp_ambiguous, c.opportunities),
    },
    Metric {
        key: "risk_on_ambiguous",
        label: "Risk of confident decisions on oracle-ambiguous opportunities",
        level: "decision",
        numerator: "incorrect confident decisions at oracle-ambiguous opportunities",
        denominator: "confident decisions at oracle-ambiguous opportunities",
        better: Better::Lower,
        primary: false,
        parts: |c| (c.incorrect_on_ambiguous, c.confident_on_ambiguous),
    },
    Metric {
        key: "risk_on_determined",
        label: "Risk of confident decisions on oracle-determined opportunities",
        level: "decision",
        numerator: "incorrect confident decisions at oracle-determined opportunities",
        denominator: "confident decisions at oracle-determined opportunities",
        better: Better::Lower,
        primary: false,
        parts: |c| (c.incorrect_on_determined, c.confident_on_determined),
    },
    Metric {
        key: "abstained_guess_correct_rate",
        label: "Abstentions whose forced choice was correct",
        level: "decision",
        numerator: "abstentions at association opportunities whose forced choice would have been correct",
        denominator: "abstentions at association opportunities",
        better: Better::Neither,
        primary: false,
        parts: |c| (c.abstained_guess_correct, c.opp_abstained),
    },
    Metric {
        key: "event_accuracy",
        label: "Event-level accuracy (diagnostic)",
        level: "event",
        numerator: "observations given a correct confident decision",
        denominator: "all observations",
        better: Better::Higher,
        primary: false,
        parts: |c| (c.correct_links + c.correct_news, c.observations),
    },
    Metric {
        key: "event_abstention_rate",
        label: "Event-level abstention rate (diagnostic)",
        level: "event",
        numerator: "observations answered `uncertain`",
        denominator: "all observations",
        better: Better::Neither,
        primary: false,
        parts: |c| (c.abstentions, c.observations),
    },
    Metric {
        key: "cross_endpoint_incorrect_rate",
        label: "Incorrect share of cross-endpoint associations (descriptive)",
        level: "edge",
        numerator: "confident links that brought a new client endpoint into a track and joined two different connections",
        denominator: "confident links that brought a new client endpoint into a track",
        better: Better::Lower,
        primary: false,
        parts: |c| (c.cross_endpoint_incorrect, c.cross_endpoint_links),
    },
];

pub fn metric(key: &str) -> &'static Metric {
    METRICS
        .iter()
        .find(|m| m.key == key)
        .unwrap_or_else(|| panic!("unknown metric `{key}`"))
}

pub fn primary_metrics() -> impl Iterator<Item = &'static Metric> {
    METRICS.iter().filter(|m| m.primary)
}

#[derive(Debug, Clone, PartialEq)]
pub struct Scored {
    pub counts: Counts,
    /// One outcome per event, parallel to the trace.
    pub outcomes: Vec<Outcome>,
}

#[derive(Default)]
struct ConnState {
    tracks: BTreeSet<TrackId>,
    false_split: bool,
}

struct TrackState {
    /// Ground-truth connection of the latest observation on each 4-tuple.
    last_on_flow: HashMap<FlowKey, u32>,
    /// Ground-truth connection of the latest observation overall.
    last: u32,
    clients: BTreeSet<Endpoint>,
    members: BTreeSet<u32>,
}

impl TrackState {
    fn open(conn: u32, flow: FlowKey) -> Self {
        Self {
            last_on_flow: HashMap::from([(flow, conn)]),
            last: conn,
            clients: BTreeSet::from([flow.client]),
            members: BTreeSet::from([conn]),
        }
    }

    /// The connection of this track's predecessor for an observation on
    /// `flow`.
    fn predecessor(&self, flow: &FlowKey) -> u32 {
        self.last_on_flow.get(flow).copied().unwrap_or(self.last)
    }

    fn file(&mut self, conn: u32, flow: FlowKey) {
        self.last_on_flow.insert(flow, conn);
        self.last = conn;
        self.clients.insert(flow.client);
        self.members.insert(conn);
    }
}

fn contract(tracker: &str, event: &Event, message: String) -> Error {
    Error::TrackerContract {
        tracker: tracker.to_string(),
        seq: event.seq,
        message,
    }
}

/// Score a tracker's decisions on one trace.
///
/// `annotations` are the oracle's labels for the same observations. They
/// decide which events are opportunities and which are ambiguous; they play
/// no part in deciding whether a decision was correct.
pub fn score(
    tracker: &str,
    events: &[Event],
    decisions: &[Decision],
    annotations: &[Annotation],
) -> Result<Scored, Error> {
    if events.len() != decisions.len() || events.len() != annotations.len() {
        return Err(Error::LengthMismatch {
            events: events.len(),
            decisions: decisions.len(),
            annotations: annotations.len(),
        });
    }

    let mut c = Counts::default();
    let mut outcomes = Vec::with_capacity(events.len());
    let mut tracks: HashMap<TrackId, TrackState> = HashMap::new();
    let mut conns: BTreeMap<u32, ConnState> = BTreeMap::new();
    let mut segments_seen: HashSet<(u32, u16)> = HashSet::new();

    for ((event, decision), annotation) in events.iter().zip(decisions).zip(annotations) {
        let conn = event.truth.connection;
        let flow = event.observed.flow();
        let seen_before = conns.contains_key(&conn);
        let state = conns.entry(conn).or_default();

        let outcome = match decision.verdict {
            Verdict::Link => {
                let Some(track) = tracks.get_mut(&decision.track) else {
                    let message = format!("linked to unknown track {}", decision.track.0);
                    return Err(contract(tracker, event, message));
                };
                let correct = track.predecessor(&flow) == conn;
                if !track.clients.contains(&flow.client) {
                    c.cross_endpoint_links += 1;
                    c.cross_endpoint_incorrect += u64::from(!correct);
                }
                track.file(conn, flow);
                if correct {
                    Outcome::CorrectLink
                } else {
                    Outcome::IncorrectLink
                }
            }
            Verdict::New | Verdict::Uncertain => {
                let fresh = TrackState::open(conn, flow);
                if tracks.insert(decision.track, fresh).is_some() {
                    let message = format!("reused track id {} for a new track", decision.track.0);
                    return Err(contract(tracker, event, message));
                }
                match decision.verdict {
                    Verdict::Uncertain => Outcome::Abstained,
                    _ if seen_before => {
                        state.false_split = true;
                        Outcome::IncorrectNew
                    }
                    _ => Outcome::CorrectNew,
                }
            }
        };
        state.tracks.insert(decision.track);

        // Event level.
        c.observations += 1;
        let (confident, incorrect) = match outcome {
            Outcome::CorrectLink => {
                c.links += 1;
                c.correct_links += 1;
                (true, false)
            }
            Outcome::IncorrectLink => {
                c.links += 1;
                c.incorrect_links += 1;
                (true, true)
            }
            Outcome::CorrectNew => {
                c.news += 1;
                c.correct_news += 1;
                (true, false)
            }
            Outcome::IncorrectNew => {
                c.news += 1;
                c.incorrect_news += 1;
                (true, true)
            }
            Outcome::Abstained => {
                c.abstentions += 1;
                (false, false)
            }
        };
        if confident {
            for field in decision.basis.iter() {
                *c.field_uses.entry(field.to_string()).or_default() += 1;
            }
        }
        let ambiguous = annotation.label == Label::Ambiguous;
        if outcome == Outcome::Abstained && ambiguous {
            c.abstentions_on_ambiguous += 1;
        }

        // Decision level.
        if annotation.opportunity {
            c.opportunities += 1;
            match annotation.label {
                Label::Ambiguous => c.opp_ambiguous += 1,
                Label::DeterminedNew => c.opp_determined_new += 1,
                _ => c.opp_determined_link += 1,
            }
            if confident {
                c.opp_confident += 1;
                c.opp_incorrect += u64::from(incorrect);
                if ambiguous {
                    c.confident_on_ambiguous += 1;
                    c.incorrect_on_ambiguous += u64::from(incorrect);
                } else {
                    c.confident_on_determined += 1;
                    c.incorrect_on_determined += u64::from(incorrect);
                }
            } else {
                c.opp_abstained += 1;
                let guess_correct = match decision.guess {
                    Some(Guess::Link(id)) if id != decision.track => tracks
                        .get(&id)
                        .is_some_and(|t| t.predecessor(&flow) == conn),
                    Some(Guess::New) => !seen_before,
                    _ => false,
                };
                c.abstained_guess_correct += u64::from(guess_correct);
            }
        }

        // First observed event of each ground-truth path segment.
        if segments_seen.insert((conn, event.truth.segment)) {
            let t = c
                .transitions
                .entry(event.truth.cause.to_string())
                .or_default();
            t.transitions += 1;
            match outcome {
                Outcome::CorrectLink | Outcome::CorrectNew => t.correct += 1,
                Outcome::IncorrectNew => t.incorrect_new += 1,
                Outcome::IncorrectLink => t.incorrect_link += 1,
                Outcome::Abstained => t.abstained += 1,
            }
        }
        outcomes.push(outcome);
    }

    // Connection level.
    let mut merged_pairs: BTreeSet<(u32, u32)> = BTreeSet::new();
    for track in tracks.values() {
        let members: Vec<u32> = track.members.iter().copied().collect();
        for (i, a) in members.iter().enumerate() {
            for b in &members[i + 1..] {
                merged_pairs.insert((*a, *b));
            }
        }
    }
    let n = conns.len() as u64;
    c.connections = n;
    c.connection_pairs = n * n.saturating_sub(1) / 2;
    c.merged_pairs = merged_pairs.len() as u64;
    for state in conns.values() {
        let merged = state
            .tracks
            .iter()
            .any(|id| tracks.get(id).is_some_and(|t| t.members.len() > 1));
        let fragmented = state.tracks.len() > 1;
        c.connections_merge_involved += u64::from(merged);
        c.connections_fragmented += u64::from(fragmented);
        c.connections_false_split += u64::from(state.false_split);
        c.connections_exact += u64::from(!merged && !fragmented);
    }

    // Make every field and cause appear in every result, so rows line up.
    for field in Field::ALL {
        c.field_uses.entry(field.to_string()).or_default();
    }
    for cause in Cause::ALL {
        c.transitions.entry(cause.to_string()).or_default();
    }

    Ok(Scored {
        counts: c,
        outcomes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::basis::FieldSet;
    use crate::oracle;
    use crate::testkit::{c2s, events, events_with_cause, ObsExt, MS, SEC};
    use crate::tracker::Reason;

    fn decision(verdict: Verdict, track: u32, guess: Option<Guess>) -> Decision {
        Decision {
            verdict,
            track: TrackId(track),
            basis: FieldSet::of(&[Field::ClientAddr, Field::Timing]),
            reason: Reason::TupleContinuity,
            confidence: 1000,
            guess,
        }
    }

    fn link(track: u32) -> Decision {
        decision(Verdict::Link, track, None)
    }

    fn new(track: u32) -> Decision {
        decision(Verdict::New, track, None)
    }

    fn unsure(track: u32, guess: Guess) -> Decision {
        decision(Verdict::Uncertain, track, Some(guess))
    }

    fn scored(events: &[Event], decisions: &[Decision]) -> Scored {
        let observations: Vec<_> = events.iter().map(|e| e.observed).collect();
        let annotations = oracle::annotate(&observations);
        score("test", events, decisions, &annotations).unwrap()
    }

    fn value(counts: &Counts, key: &str) -> Option<f64> {
        metric(key).value(counts)
    }

    /// Two connections on two tuples, a handshake packet and a data packet
    /// each.
    fn two_flows() -> Vec<Event> {
        events(&[
            (c2s(0, 1, 5000).initial(0xA0), 0),
            (c2s(0, 2, 5000).initial(0xB0), 1),
            (c2s(MS, 1, 5000), 0),
            (c2s(MS, 2, 5000), 1),
        ])
    }

    #[test]
    fn perfect_tracking_scores_perfectly() {
        let c = scored(&two_flows(), &[new(0), new(1), link(0), link(1)]).counts;
        assert_eq!(
            (c.observations, c.connections, c.connection_pairs),
            (4, 2, 1)
        );
        assert_eq!((c.correct_news, c.correct_links), (2, 2));
        assert_eq!(c.incorrect_links + c.incorrect_news + c.merged_pairs, 0);
        // The two handshake packets start runs; the data packets do not.
        assert_eq!(c.opportunities, 2);
        assert_eq!(value(&c, "exact_continuity_rate"), Some(1.0));
        assert_eq!(value(&c, "false_merge_pair_rate"), Some(0.0));
        assert_eq!(value(&c, "false_split_rate"), Some(0.0));
        assert_eq!(value(&c, "incorrect_edge_rate"), Some(0.0));
        assert_eq!(value(&c, "decision_coverage"), Some(1.0));
        assert_eq!(value(&c, "selective_risk"), Some(0.0));
        // No abstentions and no ambiguous opportunities: undefined.
        assert_eq!(value(&c, "abstention_precision"), None);
        assert_eq!(value(&c, "abstention_recall"), None);
    }

    #[test]
    fn an_edge_is_judged_against_the_tracks_predecessor() {
        let s = scored(&two_flows(), &[new(0), link(0), link(0), link(0)]);
        let c = &s.counts;
        // Connection 1's first packet joins connection 0's track: one bad
        // edge. Its second packet follows its own tuple predecessor: fine.
        assert_eq!(
            s.outcomes,
            [
                Outcome::CorrectNew,
                Outcome::IncorrectLink,
                Outcome::CorrectLink,
                Outcome::CorrectLink
            ]
        );
        assert_eq!((c.incorrect_links, c.links), (1, 3));
        assert_eq!(c.merged_pairs, 1);
        assert_eq!(c.connections_merge_involved, 2);
        assert_eq!(c.connections_exact, 0);
        assert_eq!(value(c, "false_merge_pair_rate"), Some(1.0));
        // The bad edge was made at an opportunity.
        assert_eq!((c.opp_incorrect, c.opp_confident), (1, 2));
        assert_eq!(value(c, "selective_risk"), Some(0.5));
    }

    #[test]
    fn declaring_a_known_connection_new_is_a_confident_false_split() {
        let c = scored(&two_flows(), &[new(0), new(1), new(2), link(1)]).counts;
        assert_eq!(c.incorrect_news, 1);
        assert_eq!(c.connections_false_split, 1);
        assert_eq!(c.connections_fragmented, 1);
        assert_eq!(c.connections_exact, 1);
        assert_eq!(c.merged_pairs, 0);
        assert_eq!(value(&c, "false_split_rate"), Some(0.5));
        assert_eq!(value(&c, "fragmentation_rate"), Some(0.5));
    }

    #[test]
    fn an_abstention_fragments_without_being_a_false_split() {
        let ev = events(&[
            (c2s(0, 1, 5000).dcid(7), 0),
            (c2s(SEC, 9, 7000).dcid(8), 0),
            (c2s(SEC + MS, 9, 7000).dcid(8), 0),
        ]);
        let c = scored(&ev, &[new(0), unsure(1, Guess::New), link(1)]).counts;
        assert_eq!(c.connections_false_split, 0);
        assert_eq!(c.connections_fragmented, 1);
        assert_eq!(c.connections_exact, 0);
        assert_eq!(value(&c, "false_split_rate"), Some(0.0));
        assert_eq!(value(&c, "fragmentation_rate"), Some(1.0));
    }

    #[test]
    fn coverage_and_selective_risk_are_taken_over_opportunities() {
        // A migration: start, then a run on a new tuple with a fresh ID.
        let ev = events(&[
            (c2s(0, 1, 5000).dcid(7), 0),
            (c2s(100 * MS, 1, 5000).dcid(7), 0),
            (c2s(SEC, 9, 7000).dcid(8), 0),
            (c2s(SEC + MS, 9, 7000).dcid(8), 0),
        ]);
        let confident = scored(&ev, &[new(0), link(0), new(1), link(1)]).counts;
        assert_eq!(confident.opportunities, 2);
        assert_eq!(value(&confident, "decision_coverage"), Some(1.0));
        assert_eq!(value(&confident, "selective_risk"), Some(0.5));

        let cautious = scored(&ev, &[new(0), link(0), unsure(1, Guess::New), link(1)]).counts;
        assert_eq!(value(&cautious, "decision_coverage"), Some(0.5));
        assert_eq!(value(&cautious, "selective_risk"), Some(0.0));
        assert_eq!(value(&cautious, "opportunity_abstention_rate"), Some(0.5));
        // Four observations, three confident and correct.
        assert_eq!(value(&cautious, "event_accuracy"), Some(0.75));
    }

    #[test]
    fn abstentions_are_compared_with_the_oracle() {
        let ev = events(&[
            (c2s(0, 1, 5000).dcid(7), 0),
            // Ambiguous: a fresh ID on a fresh tuple.
            (c2s(SEC, 9, 7000).dcid(8), 0),
            // Routine: same tuple a millisecond later.
            (c2s(SEC + MS, 9, 7000).dcid(8), 0),
            // Determined link: a known ID after a long silence.
            (c2s(20 * SEC, 9, 7000).dcid(8), 0),
        ]);
        let decisions = [
            new(0),
            unsure(1, Guess::New),
            unsure(2, Guess::Link(TrackId(1))),
            link(1),
        ];
        let c = scored(&ev, &decisions).counts;
        assert_eq!((c.opp_ambiguous, c.opp_determined_link), (1, 1));
        assert_eq!(c.opp_determined_new, 1);
        assert_eq!((c.abstentions, c.abstentions_on_ambiguous), (2, 1));
        assert_eq!(value(&c, "abstention_precision"), Some(0.5));
        assert_eq!(value(&c, "abstention_recall"), Some(1.0));
        assert_eq!(value(&c, "ambiguous_opportunity_share"), Some(1.0 / 3.0));
        // Only the first abstention was at an opportunity; its forced
        // choice ("new") would have been wrong.
        assert_eq!((c.opp_abstained, c.abstained_guess_correct), (1, 0));
    }

    #[test]
    fn forced_choices_on_abstentions_are_scored_like_decisions() {
        let ev = events(&[(c2s(0, 1, 5000), 0), (c2s(5 * SEC, 1, 6000), 0)]);
        let right = scored(&ev, &[new(0), unsure(1, Guess::Link(TrackId(0)))]).counts;
        assert_eq!(right.abstained_guess_correct, 1);
        assert_eq!(value(&right, "abstained_guess_correct_rate"), Some(1.0));
        let wrong = scored(&ev, &[new(0), unsure(1, Guess::New)]).counts;
        assert_eq!(wrong.abstained_guess_correct, 0);
    }

    #[test]
    fn confident_decisions_are_split_by_oracle_label() {
        // The third flow goes to a server with no other traffic, so it can
        // only be new.
        let elsewhere = Endpoint {
            addr: crate::model::Addr::new(192, 0, 2, 99),
            port: 443,
        };
        let ev = events(&[
            (c2s(0, 1, 5000).dcid(7), 0),
            (c2s(SEC, 9, 7000).dcid(8), 0),
            (c2s(0, 2, 5000).initial(0xB0).to(elsewhere), 1),
        ]);
        // A correct link on an ambiguous opportunity (a lucky guess).
        let c = scored(&ev, &[new(0), link(0), new(1)]).counts;
        assert_eq!((c.confident_on_ambiguous, c.incorrect_on_ambiguous), (1, 0));
        assert_eq!(
            (c.confident_on_determined, c.incorrect_on_determined),
            (2, 0)
        );
        assert_eq!(value(&c, "risk_on_ambiguous"), Some(0.0));
    }

    #[test]
    fn merged_pairs_are_counted_once_per_pair() {
        let ev = events(&[
            (c2s(0, 1, 5000).initial(1), 0),
            (c2s(0, 2, 5000).initial(2), 1),
            (c2s(0, 3, 5000).initial(3), 2),
            (c2s(0, 4, 5000).initial(4), 3),
        ]);
        let c = scored(&ev, &[new(0), link(0), link(0), new(1)]).counts;
        // Three connections in one track: three pairs out of six.
        assert_eq!((c.merged_pairs, c.connection_pairs), (3, 6));
        assert_eq!(c.connections_merge_involved, 3);
        assert_eq!(c.connections_exact, 1);
        assert_eq!(value(&c, "merge_involved_rate"), Some(0.75));
    }

    #[test]
    fn cross_endpoint_links_count_each_new_client_endpoint_once() {
        let ev = events(&[
            (c2s(0, 1, 5000), 0),
            (c2s(MS, 1, 5000), 0),
            (c2s(SEC, 1, 6000), 0),
            (c2s(2 * SEC, 9, 7000), 0),
            (c2s(0, 2, 5000), 1),
            // Going back and forth between known endpoints adds nothing.
            (c2s(3 * SEC, 1, 5000), 0),
            (c2s(3 * SEC, 9, 7000), 0),
        ]);
        let all = [new(0), link(0), link(0), link(0), link(0), link(0), link(0)];
        let c = scored(&ev, &all).counts;
        assert_eq!(c.cross_endpoint_links, 3);
        assert_eq!(c.cross_endpoint_incorrect, 1);
    }

    #[test]
    fn field_uses_cover_confident_decisions_only() {
        let c = scored(
            &two_flows(),
            &[new(0), unsure(1, Guess::New), link(0), link(1)],
        )
        .counts;
        assert_eq!(c.field_uses["client-addr"], 3);
        assert_eq!(c.field_uses["connection-id"], 0);
    }

    #[test]
    fn transitions_are_scored_at_the_first_event_of_each_segment() {
        let ev = events_with_cause(&[
            (c2s(0, 1, 5000).initial(0xA0), 0, 0, Cause::Start),
            (c2s(MS, 1, 5000), 0, 0, Cause::Start),
            (c2s(SEC, 1, 6000), 0, 1, Cause::NatRebind),
            (c2s(SEC + MS, 1, 6000), 0, 1, Cause::NatRebind),
            (c2s(2 * SEC, 9, 7000), 0, 2, Cause::Migration),
        ]);
        let decisions = [new(0), link(0), new(1), link(1), unsure(2, Guess::New)];
        let t = scored(&ev, &decisions).counts.transitions;
        assert_eq!((t["start"].transitions, t["start"].correct), (1, 1));
        assert_eq!(t["nat-rebind"].incorrect_new, 1);
        assert_eq!(t["migration"].abstained, 1);
        assert_eq!(t["path-change"].transitions, 0);
    }

    #[test]
    fn counts_are_additive_and_internally_consistent() {
        let a = scored(&two_flows(), &[new(0), new(1), link(0), link(1)]).counts;
        let b = scored(&two_flows(), &[new(0), link(0), link(0), link(0)]).counts;
        let total = Counts::pooled([&a, &b]);
        assert_eq!(total.observations, 8);
        assert_eq!(total.connections, 4);
        // Pairs are counted within a trace, never across traces.
        assert_eq!(total.connection_pairs, 2);
        assert_eq!(total.transitions["start"].transitions, 4);

        for c in [&a, &b, &total] {
            assert_eq!(c.links + c.news + c.abstentions, c.observations);
            assert_eq!(c.correct_links + c.incorrect_links, c.links);
            assert_eq!(c.correct_news + c.incorrect_news, c.news);
            assert_eq!(c.opp_confident + c.opp_abstained, c.opportunities);
            assert_eq!(
                c.opp_ambiguous + c.opp_determined_new + c.opp_determined_link,
                c.opportunities
            );
            assert_eq!(
                c.confident_on_ambiguous + c.confident_on_determined,
                c.opp_confident
            );
        }
    }

    #[test]
    fn every_metric_names_its_numerator_and_denominator() {
        let keys: BTreeSet<&str> = METRICS.iter().map(|m| m.key).collect();
        assert_eq!(keys.len(), METRICS.len());
        assert_eq!(primary_metrics().count(), 8);
        for m in METRICS {
            assert!(
                !m.numerator.is_empty() && !m.denominator.is_empty(),
                "{}",
                m.key
            );
            assert!(["connection", "edge", "decision", "event"].contains(&m.level));
            assert_eq!(m.value(&Counts::default()), None);
        }
    }

    #[test]
    fn contract_violations_and_length_mismatches_are_errors() {
        let ev = two_flows();
        let observations: Vec<_> = ev.iter().map(|e| e.observed).collect();
        let ann = oracle::annotate(&observations);

        let unknown = score("t", &ev, &[new(0), link(5), link(0), link(0)], &ann);
        assert!(matches!(
            unknown,
            Err(Error::TrackerContract { seq: 1, .. })
        ));
        let reused = score("t", &ev, &[new(0), new(0), link(0), link(0)], &ann);
        assert!(matches!(reused, Err(Error::TrackerContract { seq: 1, .. })));
        let short = score("t", &ev, &[new(0)], &ann);
        assert!(matches!(short, Err(Error::LengthMismatch { .. })));
    }

    #[test]
    fn run_gives_one_decision_per_event() {
        let trace = crate::gen::generate(crate::gen::Scenario::Ordinary, 1, 3);
        let mut tracker = crate::tracker::Spec::StrictTuple.build();
        assert_eq!(run(tracker.as_mut(), &trace).len(), trace.events.len());
    }
}
