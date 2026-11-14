//! `continuity-forced` and `continuity-abstain`: one evidence computation,
//! two final policies.
//!
//! [`Continuity::evidence`] turns an observation and the tracker's state
//! into a ranked list of scored choices. It is the only place evidence is
//! computed, and it does not know which policy will use it.
//!
//! * [`Policy::Forced`] always takes the best-scoring choice.
//! * [`Policy::Abstain`] takes the same choice when its score reaches the
//!   threshold, and otherwise answers `uncertain`, filing the observation
//!   under a provisional track and reporting the choice as its guess.
//!
//! With a threshold of zero the two are the same tracker.
//!
//! # Scores
//!
//! Each choice gets a weight; a choice's score is its share of the total
//! weight, in thousandths. The weights are fixed, simple, and deliberately
//! not tuned:
//!
//! * a known connection ID, or a long header: the single choice, score 1000;
//! * a known 4-tuple silent for `g`: "same track" weighs `T / (T + g)` and
//!   "new connection" the remainder, with `T` = [`TUPLE_HALF_LIFE_US`];
//! * an unknown 4-tuple: each existing track to that server weighs
//!   `H / (H + g)` with `H` = [`HANDOVER_HALF_LIFE_US`], divided by
//!   [`OTHER_ADDRESS_DIVISOR`] if its client address differs; "new
//!   connection" weighs [`NEW_PRIOR_PER_MILLE`] thousandths.

use crate::basis::{Field, FieldSet};
use crate::model::{HeaderForm, Observation};

use super::table::Table;
use super::{
    Decision, Guess, Reason, TrackId, Tracker, Verdict, CONTINUITY_ABSTAIN, CONTINUITY_FORCED,
};

/// Silence after which "same track" and "new connection" score equally on
/// a known 4-tuple.
pub const TUPLE_HALF_LIFE_US: u64 = 30_000_000;
/// Silence at which an existing track's weight as a handover source halves.
pub const HANDOVER_HALF_LIFE_US: u64 = 10_000_000;
/// Weight of "new connection" on an unknown 4-tuple, in thousandths of a
/// just-active same-address track's weight.
pub const NEW_PRIOR_PER_MILLE: u64 = 500;
/// How much less a track from a different client address weighs.
pub const OTHER_ADDRESS_DIVISOR: u64 = 4;
/// Long-header packets on one tuple within this long of a handshake's first
/// packet are taken to be part of that handshake.
pub const HANDSHAKE_WINDOW_US: u64 = 1_000_000;

const UNIT: u64 = 1_000_000;

fn decay(half_life_us: u64, gap_us: u64) -> u64 {
    UNIT * half_life_us / (half_life_us + gap_us)
}

/// What an observation could be: a continuation of a track, or new.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Target {
    Link(TrackId),
    New,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Candidate {
    pub target: Target,
    pub weight: u64,
}

/// The scored choices for one observation, best first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
    pub kind: Reason,
    pub basis: FieldSet,
    /// Never empty. Sorted by weight, heaviest first; ties go to a link
    /// over "new", then to the older track.
    pub candidates: Vec<Candidate>,
    /// Whether a track opened on this evidence takes over the 4-tuple.
    pub claims_tuple: bool,
}

impl Evidence {
    fn certain(target: Target, kind: Reason, basis: FieldSet) -> Self {
        Evidence {
            kind,
            basis,
            candidates: vec![Candidate {
                target,
                weight: UNIT,
            }],
            claims_tuple: true,
        }
    }

    fn ranked(kind: Reason, basis: FieldSet, mut candidates: Vec<Candidate>, claims: bool) -> Self {
        candidates.sort_by_key(|c| (std::cmp::Reverse(c.weight), c.target));
        Evidence {
            kind,
            basis,
            candidates,
            claims_tuple: claims,
        }
    }

    pub fn best(&self) -> Candidate {
        self.candidates[0]
    }

    /// The best choice's share of the total weight, in thousandths.
    pub fn confidence(&self) -> u16 {
        let total: u64 = self.candidates.iter().map(|c| c.weight).sum();
        (self.best().weight * 1000 / total.max(1)) as u16
    }
}

/// The final decision policy. The only thing that differs between the two
/// continuity methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    Forced,
    Abstain { threshold_per_mille: u16 },
}

impl Policy {
    fn abstains_at(self, confidence: u16) -> bool {
        match self {
            Policy::Forced => false,
            Policy::Abstain {
                threshold_per_mille,
            } => confidence < threshold_per_mille,
        }
    }
}

fn tuple_basis() -> FieldSet {
    FieldSet::of(&[
        Field::ClientAddr,
        Field::ClientPort,
        Field::ServerEndpoint,
        Field::Timing,
    ])
}

pub struct Continuity {
    table: Table,
    policy: Policy,
}

impl Continuity {
    pub fn new(policy: Policy) -> Self {
        Self {
            table: Table::default(),
            policy,
        }
    }

    pub fn policy(&self) -> Policy {
        self.policy
    }

    /// Replace the policy, keeping all state. Lets a test ask what the other
    /// method would decide from exactly this state.
    pub fn with_policy(mut self, policy: Policy) -> Self {
        self.policy = policy;
        self
    }

    /// The scored choices for `obs` given everything seen so far. Does not
    /// change any state and does not depend on the policy.
    pub fn evidence(&self, obs: &Observation) -> Evidence {
        // A connection ID already filed under a track.
        if let Some(track) = self.table.by_cid(obs) {
            let basis = FieldSet::of(&[Field::ConnectionId, Field::ServerEndpoint]);
            return Evidence::certain(Target::Link(track), Reason::CidMatch, basis);
        }

        let now = obs.timestamp_us;
        let holder = self.table.on_flow(obs);

        // Long headers occur only during a handshake: this one belongs to a
        // handshake just seen starting on its tuple, or starts a connection.
        if obs.transport.header == HeaderForm::Long {
            let in_progress = holder.filter(|t| {
                t.opened_by_handshake && now.abs_diff(t.started_us) <= HANDSHAKE_WINDOW_US
            });
            return match in_progress {
                Some(track) => Evidence::certain(
                    Target::Link(track.id),
                    Reason::HandshakeContinuation,
                    tuple_basis().with(Field::Handshake),
                ),
                None => Evidence::certain(
                    Target::New,
                    Reason::HandshakeStart,
                    FieldSet::of(&[Field::Handshake, Field::ConnectionId]),
                ),
            };
        }

        // A known 4-tuple: same track or a new connection, by silence.
        if let Some(holder) = holder {
            // A record captured before the holder took the tuple over
            // belongs to the era of the track it displaced.
            let earlier = holder
                .displaced
                .filter(|_| now < holder.started_us)
                .map(|id| self.table.get(id));
            let (track, kind, claims) = match earlier {
                Some(previous) => (previous, Reason::Reordered, false),
                None => (holder, Reason::TupleContinuity, true),
            };
            let same = decay(TUPLE_HALF_LIFE_US, now.saturating_sub(track.last_seen_us));
            let candidates = vec![
                Candidate {
                    target: Target::Link(track.id),
                    weight: same,
                },
                Candidate {
                    target: Target::New,
                    weight: UNIT - same,
                },
            ];
            return Evidence::ranked(kind, tuple_basis(), candidates, claims);
        }

        // An unknown 4-tuple: any existing track to this server might have
        // moved here, or it is a connection not seen before.
        let client = obs.client();
        let mut candidates: Vec<Candidate> = self
            .table
            .toward(obs.server())
            .iter()
            .map(|id| {
                let track = self.table.get(*id);
                let mut weight = decay(
                    HANDOVER_HALF_LIFE_US,
                    now.saturating_sub(track.last_seen_us),
                );
                if track.flow.client.addr != client.addr {
                    weight /= OTHER_ADDRESS_DIVISOR;
                }
                Candidate {
                    target: Target::Link(*id),
                    weight,
                }
            })
            .collect();
        if candidates.is_empty() {
            let basis = tuple_basis().with(Field::CrossFlow);
            return Evidence::certain(Target::New, Reason::Isolated, basis);
        }
        candidates.push(Candidate {
            target: Target::New,
            weight: UNIT * NEW_PRIOR_PER_MILLE / 1000,
        });
        let basis = FieldSet::of(&[
            Field::ClientAddr,
            Field::ServerEndpoint,
            Field::Timing,
            Field::CrossFlow,
        ]);
        Evidence::ranked(Reason::Handover, basis, candidates, true)
    }
}

impl Tracker for Continuity {
    fn name(&self) -> &'static str {
        match self.policy {
            Policy::Forced => CONTINUITY_FORCED,
            Policy::Abstain { .. } => CONTINUITY_ABSTAIN,
        }
    }

    fn observe(&mut self, obs: &Observation) -> Decision {
        let evidence = self.evidence(obs);
        let best = evidence.best();
        let confidence = evidence.confidence();

        if self.policy.abstains_at(confidence) {
            let track = self.table.open(obs, evidence.claims_tuple);
            let guess = match best.target {
                Target::Link(id) => Guess::Link(id),
                Target::New => Guess::New,
            };
            return Decision {
                verdict: Verdict::Uncertain,
                track,
                basis: evidence.basis,
                reason: evidence.kind,
                confidence,
                guess: Some(guess),
            };
        }

        let (verdict, track) = match best.target {
            Target::Link(id) => {
                self.table.file(id, obs);
                (Verdict::Link, id)
            }
            Target::New => (Verdict::New, self.table.open(obs, evidence.claims_tuple)),
        };
        Decision {
            verdict,
            track,
            basis: evidence.basis,
            reason: evidence.kind,
            confidence,
            guess: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Addr, Endpoint};
    use crate::testkit::{c2s, s2c, ObsExt, MS, SEC};

    fn forced() -> Continuity {
        Continuity::new(Policy::Forced)
    }

    fn abstain(threshold_per_mille: u16) -> Continuity {
        Continuity::new(Policy::Abstain {
            threshold_per_mille,
        })
    }

    #[test]
    fn decay_halves_at_the_half_life() {
        assert_eq!(decay(10 * SEC, 0), UNIT);
        assert_eq!(decay(10 * SEC, 10 * SEC), UNIT / 2);
        assert_eq!(decay(10 * SEC, 30 * SEC), UNIT / 4);
    }

    // --- evidence -------------------------------------------------------

    #[test]
    fn a_known_connection_id_is_the_only_choice() {
        let mut t = forced();
        let before = t.observe(&c2s(0, 1, 5000).dcid(7));
        let evidence = t.evidence(&c2s(60 * SEC, 2, 6000).dcid(7));
        assert_eq!(evidence.kind, Reason::CidMatch);
        assert_eq!(evidence.best().target, Target::Link(before.track));
        assert_eq!(evidence.confidence(), 1000);
        assert!(!evidence.basis.contains(Field::ClientAddr));
    }

    #[test]
    fn a_long_header_starts_or_continues_a_handshake() {
        let mut t = forced();
        let quiet = t.observe(&c2s(0, 1, 5000));
        let restart = c2s(5 * SEC, 1, 5000).initial(0xB0);
        assert_eq!(t.evidence(&restart).kind, Reason::HandshakeStart);
        assert_eq!(t.evidence(&restart).best().target, Target::New);
        let started = t.observe(&restart);
        assert_ne!(started.track, quiet.track);

        // The server's reply, with IDs not seen yet, joins that handshake.
        let reply = s2c(5 * SEC + 20 * MS, 1, 5000).initial(0xB1);
        let evidence = t.evidence(&reply);
        assert_eq!(evidence.kind, Reason::HandshakeContinuation);
        assert_eq!(evidence.best().target, Target::Link(started.track));
        assert_eq!(evidence.confidence(), 1000);
    }

    #[test]
    fn a_server_initial_seen_first_starts_a_connection() {
        let mut t = forced();
        t.observe(&c2s(0, 1, 5000));
        let first = t.observe(&s2c(SEC, 2, 6000).initial(0xA1));
        assert_eq!(first.verdict, Verdict::New);
        assert_eq!(first.reason, Reason::HandshakeStart);
    }

    #[test]
    fn tuple_continuity_is_scored_by_silence() {
        let mut t = forced();
        let track = t.observe(&c2s(0, 1, 5000)).track;
        let score = |t: &Continuity, at: u64| {
            let e = t.evidence(&c2s(at, 1, 5000));
            assert_eq!(e.kind, Reason::TupleContinuity);
            (e.best().target, e.confidence())
        };
        assert_eq!(score(&t, 0), (Target::Link(track), 1000));
        assert_eq!(score(&t, 10 * SEC), (Target::Link(track), 750));
        // At the half-life the two choices tie and the link is listed first.
        assert_eq!(score(&t, 30 * SEC), (Target::Link(track), 500));
        assert_eq!(score(&t, 90 * SEC), (Target::New, 750));
    }

    #[test]
    fn a_rotated_id_on_an_active_tuple_scores_as_tuple_continuity() {
        let mut t = forced();
        let before = t.observe(&c2s(0, 1, 5000).dcid(7));
        let e = t.evidence(&c2s(SEC, 1, 5000).dcid(8));
        assert_eq!(e.kind, Reason::TupleContinuity);
        assert_eq!(e.best().target, Target::Link(before.track));
    }

    #[test]
    fn handover_weighs_recency_and_client_address() {
        let mut t = forced();
        let old = t.observe(&c2s(0, 1, 5000).initial(1)).track;
        let recent = t.observe(&c2s(8 * SEC, 1, 5001).initial(2)).track;
        let other = t.observe(&c2s(10 * SEC, 2, 5000).initial(3)).track;

        let e = t.evidence(&c2s(10 * SEC, 1, 6000));
        assert_eq!(e.kind, Reason::Handover);
        assert!(e.basis.contains(Field::CrossFlow));
        let order: Vec<Target> = e.candidates.iter().map(|c| c.target).collect();
        // Same address and recent, then same address and older (tied with
        // "new", which loses ties), then the other address.
        assert_eq!(
            order,
            [
                Target::Link(recent),
                Target::Link(old),
                Target::New,
                Target::Link(other)
            ]
        );
        let weights: Vec<u64> = e.candidates.iter().map(|c| c.weight).collect();
        assert_eq!(weights, [UNIT * 10 / 12, UNIT / 2, UNIT / 2, UNIT / 4]);
        // 833333 of 2083333.
        assert_eq!(e.confidence(), 399);
    }

    #[test]
    fn a_first_flow_to_a_server_is_new_with_full_confidence() {
        let mut t = forced();
        let e = t.evidence(&c2s(0, 1, 5000));
        assert_eq!(e.kind, Reason::Isolated);
        assert_eq!((e.best().target, e.confidence()), (Target::New, 1000));

        t.observe(&c2s(0, 1, 5000));
        let elsewhere = Endpoint {
            addr: Addr::new(192, 0, 2, 99),
            port: 443,
        };
        let e = t.evidence(&c2s(SEC, 2, 5000).to(elsewhere));
        assert_eq!(e.kind, Reason::Isolated);
    }

    #[test]
    fn a_record_older_than_the_tuples_holder_is_scored_against_its_predecessor() {
        let mut t = forced();
        let old = t.observe(&c2s(0, 1, 5000)).track;
        let new = t.observe(&c2s(2 * SEC, 1, 5000).initial(0xB0)).track;
        let late = c2s(SEC, 1, 5000);
        let e = t.evidence(&late);
        assert_eq!(e.kind, Reason::Reordered);
        assert_eq!(e.best().target, Target::Link(old));
        assert!(!e.claims_tuple);

        // Filing it does not take the tuple back from the new connection.
        assert_eq!(t.observe(&late).track, old);
        assert_eq!(t.observe(&c2s(2 * SEC + MS, 1, 5000)).track, new);
    }

    #[test]
    fn a_slightly_early_record_on_a_fresh_tuple_is_plain_continuity() {
        let mut t = forced();
        let first = t.observe(&s2c(SEC, 1, 5000));
        let e = t.evidence(&c2s(SEC - 10 * MS, 1, 5000));
        assert_eq!(e.kind, Reason::TupleContinuity);
        assert_eq!(e.best().target, Target::Link(first.track));
        assert_eq!(e.confidence(), 1000);
    }

    #[test]
    fn evidence_does_not_change_state() {
        let mut t = forced();
        t.observe(&c2s(0, 1, 5000));
        let probe = c2s(5 * SEC, 1, 6000);
        let first = t.evidence(&probe);
        for _ in 0..3 {
            assert_eq!(t.evidence(&probe), first);
        }
    }

    // --- policies -------------------------------------------------------

    #[test]
    fn forced_always_takes_the_best_choice() {
        let mut t = forced();
        let a = t.observe(&c2s(0, 1, 5000));
        // Same address, a second later: a handover link beats "new".
        let moved = t.observe(&c2s(SEC, 1, 6000));
        assert_eq!(moved.verdict, Verdict::Link);
        assert_eq!(moved.track, a.track);
        assert_eq!(moved.reason, Reason::Handover);
        assert_eq!(moved.guess, None);
        // Another address: "new" outweighs every candidate.
        let elsewhere = t.observe(&c2s(2 * SEC, 9, 7000));
        assert_eq!(elsewhere.verdict, Verdict::New);
        // A tuple silent far past the half-life: "new".
        let stale = t.observe(&c2s(200 * SEC, 9, 7000));
        assert_eq!(stale.verdict, Verdict::New);
        assert_ne!(stale.track, elsewhere.track);
    }

    #[test]
    fn abstain_declines_below_its_threshold_and_reports_the_forced_choice() {
        let mut t = abstain(800);
        let a = t.observe(&c2s(0, 1, 5000));
        let moved = t.observe(&c2s(SEC, 1, 6000));
        assert_eq!(moved.verdict, Verdict::Uncertain);
        assert_eq!(moved.guess, Some(Guess::Link(a.track)));
        assert_eq!(moved.reason, Reason::Handover);
        assert!(moved.confidence < 800);
        assert_ne!(moved.track, a.track);

        // What follows on the new tuple links to the provisional track.
        let next = t.observe(&c2s(SEC + MS, 1, 6000));
        assert_eq!(next.verdict, Verdict::Link);
        assert_eq!(next.track, moved.track);
    }

    #[test]
    fn abstain_is_confident_on_hard_evidence() {
        let mut t = abstain(990);
        let start = t.observe(&c2s(0, 1, 5000).initial(0xA0));
        assert_eq!(start.verdict, Verdict::New);
        let data = t.observe(&c2s(50 * MS, 1, 5000).dcid(7));
        assert_eq!(data.verdict, Verdict::Link);
        let rebound = t.observe(&c2s(40 * SEC, 2, 6000).dcid(7));
        assert_eq!(rebound.verdict, Verdict::Link);
        assert_eq!(rebound.track, start.track);
    }

    #[test]
    fn the_threshold_sets_how_long_a_silent_tuple_is_trusted() {
        // Score after 10 s of silence is 750.
        let run = |threshold| {
            let mut t = abstain(threshold);
            t.observe(&c2s(0, 1, 5000));
            t.observe(&c2s(10 * SEC, 1, 5000)).verdict
        };
        assert_eq!(run(750), Verdict::Link);
        assert_eq!(run(751), Verdict::Uncertain);
    }

    #[test]
    fn a_zero_threshold_never_abstains() {
        let mut a = abstain(0);
        let mut f = forced();
        for i in 0..200u64 {
            let obs = c2s(i * 3 * SEC, (i % 4) as u8 + 1, 5000 + (i % 7) as u16);
            let (da, df) = (a.observe(&obs), f.observe(&obs));
            assert_eq!(da, df, "observation {i}");
            assert_ne!(da.verdict, Verdict::Uncertain);
        }
    }

    #[test]
    fn both_policies_see_identical_evidence_from_identical_state() {
        // Drive an abstaining tracker. Before every observation, ask what a
        // forced tracker holding exactly the same state would compute.
        let mut tracker = abstain(800);
        let mut abstentions = 0;
        for i in 0..300u64 {
            let obs = c2s(i * 2 * SEC, (i % 5) as u8 + 1, 5000 + (i % 9) as u16);
            let evidence = tracker.evidence(&obs);

            let as_forced = tracker.with_policy(Policy::Forced);
            assert_eq!(as_forced.evidence(&obs), evidence, "observation {i}");
            tracker = as_forced.with_policy(Policy::Abstain {
                threshold_per_mille: 800,
            });

            let decision = tracker.observe(&obs);
            assert_eq!(decision.confidence, evidence.confidence());
            assert_eq!(decision.reason, evidence.kind);
            // The policy only decides whether to commit to the best choice.
            let best = evidence.best().target;
            match decision.verdict {
                Verdict::Uncertain => {
                    abstentions += 1;
                    assert!(decision.confidence < 800);
                    let guess = match best {
                        Target::Link(id) => Guess::Link(id),
                        Target::New => Guess::New,
                    };
                    assert_eq!(decision.guess, Some(guess));
                }
                Verdict::Link => assert_eq!(best, Target::Link(decision.track)),
                Verdict::New => assert_eq!(best, Target::New),
            }
        }
        assert!(abstentions > 0);
    }

    #[test]
    fn every_new_or_uncertain_decision_opens_a_fresh_track() {
        for mut t in [forced(), abstain(800)] {
            let mut opened = std::collections::BTreeSet::new();
            for i in 0..120u64 {
                let obs = c2s(i * 4 * SEC, (i % 3) as u8 + 1, 5000 + (i % 11) as u16);
                let d = t.observe(&obs);
                match d.verdict {
                    Verdict::Link => assert!(opened.contains(&d.track)),
                    Verdict::New | Verdict::Uncertain => assert!(opened.insert(d.track)),
                }
                assert_eq!(d.guess.is_some(), d.verdict == Verdict::Uncertain);
            }
        }
    }
}
