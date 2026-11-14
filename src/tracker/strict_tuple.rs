//! Baseline: classic flow-table tracking on the 4-tuple.

use std::collections::HashMap;

use crate::basis::{Field, FieldSet};
use crate::model::{FlowKey, Observation};

use super::{Decision, Reason, TrackId, Tracker, Verdict, STRICT_TUPLE};

/// One track per 4-tuple, expired after an idle timeout. It reads no QUIC
/// field at all, so it cannot follow a connection to a new address and
/// cannot tell a new connection from an old one on a reused tuple. It
/// always decides, with full confidence.
pub struct StrictTuple {
    idle_us: u64,
    flows: HashMap<FlowKey, (TrackId, u64)>,
    next: u32,
}

impl StrictTuple {
    pub fn new(idle_us: u64) -> Self {
        Self {
            idle_us,
            flows: HashMap::new(),
            next: 0,
        }
    }
}

impl Tracker for StrictTuple {
    fn name(&self) -> &'static str {
        STRICT_TUPLE
    }

    fn observe(&mut self, obs: &Observation) -> Decision {
        let basis = FieldSet::of(&[
            Field::ClientAddr,
            Field::ClientPort,
            Field::ServerEndpoint,
            Field::Timing,
        ]);
        let now = obs.timestamp_us;
        let existing = self.flows.get(&obs.flow()).copied();
        if let Some((track, last_seen)) = existing {
            if now.saturating_sub(last_seen) <= self.idle_us {
                self.flows.insert(obs.flow(), (track, last_seen.max(now)));
                return Decision {
                    verdict: Verdict::Link,
                    track,
                    basis,
                    reason: Reason::TupleMatch,
                    confidence: 1000,
                    guess: None,
                };
            }
        }
        let track = TrackId(self.next);
        self.next += 1;
        self.flows.insert(obs.flow(), (track, now));
        let reason = if existing.is_some() {
            Reason::IdleTimeout
        } else {
            Reason::NewTuple
        };
        Decision {
            verdict: Verdict::New,
            track,
            basis,
            reason,
            confidence: 1000,
            guess: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{c2s, s2c, ObsExt, MS, SEC};

    fn tracker() -> StrictTuple {
        StrictTuple::new(30 * SEC)
    }

    #[test]
    fn both_directions_of_a_tuple_share_a_track() {
        let mut t = tracker();
        let first = t.observe(&c2s(0, 1, 5000));
        let reply = t.observe(&s2c(10 * MS, 1, 5000));
        assert_eq!(first.verdict, Verdict::New);
        assert_eq!(reply.verdict, Verdict::Link);
        assert_eq!(reply.track, first.track);
    }

    #[test]
    fn a_new_tuple_is_always_a_new_track_even_with_a_known_cid() {
        let mut t = tracker();
        let before = t.observe(&c2s(0, 1, 5000).dcid(7));
        let after = t.observe(&c2s(SEC, 1, 6000).dcid(7));
        assert_eq!(after.verdict, Verdict::New);
        assert_ne!(after.track, before.track);
    }

    #[test]
    fn a_reused_tuple_within_the_timeout_is_merged_even_on_an_initial() {
        let mut t = tracker();
        let old = t.observe(&c2s(0, 1, 5000));
        let reuse = t.observe(&c2s(5 * SEC, 1, 5000).initial(9));
        assert_eq!(reuse.verdict, Verdict::Link);
        assert_eq!(reuse.track, old.track);
    }

    #[test]
    fn the_idle_timeout_splits_a_quiet_tuple() {
        let mut t = tracker();
        let old = t.observe(&c2s(0, 1, 5000));
        let at_limit = t.observe(&c2s(30 * SEC, 1, 5000));
        assert_eq!(at_limit.track, old.track);
        let later = t.observe(&c2s(61 * SEC, 1, 5000));
        assert_eq!(later.verdict, Verdict::New);
        assert_eq!(later.reason, Reason::IdleTimeout);
    }

    #[test]
    fn a_late_record_does_not_expire_or_rewind_the_flow() {
        let mut t = tracker();
        let first = t.observe(&c2s(40 * SEC, 1, 5000));
        let late = t.observe(&c2s(SEC, 1, 5000));
        assert_eq!(late.track, first.track);
        let next = t.observe(&c2s(69 * SEC, 1, 5000));
        assert_eq!(next.track, first.track);
    }

    #[test]
    fn never_abstains_and_never_reads_quic_fields() {
        let mut t = tracker();
        for i in 0..50u64 {
            let d = t.observe(&c2s(i * SEC * 7, (i % 5) as u8 + 1, 5000));
            assert_ne!(d.verdict, Verdict::Uncertain);
            assert_eq!(d.confidence, 1000);
            assert!(!d.basis.contains(Field::ConnectionId));
            assert!(!d.basis.contains(Field::Handshake));
            assert!(!d.basis.contains(Field::CrossFlow));
        }
    }
}
