//! The tracker interface and the three comparison methods.
//!
//! A tracker is fed [`Observation`]s one at a time, in the order the monitor
//! received them, and answers each with a [`Decision`]. It is never given
//! ground truth, scenario names, or oracle labels: the signature of
//! [`Tracker::observe`] makes that a property of the types.
//!
//! The methods:
//!
//! * `strict-tuple`: tuple-only baseline.
//! * `continuity-forced` and `continuity-abstain`: one evidence computation
//!   ([`Continuity::evidence`]) and two final policies. See [`continuity`].

pub mod continuity;
mod strict_tuple;
mod table;

use crate::basis::FieldSet;
use crate::error::Error;
use crate::model::{labelled_enum, Observation};

pub use continuity::{Continuity, Policy};
pub use strict_tuple::StrictTuple;

/// A tracker's handle for one of its own tracks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TrackId(pub u32);

labelled_enum! {
    pub enum Verdict {
        /// Confident: this observation belongs to an existing track.
        Link => "link",
        /// Confident: this observation starts a connection not seen before.
        New => "new",
        /// The evidence does not support a confident decision. The
        /// observation is filed under a fresh provisional track, and no
        /// claim is made about how that track relates to earlier ones.
        Uncertain => "uncertain",
    }
}

labelled_enum! {
    /// The kind of evidence a decision rested on.
    pub enum Reason {
        /// A connection ID already filed under a track.
        CidMatch => "cid-match",
        /// A long-header packet with no known connection ID.
        HandshakeStart => "handshake-start",
        /// A long-header packet on a tuple whose handshake just began.
        HandshakeContinuation => "handshake-continuation",
        /// The 4-tuple has a track; scored by how long it was silent.
        TupleContinuity => "tuple-continuity",
        /// The record predates the track now holding its tuple.
        Reordered => "reordered",
        /// A new tuple scored against existing tracks to the same server.
        Handover => "handover",
        /// A new tuple toward a server with no tracks at all.
        Isolated => "isolated",
        /// `strict-tuple`: the tuple has a live track.
        TupleMatch => "tuple-match",
        /// `strict-tuple`: the tuple's track timed out.
        IdleTimeout => "idle-timeout",
        /// `strict-tuple`: a tuple not seen before.
        NewTuple => "new-tuple",
    }
}

/// What an abstaining tracker would have answered if forced to choose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Guess {
    Link(TrackId),
    New,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decision {
    pub verdict: Verdict,
    /// The track the observation is filed under: an existing one for
    /// `Link`, a fresh one for `New` and `Uncertain`.
    pub track: TrackId,
    /// The metadata this decision depended on.
    pub basis: FieldSet,
    pub reason: Reason,
    /// Score of the best-supported choice, in thousandths.
    pub confidence: u16,
    /// For `Uncertain` only: the forced choice.
    pub guess: Option<Guess>,
}

pub trait Tracker {
    /// Stable identifier used on the command line and in reports.
    fn name(&self) -> &'static str;

    /// Process one observation and say which track it belongs to.
    ///
    /// Contract: a `Link` must name a track this tracker opened earlier; a
    /// `New` or `Uncertain` must name a track id not used before.
    fn observe(&mut self, obs: &Observation) -> Decision;
}

/// Flow-table idle timeout of the `strict-tuple` baseline.
pub const STRICT_IDLE_US: u64 = 30_000_000;

/// A method and its parameters. A fresh instance is built for every trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Spec {
    StrictTuple,
    ContinuityForced,
    ContinuityAbstain { threshold_per_mille: u16 },
}

pub const STRICT_TUPLE: &str = "strict-tuple";
pub const CONTINUITY_FORCED: &str = "continuity-forced";
pub const CONTINUITY_ABSTAIN: &str = "continuity-abstain";

impl Spec {
    /// The three methods, with the abstention threshold given.
    pub fn all(threshold_per_mille: u16) -> [Spec; 3] {
        [
            Spec::StrictTuple,
            Spec::ContinuityForced,
            Spec::ContinuityAbstain {
                threshold_per_mille,
            },
        ]
    }

    pub fn parse(name: &str, threshold_per_mille: u16) -> Result<Spec, Error> {
        if let Some(spec) = Spec::all(threshold_per_mille)
            .into_iter()
            .find(|s| s.name() == name)
        {
            return Ok(spec);
        }
        // Names from the preliminary version. Their implementations were
        // different, so they are not accepted as aliases.
        let replacement = match name {
            "continuity" => Some(CONTINUITY_FORCED),
            "abstain" => Some(CONTINUITY_ABSTAIN),
            _ => None,
        };
        Err(match replacement {
            Some(replacement) => Error::RetiredTracker {
                name: name.to_string(),
                replacement,
            },
            None => Error::UnknownTracker(name.to_string()),
        })
    }

    pub fn name(&self) -> &'static str {
        match self {
            Spec::StrictTuple => STRICT_TUPLE,
            Spec::ContinuityForced => CONTINUITY_FORCED,
            Spec::ContinuityAbstain { .. } => CONTINUITY_ABSTAIN,
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Spec::StrictTuple => {
                "one track per 4-tuple with a 30 s idle timeout; reads no QUIC field; always decides"
            }
            Spec::ContinuityForced => {
                "scores continuity evidence (connection ID, handshake, tuple silence, handover) and always takes the best-scoring choice"
            }
            Spec::ContinuityAbstain { .. } => {
                "same evidence and scores as continuity-forced; returns uncertain when the best score is below the threshold"
            }
        }
    }

    /// The abstention threshold, for the method that has one.
    pub fn threshold_per_mille(&self) -> Option<u16> {
        match self {
            Spec::ContinuityAbstain {
                threshold_per_mille,
            } => Some(*threshold_per_mille),
            _ => None,
        }
    }

    pub fn build(&self) -> Box<dyn Tracker> {
        match *self {
            Spec::StrictTuple => Box::new(StrictTuple::new(STRICT_IDLE_US)),
            Spec::ContinuityForced => Box::new(Continuity::new(Policy::Forced)),
            Spec::ContinuityAbstain {
                threshold_per_mille,
            } => Box::new(Continuity::new(Policy::Abstain {
                threshold_per_mille,
            })),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exactly_three_methods_with_stable_names() {
        let specs = Spec::all(800);
        let names: Vec<&str> = specs.iter().map(Spec::name).collect();
        assert_eq!(
            names,
            ["strict-tuple", "continuity-forced", "continuity-abstain"]
        );
        for spec in &specs {
            assert_eq!(spec.build().name(), spec.name());
            assert!(!spec.description().is_empty());
            assert_eq!(Spec::parse(spec.name(), 800), Ok(*spec));
        }
        assert_eq!(specs[2].threshold_per_mille(), Some(800));
        assert_eq!(specs[1].threshold_per_mille(), None);
    }

    #[test]
    fn preliminary_names_are_rejected_with_a_pointer_to_their_successor() {
        assert_eq!(
            Spec::parse("abstain", 800),
            Err(Error::RetiredTracker {
                name: "abstain".into(),
                replacement: CONTINUITY_ABSTAIN,
            })
        );
        assert!(matches!(
            Spec::parse("continuity", 800),
            Err(Error::RetiredTracker { .. })
        ));
        assert_eq!(
            Spec::parse("psychic", 800),
            Err(Error::UnknownTracker("psychic".into()))
        );
    }

    #[test]
    fn tracker_sources_do_not_reference_truth_or_the_oracle() {
        let sources = [
            include_str!("mod.rs"),
            include_str!("continuity.rs"),
            include_str!("strict_tuple.rs"),
            include_str!("table.rs"),
        ];
        for source in sources {
            let code: String = source
                .split("#[cfg(test)]")
                .next()
                .unwrap()
                .lines()
                .filter(|line| !line.trim_start().starts_with("//"))
                .collect::<Vec<_>>()
                .join("\n");
            for forbidden in ["oracle", "simmodel", "Truth", "Event", "eval", "gen::"] {
                assert!(
                    !code.contains(forbidden),
                    "tracker code mentions `{forbidden}`"
                );
            }
        }
    }
}
