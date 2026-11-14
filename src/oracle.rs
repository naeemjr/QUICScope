//! The ambiguity oracle. Evaluation only.
//!
//! # Definition
//!
//! A *history* of a sequence of observations is an assignment of each
//! observation to a connection. A history is *consistent* if the declared
//! simulator model ([`crate::simmodel`]) admits it: some run of the
//! simulator could have produced exactly these observations with exactly
//! that assignment.
//!
//! The decision at an observation is **observationally ambiguous** if there
//! are two consistent histories that agree on every earlier observation and
//! assign this one differently. It is **determined** if every consistent
//! history of the earlier observations can be extended in exactly one way.
//!
//! # What the oracle reads
//!
//! Only [`Observation`]s, in delivery order, and the constants of the
//! declared model. It reads **no ground truth**, so two traces with the
//! same observations always get the same labels. It imports nothing from
//! [`crate::tracker`] and uses no tracker threshold, score, or state.
//!
//! # How it decides
//!
//! Observations are grouped into *components* that the model forces to be
//! one connection: a shared connection ID toward one server (M5), or the
//! same 4-tuple with capture times closer than the minimum reuse gap, or
//! enclosed by such a component on that tuple (M7).
//!
//! An observation with nothing on its 4-tuple within the minimum reuse gap
//! is an **association opportunity**: the start of a run the monitor has to
//! place. It is then one of:
//!
//! * [`Label::DeterminedLink`]: forced into an earlier component;
//! * [`Label::DeterminedNew`]: no earlier component could be the same
//!   connection, so it can only be new to the monitor;
//! * [`Label::Ambiguous`]: it may be new (an unseen handshake is always
//!   possible, M8) and it may also continue at least one earlier component.
//!
//! "Could be the same connection" is decided by [`block_consistent`], the
//! per-connection rules M1 to M4, after pulling in every component the
//! merge would enclose on a shared tuple.
//!
//! # Completeness
//!
//! For the model as formalised here the labels are exact for traces of any
//! length; `docs/METHODOLOGY.md` gives the argument. [`exhaustive`]
//! enumerates every history outright and is used by the tests to check the
//! labels on sequences of up to [`exhaustive::MAX_OBSERVATIONS`]
//! observations. The model itself over-approximates the generator, so
//! `Ambiguous` is an upper bound: see [`crate::simmodel`].

use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::model::{
    labelled_enum, Cid, Direction, Endpoint, FlowKey, HeaderForm, Observation, PacketType,
};
use crate::simmodel::{HANDSHAKE_SPAN_MAX_US, MIN_TUPLE_REUSE_GAP_US};

labelled_enum! {
    pub enum Label {
        /// Not an association opportunity: the 4-tuple was active within
        /// the minimum reuse gap, so the model forces continuity.
        Routine => "routine",
        /// An opportunity the model forces into an earlier component.
        DeterminedLink => "determined-link",
        /// An opportunity that can only be new to the monitor.
        DeterminedNew => "determined-new",
        /// An opportunity with at least two consistent explanations.
        Ambiguous => "ambiguous",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Annotation {
    /// Whether this observation starts a run the monitor has to place.
    pub opportunity: bool,
    pub label: Label,
    /// Explanations found: 1 when determined, otherwise 1 (new) plus the
    /// number of earlier components it could continue.
    pub hypotheses: u32,
}

impl Annotation {
    pub fn is_ambiguous(&self) -> bool {
        self.label == Label::Ambiguous
    }
}

const GAP: u64 = MIN_TUPLE_REUSE_GAP_US;

/// What a packet shows about M4: whether the server-issued ID is non-empty
/// and whether the client-issued ID is non-empty.
fn mode_evidence(o: &Observation) -> (Option<bool>, Option<bool>) {
    if o.quality.truncated {
        return (None, None);
    }
    let dcid = Some(o.dcid.is_some());
    let scid = Some(o.scid.is_some());
    use Direction::{ClientToServer as Up, ServerToClient as Down};
    match (o.transport.direction, o.transport.header) {
        (Up, HeaderForm::Short) => (dcid, None),
        (Down, HeaderForm::Short) => (None, dcid),
        // A client Initial is addressed to an ID the client made up.
        (Up, HeaderForm::Long) if o.transport.packet_type == PacketType::Initial => (None, scid),
        (Up, HeaderForm::Long) => (dcid, scid),
        (Down, HeaderForm::Long) => (scid, dcid),
    }
}

fn agree(seen: &mut Option<bool>, now: Option<bool>) -> bool {
    match (*seen, now) {
        (Some(a), Some(b)) => a == b,
        (None, Some(_)) => {
            *seen = now;
            true
        }
        _ => true,
    }
}

/// Could these observations all belong to one connection? Rules M1 to M4.
///
/// Every rule is hereditary: a subset of a consistent block is consistent.
pub fn block_consistent(block: &[&Observation]) -> bool {
    let Some(first) = block.first() else {
        return true;
    };

    // M1: one server.
    let server = first.server();
    if block.iter().any(|o| o.server() != server) {
        return false;
    }

    // M4: connection-ID modes never change.
    let (mut server_mode, mut client_mode) = (None, None);
    for o in block {
        let (s, c) = mode_evidence(o);
        if !agree(&mut server_mode, s) || !agree(&mut client_mode, c) {
            return false;
        }
    }

    // M2: one client endpoint at a time, never revisited.
    let mut spans: BTreeMap<Endpoint, (u64, u64)> = BTreeMap::new();
    for o in block {
        let t = o.timestamp_us;
        let span = spans.entry(o.client()).or_insert((t, t));
        span.0 = span.0.min(t);
        span.1 = span.1.max(t);
    }
    let mut ordered: Vec<(u64, u64)> = spans.into_values().collect();
    ordered.sort_unstable();
    if ordered.windows(2).any(|w| w[0].1 >= w[1].0) {
        return false;
    }

    // M3: the handshake is on one tuple, short, and precedes all data.
    let long: Vec<&&Observation> = block
        .iter()
        .filter(|o| o.transport.header == HeaderForm::Long)
        .collect();
    if let Some(any) = long.first() {
        let flow = any.flow();
        let start = long.iter().map(|o| o.timestamp_us).min().unwrap_or(0);
        let end = long.iter().map(|o| o.timestamp_us).max().unwrap_or(0);
        if long.iter().any(|o| o.flow() != flow) || end - start > HANDSHAKE_SPAN_MAX_US {
            return false;
        }
        let early_data = block
            .iter()
            .any(|o| o.transport.header == HeaderForm::Short && o.timestamp_us < end);
        if early_data {
            return false;
        }
    }
    true
}

/// The observations delivered so far, grouped into forced components.
struct Prefix<'a> {
    obs: &'a [Observation],
    parent: Vec<usize>,
    /// Members of each component, valid at its root.
    members: Vec<Vec<usize>>,
    first_with_cid: HashMap<(Endpoint, Cid), usize>,
    on_flow: HashMap<FlowKey, BTreeSet<(u64, usize)>>,
    toward: HashMap<Endpoint, Vec<usize>>,
}

impl<'a> Prefix<'a> {
    fn new(obs: &'a [Observation]) -> Self {
        Self {
            obs,
            parent: Vec::new(),
            members: Vec::new(),
            first_with_cid: HashMap::new(),
            on_flow: HashMap::new(),
            toward: HashMap::new(),
        }
    }

    fn root(&self, mut i: usize) -> usize {
        while self.parent[i] != i {
            i = self.parent[i];
        }
        i
    }

    fn union(&mut self, a: usize, b: usize) -> usize {
        let (a, b) = (self.root(a), self.root(b));
        if a == b {
            return a;
        }
        let (keep, drop) = if self.members[a].len() >= self.members[b].len() {
            (a, b)
        } else {
            (b, a)
        };
        let moved = std::mem::take(&mut self.members[drop]);
        self.members[keep].extend(moved);
        self.parent[drop] = keep;
        keep
    }

    /// Delivered observations on `flow` captured strictly closer than the
    /// minimum reuse gap to the interval `[lo, hi]`.
    fn within_gap(&self, flow: &FlowKey, lo: u64, hi: u64) -> Vec<usize> {
        let Some(set) = self.on_flow.get(flow) else {
            return Vec::new();
        };
        let from = (lo.saturating_sub(GAP - 1), 0);
        let to = (hi + GAP - 1, usize::MAX);
        set.range(from..=to).map(|(_, i)| *i).collect()
    }

    fn spans(&self, members: impl Iterator<Item = usize>) -> BTreeMap<FlowKey, (u64, u64)> {
        let mut spans = BTreeMap::new();
        for i in members {
            let o = &self.obs[i];
            let t = o.timestamp_us;
            let span = spans.entry(o.flow()).or_insert((t, t));
            span.0 = span.0.min(t);
            span.1 = span.1.max(t);
        }
        spans
    }

    /// M7 closure: a component owns every observation on a tuple within the
    /// minimum reuse gap of its own span there. Repeat until nothing joins.
    fn absorb_enclosed(&mut self, start: usize) {
        loop {
            let root = self.root(start);
            let spans = self.spans(self.members[root].iter().copied());
            let outsiders: Vec<usize> = spans
                .iter()
                .flat_map(|(flow, (lo, hi))| self.within_gap(flow, *lo, *hi))
                .filter(|j| self.root(*j) != root)
                .collect();
            if outsiders.is_empty() {
                return;
            }
            for j in outsiders {
                self.union(root, j);
            }
        }
    }

    /// Would treating components `a` and `b` as one connection be
    /// consistent? Pull in everything the merge would enclose first.
    fn merge_is_consistent(&self, a: usize, b: usize) -> bool {
        let mut roots = BTreeSet::from([self.root(a), self.root(b)]);
        loop {
            let members = roots.iter().flat_map(|r| self.members[*r].iter().copied());
            let spans = self.spans(members);
            let enclosed: BTreeSet<usize> = spans
                .iter()
                .flat_map(|(flow, (lo, hi))| self.within_gap(flow, *lo, *hi))
                .map(|j| self.root(j))
                .filter(|r| !roots.contains(r))
                .collect();
            if enclosed.is_empty() {
                break;
            }
            roots.extend(enclosed);
        }
        let block: Vec<&Observation> = roots
            .iter()
            .flat_map(|r| self.members[*r].iter())
            .map(|i| &self.obs[*i])
            .collect();
        block_consistent(&block)
    }

    fn admit(&mut self, i: usize) -> Annotation {
        let observations: &'a [Observation] = self.obs;
        let o = &observations[i];
        let (flow, t, server) = (o.flow(), o.timestamp_us, o.server());

        let near = self.within_gap(&flow, t, t);
        let opportunity = near.is_empty();

        // On one tuple, components occupy disjoint stretches of time, so an
        // observation between two members of one component is enclosed.
        let set = self.on_flow.entry(flow).or_default();
        let before = set.range(..(t, 0)).next_back().map(|(_, j)| *j);
        let after = set.range((t, 0)..).next().map(|(_, j)| *j);
        set.insert((t, i));

        self.parent.push(i);
        self.members.push(vec![i]);
        self.toward.entry(server).or_default().push(i);

        for j in near {
            self.union(i, j);
        }
        if let (Some(b), Some(a)) = (before, after) {
            if self.root(b) == self.root(a) {
                self.union(i, b);
            }
        }
        for cid in o.cids() {
            match self.first_with_cid.get(&(server, cid)) {
                Some(j) => {
                    self.union(i, *j);
                }
                None => {
                    self.first_with_cid.insert((server, cid), i);
                }
            }
        }
        self.absorb_enclosed(i);

        let determined = |label| Annotation {
            opportunity,
            label,
            hypotheses: 1,
        };
        if !opportunity {
            return determined(Label::Routine);
        }
        let root = self.root(i);
        if self.members[root].len() > 1 {
            return determined(Label::DeterminedLink);
        }

        let others: BTreeSet<usize> = self.toward[&server]
            .iter()
            .map(|j| self.root(*j))
            .filter(|r| *r != root)
            .collect();
        let continuations = others
            .into_iter()
            .filter(|r| self.merge_is_consistent(root, *r))
            .count() as u32;
        if continuations == 0 {
            determined(Label::DeterminedNew)
        } else {
            Annotation {
                opportunity,
                label: Label::Ambiguous,
                hypotheses: 1 + continuations,
            }
        }
    }
}

/// Label every observation, in delivery order, from the observations
/// delivered up to and including it. The result is parallel to the input.
pub fn annotate(observations: &[Observation]) -> Vec<Annotation> {
    let mut prefix = Prefix::new(observations);
    (0..observations.len()).map(|i| prefix.admit(i)).collect()
}

/// The forced component of every observation once the whole sequence has
/// been delivered. Observations with equal values must be one connection.
/// Used by tests to check the forced links against ground truth.
pub fn forced_components(observations: &[Observation]) -> Vec<usize> {
    let mut prefix = Prefix::new(observations);
    for i in 0..observations.len() {
        prefix.admit(i);
    }
    (0..observations.len()).map(|i| prefix.root(i)).collect()
}

/// Exhaustive enumeration of histories, straight from the definition.
///
/// This is deliberately a separate, slower implementation: it considers
/// every way of partitioning the observations into connections and keeps
/// the ones the declared model admits. It exists to check [`annotate`].
pub mod exhaustive {
    use super::*;

    /// The enumerator refuses longer sequences. Ten observations have
    /// 115,975 partitions.
    pub const MAX_OBSERVATIONS: usize = 10;

    /// Marks "a connection of its own" among the placements of the last
    /// observation.
    pub const NEW: u8 = u8::MAX;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Enumeration {
        /// Consistent histories of the whole sequence.
        pub histories: u64,
        /// For each consistent history of the earlier observations, the
        /// ways the last observation can be placed: a block number, or
        /// [`NEW`].
        pub placements: BTreeMap<Vec<u8>, BTreeSet<u8>>,
    }

    impl Enumeration {
        /// Two consistent histories agree on the past and differ on the
        /// last observation.
        pub fn ambiguous(&self) -> bool {
            self.placements.values().any(|p| p.len() >= 2)
        }

        /// The label the definition assigns to the last observation, apart
        /// from the routine/opportunity distinction.
        pub fn label(&self) -> Label {
            if self.ambiguous() {
                Label::Ambiguous
            } else if self.placements.values().all(|p| p.contains(&NEW)) {
                Label::DeterminedNew
            } else {
                Label::DeterminedLink
            }
        }
    }

    /// M5 and M7, the rules that relate different connections.
    fn blocks_coexist(obs: &[Observation], blocks: &[Vec<usize>]) -> bool {
        let mut cid_block: HashMap<(Endpoint, Cid), usize> = HashMap::new();
        let mut spans: Vec<BTreeMap<FlowKey, (u64, u64)>> = Vec::new();
        for (b, block) in blocks.iter().enumerate() {
            let mut span = BTreeMap::new();
            for &i in block {
                let o = &obs[i];
                for cid in o.cids() {
                    if *cid_block.entry((o.server(), cid)).or_insert(b) != b {
                        return false;
                    }
                }
                let t = o.timestamp_us;
                let s = span.entry(o.flow()).or_insert((t, t));
                s.0 = s.0.min(t);
                s.1 = s.1.max(t);
            }
            spans.push(span);
        }
        for (b, span) in spans.iter().enumerate() {
            for other in &spans[b + 1..] {
                for (flow, (lo, hi)) in span {
                    if let Some((olo, ohi)) = other.get(flow) {
                        let apart = hi + GAP <= *olo || ohi + GAP <= *lo;
                        if !apart {
                            return false;
                        }
                    }
                }
            }
        }
        true
    }

    fn recurse(
        obs: &[Observation],
        next: usize,
        blocks: &mut Vec<Vec<usize>>,
        assignment: &mut Vec<u8>,
        out: &mut Enumeration,
    ) {
        if next == obs.len() {
            if blocks_coexist(obs, blocks) {
                out.histories += 1;
                let last = assignment[next - 1];
                let alone = blocks[last as usize].len() == 1;
                let past = assignment[..next - 1].to_vec();
                let placement = if alone { NEW } else { last };
                out.placements.entry(past).or_default().insert(placement);
            }
            return;
        }
        for b in 0..=blocks.len() {
            if b == blocks.len() {
                blocks.push(Vec::new());
            }
            blocks[b].push(next);
            let block: Vec<&Observation> = blocks[b].iter().map(|i| &obs[*i]).collect();
            if block_consistent(&block) {
                assignment.push(b as u8);
                recurse(obs, next + 1, blocks, assignment, out);
                assignment.pop();
            }
            blocks[b].pop();
            if blocks[b].is_empty() {
                blocks.pop();
            }
        }
    }

    /// Enumerate every consistent history and report how the last
    /// observation can be placed. `None` if the sequence is empty or longer
    /// than [`MAX_OBSERVATIONS`].
    pub fn enumerate(observations: &[Observation]) -> Option<Enumeration> {
        if observations.is_empty() || observations.len() > MAX_OBSERVATIONS {
            return None;
        }
        let mut out = Enumeration {
            histories: 0,
            placements: BTreeMap::new(),
        };
        recurse(observations, 0, &mut Vec::new(), &mut Vec::new(), &mut out);
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Addr;
    use crate::testkit::{c2s, s2c, ObsExt, MS, SEC};

    fn labels(obs: &[Observation]) -> Vec<Label> {
        annotate(obs).into_iter().map(|a| a.label).collect()
    }

    fn last(obs: &[Observation]) -> Annotation {
        *annotate(obs).last().unwrap()
    }

    /// The fast label of the last observation must match the definition.
    fn check_against_definition(obs: &[Observation]) -> Label {
        let fast = last(obs);
        let slow = exhaustive::enumerate(obs).expect("short enough");
        assert!(slow.histories > 0, "observations violate the model");
        assert_eq!(fast.is_ambiguous(), slow.ambiguous(), "{obs:#?}");
        if fast.label == Label::Routine {
            assert_eq!(slow.label(), Label::DeterminedLink);
        } else {
            assert_eq!(fast.label, slow.label());
        }
        fast.label
    }

    #[test]
    fn distinguishable_continuation_within_the_reuse_gap_is_routine() {
        let obs = [
            c2s(0, 1, 5000),
            s2c(20 * MS, 1, 5000),
            c2s(900 * MS, 1, 5000),
        ];
        assert_eq!(
            labels(&obs),
            [Label::DeterminedNew, Label::Routine, Label::Routine]
        );
        assert!(!annotate(&obs)[2].opportunity);
        check_against_definition(&obs);
    }

    #[test]
    fn distinguishable_continuation_by_connection_id_is_a_determined_link() {
        // Five seconds of silence, but the same ID toward the same server.
        let obs = [c2s(0, 1, 5000).dcid(7), c2s(5 * SEC, 1, 5000).dcid(7)];
        let a = last(&obs);
        assert!(a.opportunity);
        assert_eq!(a.label, Label::DeterminedLink);
        assert_eq!(a.hypotheses, 1);
        check_against_definition(&obs);
    }

    #[test]
    fn distinguishable_new_connection_by_handshake() {
        // A visible Initial on a tuple that has been quiet: only "new".
        let obs = [
            c2s(0, 1, 5000),
            c2s(5 * SEC, 1, 5000).initial(0xB0),
            s2c(5 * SEC + 20 * MS, 1, 5000),
        ];
        assert_eq!(
            labels(&obs),
            [Label::DeterminedNew, Label::DeterminedNew, Label::Routine]
        );
        check_against_definition(&obs[..2]);
        check_against_definition(&obs);
    }

    #[test]
    fn nat_rebinding_with_a_visible_id_is_determined() {
        let obs = [c2s(0, 1, 5000).dcid(7), c2s(10 * SEC, 2, 6000).dcid(7)];
        assert_eq!(last(&obs).label, Label::DeterminedLink);
        check_against_definition(&obs);
    }

    #[test]
    fn nat_rebinding_without_an_id_is_ambiguous() {
        let obs = [c2s(0, 1, 5000), c2s(10 * SEC, 1, 6000)];
        let a = last(&obs);
        assert_eq!(a.label, Label::Ambiguous);
        // New, or the continuation of the one earlier connection.
        assert_eq!(a.hypotheses, 2);
        assert_eq!(check_against_definition(&obs), Label::Ambiguous);
    }

    #[test]
    fn migration_to_fresh_ids_is_ambiguous() {
        let obs = [
            c2s(0, 1, 5000).dcid(7),
            c2s(SEC, 9, 7000).dcid(8),
            // Once the new path exists, what follows on it is forced.
            c2s(SEC + MS, 9, 7000).dcid(8),
        ];
        assert_eq!(
            labels(&obs),
            [Label::DeterminedNew, Label::Ambiguous, Label::Routine]
        );
        check_against_definition(&obs[..2]);
        check_against_definition(&obs);
    }

    #[test]
    fn unseen_handshake_makes_a_new_flow_ambiguous_when_a_candidate_exists() {
        // The second flow is really a new connection, but nothing visible
        // rules out its being the first one after a path change.
        let obs = [c2s(0, 1, 5000), c2s(3 * SEC, 2, 5000)];
        assert_eq!(check_against_definition(&obs), Label::Ambiguous);

        // With no earlier flow toward that server there is no candidate.
        let elsewhere = Endpoint {
            addr: Addr::new(192, 0, 2, 99),
            port: 443,
        };
        let obs = [c2s(0, 1, 5000), c2s(3 * SEC, 2, 5000).to(elsewhere)];
        assert_eq!(check_against_definition(&obs), Label::DeterminedNew);
    }

    #[test]
    fn tuple_reuse_after_the_minimum_gap_is_ambiguous_without_evidence() {
        // Same tuple, no ID, silent for longer than the reuse gap: the old
        // connection resuming and a new one are both consistent.
        let obs = [c2s(0, 1, 5000), c2s(2 * SEC, 1, 5000)];
        assert_eq!(check_against_definition(&obs), Label::Ambiguous);

        // The length of the silence does not matter to the definition.
        let obs = [c2s(0, 1, 5000), c2s(80 * SEC, 1, 5000)];
        assert_eq!(check_against_definition(&obs), Label::Ambiguous);
    }

    #[test]
    fn tuple_reuse_with_a_visible_handshake_is_determined_new() {
        let obs = [
            c2s(0, 1, 5000),
            c2s(2 * SEC, 1, 5000).initial(0xB0),
            // Later traffic on the tuple cannot be the first connection:
            // that would enclose the handshake inside it.
            c2s(6 * SEC, 1, 5000),
        ];
        check_against_definition(&obs[..2]);
        let a = last(&obs);
        assert_eq!(a.label, Label::Ambiguous);
        // New, or the second connection resuming. Not the first.
        assert_eq!(a.hypotheses, 2);
        check_against_definition(&obs);
    }

    #[test]
    fn partial_loss_can_split_a_burst_into_ambiguous_runs() {
        // Packets every 300 ms, then several lost: a 1.5 s hole.
        let obs = [
            c2s(0, 1, 5000),
            c2s(300 * MS, 1, 5000),
            c2s(1800 * MS, 1, 5000),
        ];
        assert_eq!(
            labels(&obs),
            [Label::DeterminedNew, Label::Routine, Label::Ambiguous]
        );
        check_against_definition(&obs);

        // With an ID on the packets the same hole is harmless.
        let obs = [
            c2s(0, 1, 5000).dcid(7),
            c2s(300 * MS, 1, 5000).dcid(7),
            c2s(1800 * MS, 1, 5000).dcid(7),
        ];
        assert_eq!(last(&obs).label, Label::DeterminedLink);
        check_against_definition(&obs);
    }

    #[test]
    fn control_a_concurrently_active_flow_is_not_a_candidate() {
        // A late record for flow A, captured after B started, shows A was
        // still on its own tuple: B cannot be A's continuation.
        let obs = [
            c2s(0, 1, 5000).dcid(1),
            c2s(5 * SEC, 1, 5000).dcid(1),
            c2s(3 * SEC, 2, 6000).dcid(2),
        ];
        assert_eq!(check_against_definition(&obs), Label::DeterminedNew);

        // Delivered in capture order instead, B arrives before A is seen
        // again, and at that moment it is ambiguous.
        let obs = [obs[0], obs[2]];
        assert_eq!(check_against_definition(&obs), Label::Ambiguous);
    }

    #[test]
    fn control_incompatible_id_modes_rule_out_continuation() {
        // The first connection visibly uses a server-issued ID; the new
        // flow visibly does not.
        let obs = [c2s(0, 1, 5000).dcid(7), c2s(3 * SEC, 2, 6000)];
        assert_eq!(check_against_definition(&obs), Label::DeterminedNew);

        // If the new flow's IDs were cut off, nothing is ruled out.
        let mut truncated = c2s(3 * SEC, 2, 6000);
        truncated.quality.truncated = true;
        let obs = [c2s(0, 1, 5000).dcid(7), truncated];
        assert_eq!(check_against_definition(&obs), Label::Ambiguous);
    }

    #[test]
    fn control_a_handshake_cannot_continue_an_older_connection() {
        let obs = [c2s(0, 1, 5000), c2s(3 * SEC, 2, 6000).initial(0xB0)];
        assert_eq!(check_against_definition(&obs), Label::DeterminedNew);
    }

    #[test]
    fn hypotheses_count_every_candidate() {
        let obs = [
            c2s(0, 1, 5000),
            c2s(0, 2, 5000),
            c2s(0, 3, 5000),
            c2s(5 * SEC, 4, 5000),
        ];
        // Each earlier flow is ambiguous against those before it; the last
        // could be new or continue any of the three.
        assert_eq!(last(&obs).hypotheses, 4);
        check_against_definition(&obs);
    }

    #[test]
    fn enclosure_forces_an_observation_between_two_linked_ones() {
        let obs = [
            c2s(0, 1, 5000).dcid(7),
            c2s(10 * SEC, 1, 5000).dcid(7),
            // Captured in between, delivered last, carries no ID.
            s2c(5 * SEC, 1, 5000),
        ];
        let a = last(&obs);
        assert!(a.opportunity);
        assert_eq!(a.label, Label::DeterminedLink);
        check_against_definition(&obs);
    }

    #[test]
    fn labels_depend_only_on_the_prefix() {
        let obs = [
            c2s(0, 1, 5000),
            c2s(10 * SEC, 1, 6000),
            c2s(11 * SEC, 1, 5000),
        ];
        let full = annotate(&obs);
        assert_eq!(full[..2], annotate(&obs[..2])[..]);
        // Hindsight (the old tuple is active again) does not relabel it.
        assert_eq!(full[1].label, Label::Ambiguous);
    }

    #[test]
    fn block_rules_are_checked_individually() {
        let a = c2s(0, 1, 5000);
        // M1: two servers.
        let elsewhere = Endpoint {
            addr: Addr::new(192, 0, 2, 99),
            port: 443,
        };
        assert!(!block_consistent(&[&a, &c2s(SEC, 1, 5000).to(elsewhere)]));
        // M2: two client endpoints at overlapping times.
        let b = [c2s(0, 1, 5000), c2s(2 * SEC, 1, 5000), c2s(SEC, 2, 6000)];
        assert!(!block_consistent(&[&b[0], &b[1], &b[2]]));
        assert!(block_consistent(&[&b[0], &b[2]]));
        // M3: data before the handshake ends; a handshake that is too long.
        let init = c2s(SEC, 1, 5000).initial(1);
        assert!(!block_consistent(&[&a, &init]));
        assert!(block_consistent(&[&init, &c2s(SEC + MS, 1, 5000)]));
        let slow = s2c(SEC + 200 * MS, 1, 5000).initial(2);
        assert!(!block_consistent(&[&init, &slow]));
        // M4: mode flip.
        assert!(!block_consistent(&[&a, &c2s(SEC, 1, 5000).dcid(3)]));
        assert!(block_consistent(&[]));
    }

    #[test]
    fn exhaustive_enumerator_respects_its_bound() {
        assert!(exhaustive::enumerate(&[]).is_none());
        let many: Vec<Observation> = (0..11).map(|i| c2s(i * 10 * SEC, 1, 5000)).collect();
        assert!(exhaustive::enumerate(&many).is_none());
        assert!(exhaustive::enumerate(&many[..10]).is_some());
    }

    #[test]
    fn exhaustive_enumerator_counts_histories() {
        // Two unrelated servers: exactly one history.
        let elsewhere = Endpoint {
            addr: Addr::new(192, 0, 2, 99),
            port: 443,
        };
        let obs = [c2s(0, 1, 5000), c2s(0, 2, 5000).to(elsewhere)];
        assert_eq!(exhaustive::enumerate(&obs).unwrap().histories, 1);
        // One flow, then a possible continuation: together or apart.
        let obs = [c2s(0, 1, 5000), c2s(5 * SEC, 1, 6000)];
        let e = exhaustive::enumerate(&obs).unwrap();
        assert_eq!(e.histories, 2);
        assert!(e.ambiguous());
    }

    #[test]
    fn forced_components_group_what_the_model_forces() {
        let obs = [
            c2s(0, 1, 5000).dcid(7),
            c2s(100 * MS, 1, 5000),
            c2s(9 * SEC, 2, 6000).dcid(7),
            c2s(9 * SEC, 3, 6000),
        ];
        let c = forced_components(&obs);
        assert_eq!(c[0], c[1]);
        assert_eq!(c[0], c[2]);
        assert_ne!(c[0], c[3]);
    }

    #[test]
    fn the_oracle_source_does_not_reference_any_tracker() {
        // Look at code only: skip comments, and the test module, which
        // names what it searches for.
        let source = include_str!("oracle.rs");
        let code: String = source
            .split("#[cfg(test)]")
            .next()
            .unwrap()
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        for forbidden in ["tracker", "Decision", "Truth", "truth", "threshold", "eval"] {
            assert!(
                !code.contains(forbidden),
                "oracle code mentions `{forbidden}`"
            );
        }
        assert!(code.contains("use crate::simmodel::"));
    }
}
