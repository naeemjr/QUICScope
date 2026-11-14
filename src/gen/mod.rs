//! Deterministic synthetic trace generation.
//!
//! A trace is a pure function of its arguments. No clock, no network, no
//! files: the same arguments always give the same events.

mod observer;
mod scenarios;
mod world;

use serde::Serialize;

use crate::model::{labelled_enum, Event, Observation};
use crate::rng::{mix, SplitMix64};

/// Default number of units (a connection, or a small constructed group of
/// connections) generated per scenario.
pub const DEFAULT_SCALE: u32 = 30;

labelled_enum! {
    /// The scenario families of the benchmark.
    pub enum Scenario {
        Ordinary => "ordinary",
        NatRebinding => "nat-rebinding",
        Migration => "migration",
        PathChange => "path-change",
        AddressReuse => "address-reuse",
        PacketLoss => "packet-loss",
        PartialObservation => "partial-observation",
        DelayedObservation => "delayed-observation",
        Overlapping => "overlapping",
        Ambiguous => "ambiguous",
    }
}

impl Scenario {
    pub fn description(self) -> &'static str {
        match self {
            Scenario::Ordinary => {
                "Sessions on a stable 4-tuple with short pauses, fully observed."
            }
            Scenario::NatRebinding => {
                "A NAT changes the client port or address mid-connection; connection IDs are kept."
            }
            Scenario::Migration => {
                "The client moves to a new address and both sides switch to fresh connection IDs."
            }
            Scenario::PathChange => {
                "The route changes under an unchanged 4-tuple: an outage, a TTL shift, sometimes a rotated connection ID."
            }
            Scenario::AddressReuse => {
                "A new connection starts on a 4-tuple an earlier one used, mixed with connections that merely went quiet."
            }
            Scenario::PacketLoss => {
                "Ordinary, rebinding, and tuple-reuse traffic with the monitor dropping 20% of packets."
            }
            Scenario::PartialObservation => {
                "Each connection is seen one way only, or from mid-stream, or with connection IDs cut off."
            }
            Scenario::DelayedObservation => {
                "Records reach the tracker late and out of order, with tuples reused quickly."
            }
            Scenario::Overlapping => {
                "Many concurrent connections from three NAT addresses to two servers, some rebinding or migrating."
            }
            Scenario::Ambiguous => {
                "Constructed cases: twin path changes, path changes beside an unseen newcomer, long-silent tuples."
            }
        }
    }

    fn index(self) -> u64 {
        Scenario::ALL.iter().position(|s| *s == self).unwrap_or(0) as u64
    }
}

/// Knobs of the controlled family used by the exploratory sweeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ControlledParams {
    /// Chance, in thousandths, that the monitor drops a packet.
    pub loss_per_mille: u32,
    /// Chance, in thousandths, that a connection's handshake is unseen.
    pub hidden_handshake_per_mille: u32,
    /// Chance, in thousandths, that a unit is a tuple-reuse pair.
    pub reuse_per_mille: u32,
    /// Range of the gap before a 4-tuple is reused, microseconds.
    pub reuse_gap_us: (u64, u64),
    /// Range of the silence before a rebinding or migration, microseconds.
    pub path_change_quiet_us: (u64, u64),
}

impl Default for ControlledParams {
    fn default() -> Self {
        Self {
            loss_per_mille: 0,
            hidden_handshake_per_mille: 150,
            reuse_per_mille: 200,
            reuse_gap_us: (2_000_000, 90_000_000),
            path_change_quiet_us: (2_000_000, 25_000_000),
        }
    }
}

/// Label of traces from the controlled family.
pub const CONTROLLED_FAMILY: &str = "controlled";

/// A generated trace: events in the order the tracker receives them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Trace {
    /// Scenario family name.
    pub family: String,
    pub seed: u64,
    pub scale: u32,
    /// Ground-truth connections put on the wire.
    pub connections: u32,
    /// Packets put on the wire, before the monitor's view was applied.
    pub wire_events: usize,
    pub events: Vec<Event>,
}

impl Trace {
    /// What the tracker and the oracle are given: the observations alone.
    pub fn observations(&self) -> Vec<Observation> {
        self.events.iter().map(|e| e.observed).collect()
    }
}

fn finish(
    family: &str,
    seed: u64,
    scale: u32,
    mut world: world::World,
    model: observer::ObserverModel,
) -> Trace {
    let connections = world.views.len() as u32;
    let wire_events = world.wire.len();
    let events = observer::observe(world.wire, &world.views, &model, &mut world.rng);
    Trace {
        family: family.to_string(),
        seed,
        scale,
        connections,
        wire_events,
        events,
    }
}

/// Generate the trace for one scenario family.
pub fn generate(scenario: Scenario, seed: u64, scale: u32) -> Trace {
    // Each scenario draws from its own stream, so adding or removing a
    // scenario never changes another scenario's trace.
    let rng = SplitMix64::new(mix(seed, scenario.index()));
    let mut world = world::World::new(rng);
    let model = scenarios::build(scenario, scale, &mut world);
    finish(scenario.as_str(), seed, scale, world, model)
}

/// Generate a trace of the controlled family. Its random stream is
/// separate from every scenario family's.
pub fn generate_controlled(params: &ControlledParams, seed: u64, scale: u32) -> Trace {
    let rng = SplitMix64::new(mix(seed, 1_000));
    let mut world = world::World::new(rng);
    let model = scenarios::controlled(&mut world, scale, params);
    finish(CONTROLLED_FAMILY, seed, scale, world, model)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Cause, Direction, HeaderForm};
    use crate::simmodel::MIN_TUPLE_REUSE_GAP_US;
    use std::collections::{BTreeMap, BTreeSet};

    fn trace(scenario: Scenario) -> Trace {
        generate(scenario, 1, 20)
    }

    fn causes(trace: &Trace) -> BTreeSet<Cause> {
        trace.events.iter().map(|e| e.truth.cause).collect()
    }

    #[test]
    fn generation_is_a_pure_function_of_its_arguments() {
        for &scenario in Scenario::ALL {
            assert_eq!(generate(scenario, 7, 12), generate(scenario, 7, 12));
            assert_ne!(
                generate(scenario, 7, 12).events,
                generate(scenario, 8, 12).events,
                "{scenario}"
            );
        }
        let p = ControlledParams::default();
        assert_eq!(generate_controlled(&p, 3, 8), generate_controlled(&p, 3, 8));
    }

    #[test]
    fn scenarios_draw_from_independent_streams() {
        let a = generate(Scenario::Ordinary, 1, 10);
        let b = generate(Scenario::NatRebinding, 1, 10);
        assert_ne!(a.events[0].observed.src, b.events[0].observed.src);
    }

    #[test]
    fn every_scenario_produces_a_well_formed_trace() {
        for &scenario in Scenario::ALL {
            let trace = trace(scenario);
            assert_eq!(trace.family, scenario.as_str());
            assert!(trace.connections >= 20, "{scenario}");
            assert!(!trace.events.is_empty(), "{scenario}");
            assert!(trace.events.len() <= trace.wire_events, "{scenario}");
            assert_eq!(trace.observations().len(), trace.events.len());
            assert!(trace
                .events
                .iter()
                .enumerate()
                .all(|(i, e)| e.seq == i as u64));

            // Delivery order is capture time plus lag.
            assert!(
                trace.events.windows(2).all(|w| {
                    w[0].observed.timestamp_us + w[0].observed.quality.lag_us
                        <= w[1].observed.timestamp_us + w[1].observed.quality.lag_us
                }),
                "{scenario}"
            );
            assert!(!scenario.description().is_empty());
        }
    }

    #[test]
    fn every_address_is_from_a_documentation_range() {
        let mut traces: Vec<Trace> = Scenario::ALL.iter().map(|s| trace(*s)).collect();
        traces.push(generate_controlled(&ControlledParams::default(), 1, 20));
        for trace in &traces {
            for event in &trace.events {
                let obs = &event.observed;
                assert!(
                    obs.src.addr.is_documentation(),
                    "{}: {}",
                    trace.family,
                    obs.src
                );
                assert!(
                    obs.dst.addr.is_documentation(),
                    "{}: {}",
                    trace.family,
                    obs.dst
                );
                assert_eq!(obs.server().port, 443);
            }
        }
    }

    #[test]
    fn segments_only_move_forward_on_the_wire() {
        for &scenario in Scenario::ALL {
            let mut events = trace(scenario).events;
            events.sort_by_key(|e| e.truth.wire_time_us);
            let mut last: BTreeMap<u32, u16> = BTreeMap::new();
            for event in events {
                let previous = last.insert(event.truth.connection, event.truth.segment);
                assert!(previous.unwrap_or(0) <= event.truth.segment, "{scenario}");
            }
        }
    }

    #[test]
    fn ordinary_sessions_never_change_path() {
        let trace = trace(Scenario::Ordinary);
        assert_eq!(causes(&trace), BTreeSet::from([Cause::Start]));
        assert_eq!(trace.events.len(), trace.wire_events);
        assert!(trace
            .events
            .iter()
            .all(|e| e.observed.quality == Default::default()));
    }

    #[test]
    fn each_family_contains_the_transition_it_is_named_for() {
        let expect = [
            (Scenario::NatRebinding, Cause::NatRebind),
            (Scenario::Migration, Cause::Migration),
            (Scenario::PathChange, Cause::PathChange),
            (Scenario::PathChange, Cause::CidRotation),
            (Scenario::AddressReuse, Cause::StartOnReusedTuple),
            (Scenario::Overlapping, Cause::NatRebind),
            (Scenario::Overlapping, Cause::Migration),
            (Scenario::Ambiguous, Cause::NatRebind),
            (Scenario::Ambiguous, Cause::Migration),
            (Scenario::Ambiguous, Cause::StartOnReusedTuple),
        ];
        for (scenario, cause) in expect {
            assert!(
                causes(&trace(scenario)).contains(&cause),
                "{scenario} lacks {cause}"
            );
        }
    }

    #[test]
    fn reused_tuples_carry_two_connections_no_sooner_than_the_model_allows() {
        for scenario in [
            Scenario::AddressReuse,
            Scenario::PacketLoss,
            Scenario::DelayedObservation,
            Scenario::Ambiguous,
        ] {
            let trace = generate(scenario, 3, 30);
            let mut by_flow: BTreeMap<_, BTreeMap<u32, (u64, u64)>> = BTreeMap::new();
            for event in &trace.events {
                let t = event.truth.wire_time_us;
                let span = by_flow
                    .entry(event.observed.flow())
                    .or_default()
                    .entry(event.truth.connection)
                    .or_insert((t, t));
                span.0 = span.0.min(t);
                span.1 = span.1.max(t);
            }
            let mut reused = 0;
            for spans in by_flow.values() {
                assert!(spans.len() <= 2, "{scenario}");
                if let [a, b] = spans.values().collect::<Vec<_>>()[..] {
                    reused += 1;
                    let (first, second) = if a.0 < b.0 { (a, b) } else { (b, a) };
                    assert!(second.0 >= first.1 + MIN_TUPLE_REUSE_GAP_US, "{scenario}");
                }
            }
            assert!(reused > 0, "{scenario}");
        }
    }

    #[test]
    fn connection_ids_are_never_shared_between_connections() {
        for &scenario in Scenario::ALL {
            let mut owners: BTreeMap<_, BTreeSet<u32>> = BTreeMap::new();
            for event in &trace(scenario).events {
                for cid in event.observed.cids() {
                    owners
                        .entry((event.observed.server(), cid))
                        .or_default()
                        .insert(event.truth.connection);
                }
            }
            assert!(owners.values().all(|c| c.len() == 1), "{scenario}");
        }
    }

    #[test]
    fn packet_loss_drops_records_and_flags_gaps() {
        let trace = trace(Scenario::PacketLoss);
        let kept = trace.events.len() as f64 / trace.wire_events as f64;
        assert!((0.7..0.9).contains(&kept), "kept {kept}");
        assert!(trace.events.iter().any(|e| e.observed.quality.capture_gap));
    }

    #[test]
    fn partial_observation_includes_every_kind_of_restriction() {
        let trace = trace(Scenario::PartialObservation);
        let mut directions: BTreeMap<u32, BTreeSet<Direction>> = BTreeMap::new();
        let mut headers: BTreeMap<u32, BTreeSet<HeaderForm>> = BTreeMap::new();
        for event in &trace.events {
            let transport = event.observed.transport;
            directions
                .entry(event.truth.connection)
                .or_default()
                .insert(transport.direction);
            headers
                .entry(event.truth.connection)
                .or_default()
                .insert(transport.header);
        }
        let one_way = directions.values().filter(|d| d.len() == 1).count();
        let no_handshake = headers
            .values()
            .filter(|h| !h.contains(&HeaderForm::Long))
            .count();
        assert!(one_way >= 8, "one-way connections: {one_way}");
        assert!(no_handshake >= 3, "mid-stream connections: {no_handshake}");
        assert!(trace.events.iter().any(|e| e.observed.quality.truncated));
        // None of this is capture loss, so nothing is flagged as a gap.
        assert!(trace.events.iter().all(|e| !e.observed.quality.capture_gap));
    }

    #[test]
    fn delayed_observation_reorders_records() {
        let trace = trace(Scenario::DelayedObservation);
        assert_eq!(trace.events.len(), trace.wire_events);
        assert!(trace
            .events
            .windows(2)
            .any(|w| w[0].observed.timestamp_us > w[1].observed.timestamp_us));
        assert!(trace
            .events
            .iter()
            .any(|e| e.observed.quality.lag_us > 500_000));
    }

    #[test]
    fn overlapping_connections_share_a_few_client_addresses() {
        let trace = trace(Scenario::Overlapping);
        let mut first: BTreeMap<u32, &Event> = BTreeMap::new();
        for event in &trace.events {
            first.entry(event.truth.connection).or_insert(event);
        }
        let origins: BTreeSet<_> = first
            .values()
            .filter(|e| e.truth.segment == 0)
            .map(|e| e.observed.client().addr)
            .collect();
        assert!(origins.len() <= 3, "{origins:?}");
    }

    #[test]
    fn scale_controls_the_number_of_connections() {
        let small = generate(Scenario::Ordinary, 1, 5);
        let large = generate(Scenario::Ordinary, 1, 50);
        assert_eq!(small.connections, 5);
        assert_eq!(large.connections, 50);
    }

    #[test]
    fn controlled_knobs_change_what_is_generated() {
        let base = ControlledParams::default();
        let trace = |p: &ControlledParams| generate_controlled(p, 5, 40);
        assert_eq!(trace(&base).family, CONTROLLED_FAMILY);

        let lossy = ControlledParams {
            loss_per_mille: 300,
            ..base
        };
        assert!(trace(&lossy).events.len() < trace(&base).events.len());

        let reuse_heavy = ControlledParams {
            reuse_per_mille: 900,
            ..base
        };
        let reused = |t: &Trace| {
            t.events
                .iter()
                .filter(|e| e.truth.cause == Cause::StartOnReusedTuple)
                .map(|e| e.truth.connection)
                .collect::<BTreeSet<_>>()
                .len()
        };
        assert!(reused(&trace(&reuse_heavy)) > reused(&trace(&base)));

        let long_headers = |t: &Trace| {
            t.events
                .iter()
                .filter(|e| e.observed.transport.header == HeaderForm::Long)
                .count()
        };
        let all_hidden = ControlledParams {
            hidden_handshake_per_mille: 1000,
            reuse_per_mille: 0,
            ..base
        };
        assert_eq!(long_headers(&trace(&all_hidden)), 0);
        let none_hidden = ControlledParams {
            hidden_handshake_per_mille: 0,
            ..base
        };
        assert!(long_headers(&trace(&none_hidden)) > 0);
    }
}
