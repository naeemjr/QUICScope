//! The observer model: turns what was on the wire into what a monitor
//! recorded, and in what order it reached the tracker.

use crate::model::{Direction, Event, HeaderForm};
use crate::rng::SplitMix64;

use super::world::{Directions, View, Wire};

/// Capture conditions that apply to the whole vantage point.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct ObserverModel {
    /// Chance, in thousandths, that the monitor drops a packet it could see.
    pub loss_per_mille: u32,
    /// Every record is delivered after a uniform delay up to this long.
    pub max_lag_us: u64,
    /// Chance, in thousandths, that a record is held back much longer.
    pub burst_per_mille: u32,
    pub burst_lag_us: u64,
}

fn in_view(view: &View, wire: &Wire) -> bool {
    let direction_ok = match view.directions {
        Directions::Both => true,
        Directions::ClientToServer => {
            wire.observed.transport.direction == Direction::ClientToServer
        }
        Directions::ServerToClient => {
            wire.observed.transport.direction == Direction::ServerToClient
        }
    };
    direction_ok
        && wire.observed.timestamp_us >= view.visible_from_us
        && !(view.hide_handshake && wire.observed.transport.header == HeaderForm::Long)
}

/// Apply the per-connection views and the capture model, and return events
/// in delivery order.
pub(crate) fn observe(
    mut wire: Vec<Wire>,
    views: &[View],
    model: &ObserverModel,
    rng: &mut SplitMix64,
) -> Vec<Event> {
    // Wire order. The sort is stable, so packets a connection sent at the
    // same instant keep their emission order.
    wire.sort_by_key(|w| w.observed.timestamp_us);

    let mut dropped_since_last = false;
    let mut delivered: Vec<(u64, Event)> = Vec::with_capacity(wire.len());
    for w in wire {
        let view = &views[w.truth.connection as usize];
        // Outside the vantage point: the monitor does not know it exists,
        // so this is not capture loss.
        if !in_view(view, &w) {
            continue;
        }
        if rng.chance(model.loss_per_mille) {
            dropped_since_last = true;
            continue;
        }

        let mut observed = w.observed;
        if view.truncated {
            observed.dcid = None;
            observed.scid = None;
            observed.quality.truncated = true;
        }
        observed.quality.capture_gap = dropped_since_last;
        dropped_since_last = false;

        let mut lag = 0;
        if model.max_lag_us > 0 {
            lag += rng.below(model.max_lag_us + 1);
        }
        if rng.chance(model.burst_per_mille) {
            lag += rng.range(model.burst_lag_us / 4, model.burst_lag_us + 1);
        }
        observed.quality.lag_us = lag;

        let event = Event {
            seq: 0,
            observed,
            truth: w.truth,
        };
        delivered.push((observed.timestamp_us + lag, event));
    }

    delivered.sort_by_key(|(arrival, _)| *arrival);
    delivered
        .into_iter()
        .enumerate()
        .map(|(seq, (_, mut event))| {
            event.seq = seq as u64;
            event
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gen::world::{CidMode, ConnPlan, Step, World, MS, SEC};
    use crate::model::{Addr, Endpoint};

    fn world(view: View) -> World {
        let client = Endpoint {
            addr: Addr::new(198, 51, 100, 1),
            port: 5000,
        };
        let server = Endpoint {
            addr: Addr::new(192, 0, 2, 10),
            port: 443,
        };
        let mut plan = ConnPlan::new(client, server, SEC, CidMode::Both).steps(vec![Step::Send {
            packets: 40,
            gap_us: 20 * MS,
        }]);
        plan.view = view;
        let mut world = World::new(SplitMix64::new(5));
        world.emit(&plan);
        world
    }

    fn run(view: View, model: ObserverModel) -> (usize, Vec<Event>) {
        let world = world(view);
        let wire_len = world.wire.len();
        let mut rng = SplitMix64::new(11);
        (
            wire_len,
            observe(world.wire, &world.views, &model, &mut rng),
        )
    }

    #[test]
    fn a_perfect_observer_sees_everything_in_wire_order() {
        let (wire_len, events) = run(View::default(), ObserverModel::default());
        assert_eq!(events.len(), wire_len);
        assert!(events
            .windows(2)
            .all(|w| w[0].observed.timestamp_us <= w[1].observed.timestamp_us));
        assert!(events.iter().enumerate().all(|(i, e)| e.seq == i as u64));
        assert!(events
            .iter()
            .all(|e| e.observed.quality == Default::default()));
    }

    #[test]
    fn loss_drops_records_and_flags_the_next_one() {
        let model = ObserverModel {
            loss_per_mille: 300,
            ..Default::default()
        };
        let (wire_len, events) = run(View::default(), model);
        assert!(events.len() < wire_len);
        assert!(events.len() > wire_len / 3);
        let flagged = events
            .iter()
            .filter(|e| e.observed.quality.capture_gap)
            .count();
        assert!(flagged > 0);
        // Each flag accounts for at least one drop.
        assert!(flagged <= wire_len - events.len());
    }

    #[test]
    fn one_way_views_keep_a_single_direction_without_flagging_loss() {
        let view = View {
            directions: Directions::ServerToClient,
            ..Default::default()
        };
        let (wire_len, events) = run(view, ObserverModel::default());
        assert!(events.len() < wire_len);
        assert!(events
            .iter()
            .all(|e| e.observed.transport.direction == Direction::ServerToClient));
        assert!(events.iter().all(|e| !e.observed.quality.capture_gap));
    }

    #[test]
    fn hidden_handshake_and_late_start_remove_the_long_headers() {
        let hidden = View {
            hide_handshake: true,
            ..Default::default()
        };
        let (_, events) = run(hidden, ObserverModel::default());
        assert!(events
            .iter()
            .all(|e| e.observed.transport.header == HeaderForm::Short));

        let late = View {
            visible_from_us: SEC + 300 * MS,
            ..Default::default()
        };
        let (_, events) = run(late, ObserverModel::default());
        assert!(!events.is_empty());
        assert!(events
            .iter()
            .all(|e| e.observed.timestamp_us >= SEC + 300 * MS));
    }

    #[test]
    fn truncation_hides_ids_and_says_so() {
        let view = View {
            truncated: true,
            ..Default::default()
        };
        let (_, events) = run(view, ObserverModel::default());
        assert!(events.iter().all(|e| e.observed.cids().count() == 0));
        assert!(events.iter().all(|e| e.observed.quality.truncated));
    }

    #[test]
    fn lag_reorders_delivery_but_not_timestamps() {
        let model = ObserverModel {
            max_lag_us: 200 * MS,
            ..Default::default()
        };
        let (wire_len, events) = run(View::default(), model);
        assert_eq!(events.len(), wire_len);
        // Delivery order is by capture time plus lag...
        assert!(events.windows(2).all(|w| {
            w[0].observed.timestamp_us + w[0].observed.quality.lag_us
                <= w[1].observed.timestamp_us + w[1].observed.quality.lag_us
        }));
        // ...so capture timestamps are no longer monotonic.
        assert!(events
            .windows(2)
            .any(|w| w[0].observed.timestamp_us > w[1].observed.timestamp_us));
        // The capture timestamp itself is untouched.
        assert!(events
            .iter()
            .all(|e| e.observed.timestamp_us == e.truth.wire_time_us));
    }
}
