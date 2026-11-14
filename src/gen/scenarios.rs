//! The scenario families. Each builds a set of connection plans, puts them
//! on the wire, and says how the monitor observes them.
//!
//! Every construction here must stay inside the declared simulator model
//! ([`crate::simmodel`]); `tests/model_soundness.rs` checks that it does.

use crate::model::{Addr, Endpoint};
use crate::simmodel::MIN_TUPLE_REUSE_GAP_US;

use super::observer::ObserverModel;
use super::world::{CidMode, ConnPlan, Directions, Step, World, MS, SEC};
use super::{ControlledParams, Scenario};

fn server(index: u64) -> Endpoint {
    Endpoint {
        addr: Addr::new(192, 0, 2, 10 + index as u8),
        port: 443,
    }
}

/// Client address pools, both from the documentation ranges.
fn client_addr(pool: u8, host: u8) -> Addr {
    match pool {
        0 => Addr::new(198, 51, 100, host),
        _ => Addr::new(203, 0, 113, host),
    }
}

fn pool_of(addr: Addr) -> u8 {
    u8::from(addr.octets()[0] != 198)
}

fn random_addr(w: &mut World, pool: u8) -> Addr {
    client_addr(pool, w.rng.range(1, 251) as u8)
}

fn random_client(w: &mut World) -> Endpoint {
    let addr = random_addr(w, 0);
    w.client_on(addr)
}

fn random_cids(w: &mut World) -> CidMode {
    match w.rng.below(20) {
        0..=5 => CidMode::Both,
        6..=14 => CidMode::ServerOnly,
        _ => CidMode::None,
    }
}

fn send(w: &mut World, lo: u64, hi: u64) -> Step {
    Step::Send {
        packets: w.rng.range(lo, hi) as u32,
        gap_us: w.rng.range(20 * MS, 200 * MS),
    }
}

fn idle(w: &mut World, lo: u64, hi: u64) -> Step {
    Step::Idle(w.rng.range(lo, hi))
}

fn ordinary_steps(w: &mut World) -> Vec<Step> {
    vec![send(w, 20, 40), idle(w, SEC / 2, 5 * SEC), send(w, 10, 20)]
}

/// Where a NAT puts the client next: usually a new port on the same
/// address, sometimes another address from the same pool.
fn rebound(w: &mut World, client: Endpoint) -> Endpoint {
    let addr = if w.rng.chance(700) {
        client.addr
    } else {
        random_addr(w, pool_of(client.addr))
    };
    w.client_on(addr)
}

fn rebinding_steps(w: &mut World, client: Endpoint, quiet: (u64, u64)) -> Vec<Step> {
    let first = rebound(w, client);
    let mut steps = vec![
        send(w, 15, 30),
        idle(w, quiet.0, quiet.1),
        Step::Rebind(first),
        send(w, 15, 30),
    ];
    if w.rng.chance(300) {
        let second = rebound(w, first);
        steps.extend([
            idle(w, quiet.0, quiet.1),
            Step::Rebind(second),
            send(w, 10, 20),
        ]);
    }
    steps
}

fn migration_steps(w: &mut World, client: Endpoint, quiet: (u64, u64)) -> Vec<Step> {
    let addr = random_addr(w, 1 - pool_of(client.addr));
    let target = w.client_on(addr);
    vec![
        send(w, 15, 30),
        idle(w, quiet.0, quiet.1),
        Step::Migrate(target),
        send(w, 15, 30),
    ]
}

const REBIND_QUIET: (u64, u64) = (2 * SEC, 25 * SEC);
const MIGRATION_QUIET: (u64, u64) = (100 * MS, 2 * SEC);

/// A connection, then a different one on the same 4-tuple after `gap`.
fn reuse_pair(
    w: &mut World,
    client: Endpoint,
    start: u64,
    server: Endpoint,
    gap: (u64, u64),
    cids: Option<CidMode>,
    hide_second_handshake: bool,
) {
    // Model rule M7: a tuple is never reused sooner than this.
    assert!(gap.0 >= MIN_TUPLE_REUSE_GAP_US, "reuse gap below the model");
    let first_cids = cids.unwrap_or_else(|| random_cids(w));
    let steps = vec![send(w, 15, 30)];
    let first = ConnPlan::new(client, server, start, first_cids).steps(steps);
    let ended = w.emit(&first).end_us;

    let second_cids = cids.unwrap_or_else(|| random_cids(w));
    let restart = ended + w.rng.range(gap.0, gap.1);
    let steps = vec![send(w, 15, 30)];
    let mut second = ConnPlan::new(client, server, restart, second_cids).steps(steps);
    second.reuses_tuple = true;
    second.view.hide_handshake = hide_second_handshake;
    w.emit(&second);
}

fn start_time(w: &mut World) -> u64 {
    w.rng.below(60 * SEC)
}

fn ordinary(w: &mut World, scale: u32) {
    for _ in 0..scale {
        let client = random_client(w);
        let server = server(w.rng.below(4));
        let (start, cids) = (start_time(w), random_cids(w));
        let steps = ordinary_steps(w);
        w.emit(&ConnPlan::new(client, server, start, cids).steps(steps));
    }
}

fn nat_rebinding(w: &mut World, scale: u32) {
    for _ in 0..scale {
        let client = random_client(w);
        let server = server(w.rng.below(4));
        let (start, cids) = (start_time(w), random_cids(w));
        let steps = rebinding_steps(w, client, REBIND_QUIET);
        w.emit(&ConnPlan::new(client, server, start, cids).steps(steps));
    }
}

fn migration(w: &mut World, scale: u32) {
    for _ in 0..scale {
        let client = random_client(w);
        let server = server(w.rng.below(4));
        let (start, cids) = (start_time(w), random_cids(w));
        let steps = migration_steps(w, client, MIGRATION_QUIET);
        w.emit(&ConnPlan::new(client, server, start, cids).steps(steps));
    }
}

fn path_change(w: &mut World, scale: u32) {
    for _ in 0..scale {
        let client = random_client(w);
        let server = server(w.rng.below(4));
        let (start, cids) = (start_time(w), random_cids(w));
        let magnitude = w.rng.range(1, 6) as i8;
        let change = Step::PathChange {
            outage_us: w.rng.range(SEC / 2, 8 * SEC),
            ttl_shift: if w.rng.chance(500) {
                magnitude
            } else {
                -magnitude
            },
            rotate: w.rng.chance(500),
        };
        let mut steps = vec![send(w, 15, 30), change, send(w, 15, 30)];
        if w.rng.chance(250) {
            steps.extend([Step::Rotate, send(w, 10, 15)]);
        }
        w.emit(&ConnPlan::new(client, server, start, cids).steps(steps));
    }
}

/// One connection that simply goes quiet for a long time and resumes. Its
/// idle gaps are drawn from the same range as the tuple-reuse gaps, so the
/// length of a silence alone does not reveal which case it is.
fn long_idle(w: &mut World, start: u64, server: Endpoint, cids: CidMode) {
    let client = random_client(w);
    let steps = vec![send(w, 10, 20), idle(w, 2 * SEC, 90 * SEC), send(w, 10, 20)];
    w.emit(&ConnPlan::new(client, server, start, cids).steps(steps));
}

fn address_reuse(w: &mut World, scale: u32) {
    for i in 0..scale {
        let server = server(w.rng.below(4));
        let start = start_time(w);
        if i % 3 == 2 {
            let cids = random_cids(w);
            long_idle(w, start, server, cids);
        } else {
            let hide = w.rng.chance(500);
            let client = random_client(w);
            reuse_pair(w, client, start, server, (2 * SEC, 90 * SEC), None, hide);
        }
    }
}

fn mixed_unit(w: &mut World, reuse_gap: (u64, u64)) {
    let server = server(w.rng.below(4));
    let start = start_time(w);
    let client = random_client(w);
    match w.rng.below(10) {
        0..=3 => {
            let cids = random_cids(w);
            let steps = ordinary_steps(w);
            w.emit(&ConnPlan::new(client, server, start, cids).steps(steps));
        }
        4..=6 => {
            let cids = random_cids(w);
            let steps = rebinding_steps(w, client, REBIND_QUIET);
            w.emit(&ConnPlan::new(client, server, start, cids).steps(steps));
        }
        _ => reuse_pair(w, client, start, server, reuse_gap, None, false),
    }
}

fn packet_loss(w: &mut World, scale: u32) -> ObserverModel {
    for _ in 0..scale {
        mixed_unit(w, (2 * SEC, 90 * SEC));
    }
    ObserverModel {
        loss_per_mille: 200,
        ..Default::default()
    }
}

fn partial_observation(w: &mut World, scale: u32) {
    for i in 0..scale {
        let client = random_client(w);
        // Two servers only, so that unanchored flows have candidates.
        let server = server(w.rng.below(2));
        let (start, cids) = (start_time(w), random_cids(w));
        let steps = match w.rng.below(4) {
            0 | 1 => ordinary_steps(w),
            2 => rebinding_steps(w, client, REBIND_QUIET),
            _ => migration_steps(w, client, MIGRATION_QUIET),
        };
        let mut plan = ConnPlan::new(client, server, start, cids).steps(steps);
        match i % 4 {
            0 => plan.view.directions = Directions::ClientToServer,
            1 => plan.view.directions = Directions::ServerToClient,
            2 => plan.view.visible_from_us = start + w.rng.range(SEC / 2, 3 * SEC),
            _ => plan.view.truncated = true,
        }
        w.emit(&plan);
    }
}

fn delayed_observation(w: &mut World, scale: u32) -> ObserverModel {
    for _ in 0..scale {
        // Tuples are reused as quickly as the model allows, so a delayed
        // record can arrive after the next connection has started.
        mixed_unit(w, (SEC, 4 * SEC));
    }
    ObserverModel {
        max_lag_us: 150 * MS,
        burst_per_mille: 50,
        burst_lag_us: 2 * SEC,
        ..Default::default()
    }
}

/// Many concurrent connections from three NAT addresses to two servers.
fn overlapping(w: &mut World, scale: u32) {
    for _ in 0..scale {
        let addr = client_addr(0, 1 + w.rng.below(3) as u8);
        let client = w.client_on(addr);
        let server = server(w.rng.below(2));
        let start = w.rng.below(20 * SEC);
        let cids = random_cids(w);
        let steps = match w.rng.below(10) {
            0..=4 => vec![send(w, 30, 60)],
            5..=7 => {
                let next = w.client_on(addr);
                vec![
                    send(w, 15, 30),
                    idle(w, SEC, 5 * SEC),
                    Step::Rebind(next),
                    send(w, 15, 30),
                ]
            }
            _ => migration_steps(w, client, MIGRATION_QUIET),
        };
        let mut plan = ConnPlan::new(client, server, start, cids).steps(steps);
        plan.view.hide_handshake = w.rng.chance(150);
        w.emit(&plan);
    }
}

/// Two zero-length-ID connections behind one NAT address whose ports are
/// rebound at nearly the same moment, as after a NAT restart.
fn twin_rebinding(w: &mut World, start: u64, server: Endpoint) {
    let addr = random_addr(w, 0);
    let (packets, gap_us) = (w.rng.range(15, 25) as u32, w.rng.range(40 * MS, 120 * MS));
    let quiet = w.rng.range(3 * SEC, 6 * SEC);
    for twin in 0..2 {
        let client = w.client_on(addr);
        let next = w.client_on(addr);
        let steps = vec![
            Step::Send { packets, gap_us },
            Step::Idle(quiet),
            Step::Rebind(next),
            Step::Send { packets, gap_us },
        ];
        let plan = ConnPlan::new(client, server, start + twin * 50 * MS, CidMode::None);
        w.emit(&plan.steps(steps));
    }
}

/// Two connections behind one NAT address that both migrate, with fresh
/// connection IDs, at nearly the same moment.
fn twin_migration(w: &mut World, start: u64, server: Endpoint) {
    let addr = random_addr(w, 0);
    let (packets, gap_us) = (w.rng.range(15, 25) as u32, w.rng.range(40 * MS, 120 * MS));
    for twin in 0..2 {
        let client = w.client_on(addr);
        let target_addr = random_addr(w, 1);
        let target = w.client_on(target_addr);
        let steps = vec![
            Step::Send { packets, gap_us },
            Step::Idle(SEC),
            Step::Migrate(target),
            Step::Send { packets, gap_us },
        ];
        let plan = ConnPlan::new(client, server, start + twin * 50 * MS, CidMode::Both);
        w.emit(&plan.steps(steps));
    }
}

/// A connection changes path while a new connection, whose handshake the
/// monitor missed, starts toward the same server at about the same time.
/// With `migrate`, the mover takes fresh connection IDs to another address;
/// otherwise it is a zero-length-ID connection rebound on its own address.
fn path_change_with_newcomer(w: &mut World, start: u64, server: Endpoint, migrate: bool) {
    let addr = random_addr(w, 0);
    let client = w.client_on(addr);
    let (packets, gap_us) = (20, 50 * MS);
    let quiet = 3 * SEC;
    let (cids, change, newcomer_addr) = if migrate {
        let target_addr = random_addr(w, 1);
        let target = w.client_on(target_addr);
        (CidMode::Both, Step::Migrate(target), target_addr)
    } else {
        let next = w.client_on(addr);
        (CidMode::None, Step::Rebind(next), addr)
    };
    let steps = vec![
        Step::Send { packets, gap_us },
        Step::Idle(quiet),
        change,
        Step::Send { packets, gap_us },
    ];
    w.emit(&ConnPlan::new(client, server, start, cids).steps(steps));

    let moved_at = start + u64::from(packets) * gap_us + quiet;
    let newcomer_start = moved_at - 200 * MS + w.rng.below(400 * MS);
    let newcomer = w.client_on(newcomer_addr);
    let steps = vec![Step::Send { packets, gap_us }];
    let mut plan = ConnPlan::new(newcomer, server, newcomer_start, cids).steps(steps);
    plan.view.hide_handshake = true;
    w.emit(&plan);
}

/// A long silence on a zero-length-ID tuple, followed either by the same
/// connection resuming or by a new one whose handshake the monitor missed.
fn stale_tuple(w: &mut World, start: u64, server: Endpoint) {
    if w.rng.chance(500) {
        let client = random_client(w);
        let steps = vec![
            send(w, 10, 20),
            idle(w, 40 * SEC, 90 * SEC),
            send(w, 10, 20),
        ];
        w.emit(&ConnPlan::new(client, server, start, CidMode::None).steps(steps));
    } else {
        let gap = (40 * SEC, 90 * SEC);
        let client = random_client(w);
        reuse_pair(w, client, start, server, gap, Some(CidMode::None), true);
    }
}

fn ambiguous(w: &mut World, scale: u32) {
    for i in 0..scale {
        let server = server(w.rng.below(2));
        let start = start_time(w);
        match i % 5 {
            0 => twin_rebinding(w, start, server),
            1 => twin_migration(w, start, server),
            2 => path_change_with_newcomer(w, start, server, false),
            3 => path_change_with_newcomer(w, start, server, true),
            _ => stale_tuple(w, start, server),
        }
    }
}

/// The parameterised family used only for exploratory sweeps: plain,
/// rebinding, migrating, and tuple-reusing connections from six NAT
/// addresses to two servers, with every knob set by `p`.
pub(crate) fn controlled(w: &mut World, scale: u32, p: &ControlledParams) -> ObserverModel {
    for _ in 0..scale {
        let addr = client_addr(0, 1 + w.rng.below(6) as u8);
        let client = w.client_on(addr);
        let server = server(w.rng.below(2));
        let start = start_time(w);
        let hide = w.rng.chance(p.hidden_handshake_per_mille);
        if w.rng.chance(p.reuse_per_mille) {
            reuse_pair(w, client, start, server, p.reuse_gap_us, None, hide);
            continue;
        }
        let cids = random_cids(w);
        let steps = match w.rng.below(20) {
            0..=7 => ordinary_steps(w),
            8..=14 => rebinding_steps(w, client, p.path_change_quiet_us),
            _ => migration_steps(w, client, p.path_change_quiet_us),
        };
        let mut plan = ConnPlan::new(client, server, start, cids).steps(steps);
        plan.view.hide_handshake = hide;
        w.emit(&plan);
    }
    ObserverModel {
        loss_per_mille: p.loss_per_mille,
        ..Default::default()
    }
}

/// Emit every connection of `scenario` into `w` and return how the monitor
/// observes them.
pub(crate) fn build(scenario: Scenario, scale: u32, w: &mut World) -> ObserverModel {
    match scenario {
        Scenario::Ordinary => ordinary(w, scale),
        Scenario::NatRebinding => nat_rebinding(w, scale),
        Scenario::Migration => migration(w, scale),
        Scenario::PathChange => path_change(w, scale),
        Scenario::AddressReuse => address_reuse(w, scale),
        Scenario::PacketLoss => return packet_loss(w, scale),
        Scenario::PartialObservation => partial_observation(w, scale),
        Scenario::DelayedObservation => return delayed_observation(w, scale),
        Scenario::Overlapping => overlapping(w, scale),
        Scenario::Ambiguous => ambiguous(w, scale),
    }
    ObserverModel::default()
}
