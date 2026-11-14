//! The wire model: what synthetic connections put on the network, with
//! ground truth attached. Nothing here decides what a monitor gets to see;
//! that is [`super::observer`].

use std::collections::BTreeSet;

use crate::model::{
    Addr, Cause, Cid, Direction, Endpoint, HeaderForm, Observation, PacketType, Quality, Transport,
    Truth,
};
use crate::rng::SplitMix64;

pub(crate) const MS: u64 = 1_000;
pub(crate) const SEC: u64 = 1_000_000;

/// Which connection IDs are non-empty, and so visible, on a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CidMode {
    /// Both endpoints issue connection IDs.
    Both,
    /// Only the server issues one, so server-to-client packets carry none.
    ServerOnly,
    /// Both use zero-length connection IDs: only the 4-tuple identifies.
    None,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum Step {
    /// Exchange `packets` 1-RTT packets, alternating direction.
    Send {
        packets: u32,
        gap_us: u64,
    },
    Idle(u64),
    /// NAT rebinding: the client address changes, connection IDs do not.
    Rebind(Endpoint),
    /// Deliberate migration: new client address and fresh connection IDs.
    Migrate(Endpoint),
    /// Route change on the same 4-tuple: an outage, a TTL shift, and
    /// optionally a new server-issued connection ID.
    PathChange {
        outage_us: u64,
        ttl_shift: i8,
        rotate: bool,
    },
    /// Switch to a new server-issued connection ID on the same path.
    Rotate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Directions {
    #[default]
    Both,
    ClientToServer,
    ServerToClient,
}

/// Per-connection limits on what the monitor's vantage point can see.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct View {
    pub directions: Directions,
    /// Captures are cut short before the connection IDs.
    pub truncated: bool,
    /// The monitor sees nothing of this connection before this time.
    pub visible_from_us: u64,
    /// The handshake happened where the monitor could not see it.
    pub hide_handshake: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct ConnPlan {
    pub client: Endpoint,
    pub server: Endpoint,
    pub start_us: u64,
    pub cids: CidMode,
    pub steps: Vec<Step>,
    /// The 4-tuple was used by an earlier connection.
    pub reuses_tuple: bool,
    pub view: View,
}

impl ConnPlan {
    pub fn new(client: Endpoint, server: Endpoint, start_us: u64, cids: CidMode) -> Self {
        Self {
            client,
            server,
            start_us,
            cids,
            steps: Vec::new(),
            reuses_tuple: false,
            view: View::default(),
        }
    }

    pub fn steps(mut self, steps: Vec<Step>) -> Self {
        self.steps = steps;
        self
    }
}

/// One packet on the wire, before the monitor's view is applied.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Wire {
    pub observed: Observation,
    pub truth: Truth,
}

pub(crate) struct Emitted {
    pub end_us: u64,
}

pub(crate) struct World {
    pub rng: SplitMix64,
    pub wire: Vec<Wire>,
    pub views: Vec<View>,
    used_cids: BTreeSet<u64>,
    used_clients: BTreeSet<Endpoint>,
}

/// The mutable state of one connection while it is being emitted.
struct Live {
    connection: u32,
    client: Endpoint,
    server: Endpoint,
    /// Server-issued ID: the destination ID of client-to-server packets.
    server_cid: Option<Cid>,
    /// Client-issued ID: the destination ID of server-to-client packets.
    client_cid: Option<Cid>,
    ttl_c2s: u8,
    ttl_s2c: u8,
    segment: u16,
    cause: Cause,
}

impl Live {
    fn packet(
        &self,
        t: u64,
        direction: Direction,
        header: HeaderForm,
        packet_type: PacketType,
        ids: (Option<Cid>, Option<Cid>),
        size: u16,
    ) -> Wire {
        let (src, dst, ttl) = match direction {
            Direction::ClientToServer => (self.client, self.server, self.ttl_c2s),
            Direction::ServerToClient => (self.server, self.client, self.ttl_s2c),
        };
        Wire {
            observed: Observation {
                timestamp_us: t,
                src,
                dst,
                transport: Transport {
                    direction,
                    header,
                    packet_type,
                    version: (header == HeaderForm::Long).then_some(1),
                    size,
                    ttl,
                },
                dcid: ids.0,
                scid: ids.1,
                quality: Quality::default(),
            },
            truth: Truth {
                connection: self.connection,
                segment: self.segment,
                cause: self.cause,
                wire_time_us: t,
            },
        }
    }

    fn short(&self, t: u64, direction: Direction, size: u16) -> Wire {
        let dcid = match direction {
            Direction::ClientToServer => self.server_cid,
            Direction::ServerToClient => self.client_cid,
        };
        self.packet(
            t,
            direction,
            HeaderForm::Short,
            PacketType::OneRtt,
            (dcid, None),
            size,
        )
    }
}

fn shift_ttl(ttl: u8, shift: i8) -> u8 {
    ttl.saturating_add_signed(shift).max(1)
}

impl World {
    pub fn new(rng: SplitMix64) -> Self {
        Self {
            rng,
            wire: Vec::new(),
            views: Vec::new(),
            used_cids: BTreeSet::new(),
            used_clients: BTreeSet::new(),
        }
    }

    /// A connection ID no other call has returned.
    pub fn fresh_cid(&mut self) -> Cid {
        loop {
            let value = self.rng.next_u64();
            if value != 0 && self.used_cids.insert(value) {
                return Cid(value);
            }
        }
    }

    /// A client endpoint on `addr` with a port no other call has returned.
    pub fn client_on(&mut self, addr: Addr) -> Endpoint {
        loop {
            let endpoint = Endpoint {
                addr,
                port: self.rng.range(1024, 65_536) as u16,
            };
            if self.used_clients.insert(endpoint) {
                return endpoint;
            }
        }
    }

    fn size(&mut self, lo: u64, hi: u64) -> u16 {
        self.rng.range(lo, hi) as u16
    }

    /// Put one connection on the wire and return when it finished.
    pub fn emit(&mut self, plan: &ConnPlan) -> Emitted {
        let connection = self.views.len() as u32;
        self.views.push(plan.view);

        let server_cid = match plan.cids {
            CidMode::None => None,
            _ => Some(self.fresh_cid()),
        };
        let client_cid = (plan.cids == CidMode::Both).then(|| self.fresh_cid());
        let mut live = Live {
            connection,
            client: plan.client,
            server: plan.server,
            server_cid,
            client_cid,
            ttl_c2s: self.rng.range(48, 60) as u8,
            ttl_s2c: self.rng.range(48, 60) as u8,
            segment: 0,
            cause: if plan.reuses_tuple {
                Cause::StartOnReusedTuple
            } else {
                Cause::Start
            },
        };

        // Handshake. The client's first Initial is addressed to a random
        // destination ID it made up; the server answers with its own ID.
        let mut t = plan.start_us;
        let rtt = self.rng.range(10 * MS, 80 * MS);
        let original_dcid = self.fresh_cid();
        let c2s = Direction::ClientToServer;
        let s2c = Direction::ServerToClient;
        let long = HeaderForm::Long;
        let size = self.size(1200, 1351);
        self.wire.push(live.packet(
            t,
            c2s,
            long,
            PacketType::Initial,
            (Some(original_dcid), live.client_cid),
            size,
        ));
        t += rtt / 2;
        let from_server = (live.client_cid, live.server_cid);
        let size = self.size(1200, 1351);
        self.wire
            .push(live.packet(t, s2c, long, PacketType::Initial, from_server, size));
        let size = self.size(300, 1201);
        self.wire
            .push(live.packet(t + MS, s2c, long, PacketType::Handshake, from_server, size));
        t += rtt / 2;
        let size = self.size(80, 301);
        self.wire.push(live.packet(
            t,
            c2s,
            long,
            PacketType::Handshake,
            (live.server_cid, live.client_cid),
            size,
        ));

        for step in &plan.steps {
            match *step {
                Step::Send { packets, gap_us } => {
                    for i in 0..packets {
                        t += gap_us * self.rng.range(500, 1500) / 1000;
                        let wire = if i % 2 == 0 {
                            let size = self.size(60, 401);
                            live.short(t, c2s, size)
                        } else {
                            let size = self.size(200, 1351);
                            live.short(t, s2c, size)
                        };
                        self.wire.push(wire);
                    }
                }
                Step::Idle(duration) => t += duration,
                Step::Rebind(client) => {
                    live.client = client;
                    live.segment += 1;
                    live.cause = Cause::NatRebind;
                }
                Step::Migrate(client) => {
                    live.client = client;
                    if live.server_cid.is_some() {
                        live.server_cid = Some(self.fresh_cid());
                    }
                    if live.client_cid.is_some() {
                        live.client_cid = Some(self.fresh_cid());
                    }
                    live.segment += 1;
                    live.cause = Cause::Migration;
                }
                Step::PathChange {
                    outage_us,
                    ttl_shift,
                    rotate,
                } => {
                    t += outage_us;
                    live.ttl_c2s = shift_ttl(live.ttl_c2s, ttl_shift);
                    live.ttl_s2c = shift_ttl(live.ttl_s2c, ttl_shift);
                    if rotate && live.server_cid.is_some() {
                        live.server_cid = Some(self.fresh_cid());
                    }
                    live.segment += 1;
                    live.cause = Cause::PathChange;
                }
                Step::Rotate => {
                    if live.server_cid.is_some() {
                        live.server_cid = Some(self.fresh_cid());
                        live.segment += 1;
                        live.cause = Cause::CidRotation;
                    }
                }
            }
        }
        Emitted { end_us: t }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(host: u8, port: u16) -> Endpoint {
        Endpoint {
            addr: Addr::new(198, 51, 100, host),
            port,
        }
    }

    fn server() -> Endpoint {
        Endpoint {
            addr: Addr::new(192, 0, 2, 10),
            port: 443,
        }
    }

    fn send(packets: u32) -> Step {
        Step::Send {
            packets,
            gap_us: 20 * MS,
        }
    }

    fn emit(cids: CidMode, steps: Vec<Step>) -> Vec<Wire> {
        let mut world = World::new(SplitMix64::new(3));
        world.emit(&ConnPlan::new(ep(1, 5000), server(), SEC, cids).steps(steps));
        world.wire
    }

    fn c2s_dcids(wire: &[Wire], segment: u16) -> BTreeSet<Option<Cid>> {
        wire.iter()
            .filter(|w| {
                w.truth.segment == segment
                    && w.observed.transport.header == HeaderForm::Short
                    && w.observed.transport.direction == Direction::ClientToServer
            })
            .map(|w| w.observed.dcid)
            .collect()
    }

    #[test]
    fn handshake_exposes_the_connection_ids_in_order() {
        let wire = emit(CidMode::Both, vec![send(2)]);
        let [client_initial, server_initial, server_hs, client_hs] = [0, 1, 2, 3].map(|i| wire[i]);

        assert!(client_initial.observed.is_client_initial());
        assert_eq!(client_initial.observed.transport.version, Some(1));
        let client_cid = client_initial.observed.scid.unwrap();
        let server_cid = server_initial.observed.scid.unwrap();

        // The server addresses the client by the ID the client announced.
        assert_eq!(server_initial.observed.dcid, Some(client_cid));
        assert_eq!(server_hs.observed.dcid, Some(client_cid));
        // The client then addresses the server by the server's ID.
        assert_eq!(client_hs.observed.dcid, Some(server_cid));
        // 1-RTT packets carry only a destination ID.
        assert_eq!(wire[4].observed.dcid, Some(server_cid));
        assert_eq!(wire[5].observed.dcid, Some(client_cid));
        assert_eq!(wire[4].observed.scid, None);
        assert_eq!(wire[4].observed.transport.version, None);
    }

    #[test]
    fn zero_length_modes_hide_the_right_ids() {
        let server_only = emit(CidMode::ServerOnly, vec![send(2)]);
        assert!(server_only[4].observed.dcid.is_some());
        assert_eq!(server_only[5].observed.dcid, None);

        let none = emit(CidMode::None, vec![send(2)]);
        assert!(none[4..].iter().all(|w| w.observed.dcid.is_none()));
        // The client's first Initial always has a destination ID.
        assert!(none[0].observed.dcid.is_some());
    }

    #[test]
    fn rebinding_changes_the_address_and_keeps_the_ids() {
        let wire = emit(
            CidMode::Both,
            vec![send(4), Step::Rebind(ep(1, 6000)), send(4)],
        );
        assert_eq!(c2s_dcids(&wire, 0), c2s_dcids(&wire, 1));
        let after: Vec<&Wire> = wire.iter().filter(|w| w.truth.segment == 1).collect();
        assert_eq!(after.len(), 4);
        assert!(after.iter().all(|w| w.truth.cause == Cause::NatRebind));
        assert!(after.iter().all(|w| w.observed.client() == ep(1, 6000)));
        // The client speaks first from its new address.
        assert_eq!(
            after[0].observed.transport.direction,
            Direction::ClientToServer
        );
    }

    #[test]
    fn migration_changes_the_address_and_both_ids() {
        let wire = emit(
            CidMode::Both,
            vec![send(4), Step::Migrate(ep(9, 7000)), send(4)],
        );
        let before = c2s_dcids(&wire, 0);
        let after = c2s_dcids(&wire, 1);
        assert_eq!((before.len(), after.len()), (1, 1));
        assert!(before.is_disjoint(&after));

        let s2c = |segment| {
            wire.iter()
                .find(|w| {
                    w.truth.segment == segment
                        && w.observed.transport.header == HeaderForm::Short
                        && w.observed.transport.direction == Direction::ServerToClient
                })
                .unwrap()
                .observed
                .dcid
        };
        assert_ne!(s2c(0), s2c(1));
        assert!(wire
            .iter()
            .filter(|w| w.truth.segment == 1)
            .all(|w| w.truth.cause == Cause::Migration));
    }

    #[test]
    fn path_change_keeps_the_tuple_and_shifts_ttl() {
        let change = Step::PathChange {
            outage_us: 3 * SEC,
            ttl_shift: -4,
            rotate: false,
        };
        let wire = emit(CidMode::Both, vec![send(2), change, send(2)]);
        let before = wire[4];
        let after = wire[6];
        assert_eq!(before.observed.flow(), after.observed.flow());
        assert_eq!(before.observed.dcid, after.observed.dcid);
        assert_eq!(
            after.observed.transport.ttl,
            before.observed.transport.ttl - 4
        );
        assert!(after.observed.timestamp_us - wire[5].observed.timestamp_us >= 3 * SEC);
        assert_eq!(after.truth.cause, Cause::PathChange);
    }

    #[test]
    fn rotation_changes_only_the_server_issued_id() {
        let wire = emit(CidMode::Both, vec![send(2), Step::Rotate, send(2)]);
        assert_ne!(wire[4].observed.dcid, wire[6].observed.dcid);
        assert_eq!(wire[5].observed.dcid, wire[7].observed.dcid);
        assert_eq!(wire[6].truth.cause, Cause::CidRotation);

        // With nothing to rotate, the step is a no-op.
        let wire = emit(CidMode::None, vec![send(2), Step::Rotate, send(2)]);
        assert!(wire.iter().all(|w| w.truth.segment == 0));
    }

    #[test]
    fn connections_are_numbered_and_times_advance() {
        let mut world = World::new(SplitMix64::new(3));
        let plan = ConnPlan::new(ep(1, 5000), server(), SEC, CidMode::Both).steps(vec![send(6)]);
        let first = world.emit(&plan);
        let second = world.emit(&plan);
        assert!(first.end_us > SEC);
        assert!(second.end_us > SEC);
        let connections: BTreeSet<u32> = world.wire.iter().map(|w| w.truth.connection).collect();
        assert_eq!(connections, BTreeSet::from([0, 1]));
        assert_eq!(world.views.len(), 2);
    }

    #[test]
    fn handshake_fits_the_declared_span_and_precedes_all_data() {
        use crate::simmodel::HANDSHAKE_SPAN_MAX_US;
        for seed in 0..200 {
            let mut world = World::new(SplitMix64::new(seed));
            let plan =
                ConnPlan::new(ep(1, 5000), server(), SEC, CidMode::Both).steps(vec![send(4)]);
            world.emit(&plan);
            let long: Vec<u64> = world
                .wire
                .iter()
                .filter(|w| w.observed.transport.header == HeaderForm::Long)
                .map(|w| w.observed.timestamp_us)
                .collect();
            let last_long = *long.iter().max().unwrap();
            assert_eq!(long.len(), 4);
            assert!(last_long - long.iter().min().unwrap() <= HANDSHAKE_SPAN_MAX_US);
            assert!(world
                .wire
                .iter()
                .filter(|w| w.observed.transport.header == HeaderForm::Short)
                .all(|w| w.observed.timestamp_us > last_long));
        }
    }

    #[test]
    fn fresh_values_never_repeat() {
        let mut world = World::new(SplitMix64::new(1));
        let cids: BTreeSet<Cid> = (0..500).map(|_| world.fresh_cid()).collect();
        assert_eq!(cids.len(), 500);
        let addr = Addr::new(198, 51, 100, 1);
        let clients: BTreeSet<Endpoint> = (0..500).map(|_| world.client_on(addr)).collect();
        assert_eq!(clients.len(), 500);
        assert!(clients.iter().all(|c| c.port >= 1024));
    }
}
