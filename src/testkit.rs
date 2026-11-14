//! Hand-built observations and events for unit tests.

use crate::model::{
    Addr, Cause, Cid, Direction, Endpoint, Event, HeaderForm, Observation, PacketType, Quality,
    Transport, Truth,
};

pub(crate) const MS: u64 = 1_000;
pub(crate) const SEC: u64 = 1_000_000;

pub(crate) fn server() -> Endpoint {
    Endpoint {
        addr: Addr::new(192, 0, 2, 10),
        port: 443,
    }
}

pub(crate) fn client(host: u8, port: u16) -> Endpoint {
    Endpoint {
        addr: Addr::new(198, 51, 100, host),
        port,
    }
}

fn packet(t: u64, direction: Direction, host: u8, port: u16) -> Observation {
    let (src, dst) = match direction {
        Direction::ClientToServer => (client(host, port), server()),
        Direction::ServerToClient => (server(), client(host, port)),
    };
    Observation {
        timestamp_us: t,
        src,
        dst,
        transport: Transport {
            direction,
            header: HeaderForm::Short,
            packet_type: PacketType::OneRtt,
            version: None,
            size: 100,
            ttl: 55,
        },
        dcid: None,
        scid: None,
        quality: Quality::default(),
    }
}

/// A short-header client packet from `198.51.100.<host>:<port>`.
pub(crate) fn c2s(t: u64, host: u8, port: u16) -> Observation {
    packet(t, Direction::ClientToServer, host, port)
}

/// A short-header server packet to `198.51.100.<host>:<port>`.
pub(crate) fn s2c(t: u64, host: u8, port: u16) -> Observation {
    packet(t, Direction::ServerToClient, host, port)
}

pub(crate) trait ObsExt {
    fn dcid(self, cid: u64) -> Self;
    fn initial(self, dcid: u64) -> Self;
    fn to(self, server: Endpoint) -> Self;
}

impl ObsExt for Observation {
    fn dcid(mut self, cid: u64) -> Self {
        self.dcid = Some(Cid(cid));
        self
    }

    /// Turn the packet into a long-header Initial.
    fn initial(mut self, dcid: u64) -> Self {
        self.transport.header = HeaderForm::Long;
        self.transport.packet_type = PacketType::Initial;
        self.transport.version = Some(1);
        self.dcid = Some(Cid(dcid));
        self
    }

    /// Point a client packet at a different server.
    fn to(mut self, server: Endpoint) -> Self {
        self.dst = server;
        self
    }
}

/// Pair observations with ground-truth connections, in delivery order.
pub(crate) fn events(items: &[(Observation, u32)]) -> Vec<Event> {
    events_with_cause(
        &items
            .iter()
            .map(|(obs, conn)| (*obs, *conn, 0, Cause::Start))
            .collect::<Vec<_>>(),
    )
}

pub(crate) fn events_with_cause(items: &[(Observation, u32, u16, Cause)]) -> Vec<Event> {
    items
        .iter()
        .enumerate()
        .map(|(i, (obs, connection, segment, cause))| Event {
            seq: i as u64,
            observed: *obs,
            truth: Truth {
                connection: *connection,
                segment: *segment,
                cause: *cause,
                wire_time_us: obs.timestamp_us,
            },
        })
        .collect()
}
