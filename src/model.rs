//! The common event schema.
//!
//! An [`Event`] has two halves that must never be confused:
//!
//! * [`Observation`]: what a passive monitor could record from an encrypted
//!   QUIC packet. This is the only thing a tracker ever sees.
//! * [`Truth`]: which connection the packet really belonged to and why its
//!   path changed. This exists because the trace is synthetic. It is used
//!   for scoring and is never passed to a tracker.

use std::fmt;

use serde::{Serialize, Serializer};

/// Declares a fieldless enum whose variants each carry a stable kebab-case
/// label, used in JSON, CSV, and on the command line.
macro_rules! labelled_enum {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident {
            $($(#[$vmeta:meta])* $variant:ident => $label:literal),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        $vis enum $name {
            $($(#[$vmeta])* $variant),+
        }

        impl $name {
            pub const ALL: &'static [$name] = &[$($name::$variant),+];

            pub fn as_str(self) -> &'static str {
                match self {
                    $($name::$variant => $label),+
                }
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(self.as_str())
            }
        }

        impl std::str::FromStr for $name {
            type Err = String;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::ALL
                    .iter()
                    .copied()
                    .find(|v| v.as_str() == s)
                    .ok_or_else(|| {
                        let known: Vec<&str> = Self::ALL.iter().map(|v| v.as_str()).collect();
                        format!("unknown value `{s}` (expected one of: {})", known.join(", "))
                    })
            }
        }
    };
}
pub(crate) use labelled_enum;

/// A synthetic IPv4 address. The generator only ever produces addresses from
/// the RFC 5737 documentation ranges.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Addr(pub u32);

impl Addr {
    pub const fn new(a: u8, b: u8, c: u8, d: u8) -> Self {
        Addr(u32::from_be_bytes([a, b, c, d]))
    }

    pub fn octets(self) -> [u8; 4] {
        self.0.to_be_bytes()
    }

    /// Whether the address is in 192.0.2.0/24, 198.51.100.0/24, or
    /// 203.0.113.0/24: reserved for documentation, never routed.
    pub fn is_documentation(self) -> bool {
        matches!(
            self.octets(),
            [192, 0, 2, _] | [198, 51, 100, _] | [203, 0, 113, _]
        )
    }
}

impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d] = self.octets();
        write!(f, "{a}.{b}.{c}.{d}")
    }
}

impl Serialize for Addr {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub struct Endpoint {
    pub addr: Addr,
    pub port: u16,
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.addr, self.port)
    }
}

/// A non-empty QUIC connection ID as it appears on the wire. A zero-length
/// connection ID is represented by the absence of a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Cid(pub u64);

impl fmt::Display for Cid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}

impl Serialize for Cid {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

labelled_enum! {
    /// Which way the packet travelled. A monitor infers this from the server
    /// port, so it counts as observed metadata.
    pub enum Direction {
        ClientToServer => "c2s",
        ServerToClient => "s2c",
    }
}

labelled_enum! {
    pub enum HeaderForm {
        /// Handshake-era packets. Version and both connection IDs are visible.
        Long => "long",
        /// 1-RTT packets. Only the destination connection ID is visible.
        Short => "short",
    }
}

labelled_enum! {
    pub enum PacketType {
        Initial => "initial",
        Handshake => "handshake",
        OneRtt => "1rtt",
    }
}

/// Transport-layer metadata visible without decrypting anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Transport {
    pub direction: Direction,
    pub header: HeaderForm,
    pub packet_type: PacketType,
    /// QUIC version; only long headers carry it.
    pub version: Option<u32>,
    /// UDP payload size in bytes.
    pub size: u16,
    /// IP TTL / hop limit as seen at the monitor.
    pub ttl: u8,
}

/// What the monitor knows about the quality of its own observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
pub struct Quality {
    /// The monitor's drop counter advanced since the previous record: it
    /// knows it missed something, but not what or on which flow.
    pub capture_gap: bool,
    /// The capture was cut short before the connection IDs, so their absence
    /// here does not mean they were zero-length.
    pub truncated: bool,
    /// Microseconds between capture and delivery to the tracker. Records are
    /// processed in delivery order, so a large lag means reordering.
    pub lag_us: u64,
}

/// One packet as a passive monitor could record it. **This is everything a
/// tracker is given.**
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Observation {
    /// Capture timestamp in microseconds.
    pub timestamp_us: u64,
    pub src: Endpoint,
    pub dst: Endpoint,
    pub transport: Transport,
    /// Destination connection ID, if non-empty and readable.
    pub dcid: Option<Cid>,
    /// Source connection ID; long headers only.
    pub scid: Option<Cid>,
    pub quality: Quality,
}

/// The address pair of a flow with the client side first, regardless of
/// which way a given packet travelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FlowKey {
    pub client: Endpoint,
    pub server: Endpoint,
}

impl Observation {
    pub fn client(&self) -> Endpoint {
        match self.transport.direction {
            Direction::ClientToServer => self.src,
            Direction::ServerToClient => self.dst,
        }
    }

    pub fn server(&self) -> Endpoint {
        match self.transport.direction {
            Direction::ClientToServer => self.dst,
            Direction::ServerToClient => self.src,
        }
    }

    pub fn flow(&self) -> FlowKey {
        FlowKey {
            client: self.client(),
            server: self.server(),
        }
    }

    /// Every connection ID readable on this packet.
    pub fn cids(&self) -> impl Iterator<Item = Cid> {
        self.dcid.into_iter().chain(self.scid)
    }

    /// A client Initial: the visible start of a handshake.
    pub fn is_client_initial(&self) -> bool {
        self.transport.packet_type == PacketType::Initial
            && self.transport.direction == Direction::ClientToServer
    }
}

labelled_enum! {
    /// Why the current path segment of a connection began. Ground truth.
    pub enum Cause {
        /// The connection started on a client address not used before.
        Start => "start",
        /// A different connection started on a 4-tuple an earlier one used.
        StartOnReusedTuple => "start-on-reused-tuple",
        /// A NAT changed the client's address or port; the client did not
        /// notice and kept its connection IDs.
        NatRebind => "nat-rebind",
        /// The client moved deliberately and both sides switched to fresh
        /// connection IDs, as RFC 9000 requires.
        Migration => "migration",
        /// The route changed under an unchanged 4-tuple.
        PathChange => "path-change",
        /// An endpoint switched connection ID on an unchanged path.
        CidRotation => "cid-rotation",
    }
}

/// Ground truth for one packet. **Never shown to a tracker.**
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Truth {
    /// The real connection this packet belongs to.
    pub connection: u32,
    /// Index of the connection's current path segment, starting at 0.
    pub segment: u16,
    /// Why that segment began.
    pub cause: Cause,
    /// When the packet was actually on the wire.
    pub wire_time_us: u64,
}

/// One trace record: an observation paired with its hidden ground truth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Event {
    /// Position in delivery order, which is the order trackers process.
    pub seq: u64,
    pub observed: Observation,
    pub truth: Truth,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{c2s, s2c};

    #[test]
    fn addresses_render_and_classify() {
        let a = Addr::new(198, 51, 100, 7);
        assert_eq!(a.to_string(), "198.51.100.7");
        assert!(a.is_documentation());
        assert!(Addr::new(192, 0, 2, 1).is_documentation());
        assert!(Addr::new(203, 0, 113, 254).is_documentation());
        assert!(!Addr::new(192, 0, 3, 1).is_documentation());
        assert!(!Addr::new(10, 0, 0, 1).is_documentation());
    }

    #[test]
    fn flow_key_is_direction_independent() {
        let up = c2s(0, 1, 5000);
        let down = s2c(10, 1, 5000);
        assert_eq!(up.flow(), down.flow());
        assert_eq!(up.client(), down.client());
        assert_eq!(up.server().port, 443);
    }

    #[test]
    fn cids_lists_what_is_readable() {
        let mut obs = c2s(0, 1, 5000);
        assert_eq!(obs.cids().count(), 0);
        obs.dcid = Some(Cid(1));
        obs.scid = Some(Cid(2));
        assert_eq!(obs.cids().collect::<Vec<_>>(), [Cid(1), Cid(2)]);
    }

    #[test]
    fn serialises_addresses_and_cids_as_text() {
        let mut obs = c2s(5, 1, 5000);
        obs.dcid = Some(Cid(0xAB));
        let json = serde_json::to_value(obs).unwrap();
        assert_eq!(json["src"]["addr"], "198.51.100.1");
        assert_eq!(json["dcid"], "00000000000000ab");
        assert_eq!(json["transport"]["direction"], "c2s");
    }

    #[test]
    fn observation_has_no_truth_field() {
        let json = serde_json::to_value(c2s(0, 1, 5000)).unwrap();
        let keys: Vec<&String> = json.as_object().unwrap().keys().collect();
        assert!(!keys.iter().any(|k| k.contains("truth")));
        assert!(!keys.iter().any(|k| k.contains("connection")));
    }
}
