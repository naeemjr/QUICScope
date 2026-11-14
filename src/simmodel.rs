//! The declared simulator model.
//!
//! This module states, as explicit rules, what the synthetic generator can
//! and cannot produce. The ambiguity oracle ([`crate::oracle`]) reasons only
//! from these rules and the tracker-visible observations. Nothing here is a
//! claim about real QUIC deployments: these are the rules of the simulation.
//!
//! The model is a deliberate **over-approximation** of the generator. It
//! omits incidental regularities of the implementation (address pools,
//! packet sizes, TTLs, the shapes of timing distributions), so it admits
//! histories the generator would never emit. Two consequences:
//!
//! * whatever the model says is *determined* is determined for the
//!   generator too (checked by tests: the true history is always among the
//!   histories the model admits);
//! * the model may call *ambiguous* something a reasoner with full knowledge
//!   of the generator's internals could resolve.
//!
//! # Rules
//!
//! **Connections**
//!
//! * **M1 (one server).** A connection has one server endpoint for life.
//! * **M2 (one path at a time).** A connection uses one client endpoint at a
//!   time. A path change is instantaneous and permanent: the connection
//!   never returns to a client endpoint it has left.
//! * **M3 (handshake).** A connection begins with long-header packets on a
//!   single 4-tuple, all within [`HANDSHAKE_SPAN_MAX_US`] of each other.
//!   Long-header packets occur at no other time, and no short-header packet
//!   of a connection precedes its last long-header packet.
//! * **M4 (connection-ID mode).** Whether the server-issued connection ID is
//!   zero-length, and whether the client-issued one is, are fixed for the
//!   life of a connection.
//! * **M5 (connection-ID uniqueness).** A non-empty connection ID, seen
//!   toward a given server, belongs to exactly one connection.
//! * **M6 (path changes).** A path change may keep the connection IDs (a
//!   NAT rebinding) or replace them (a migration). Connection IDs may also
//!   change on an unchanged 4-tuple.
//!
//! **4-tuples**
//!
//! * **M7 (tuple reuse).** Two different connections may use the same
//!   4-tuple only one after the other, never interleaved, and the later
//!   one's first packet comes at least [`MIN_TUPLE_REUSE_GAP_US`] after the
//!   earlier one's last packet on that tuple.
//!
//! **The observer**
//!
//! * **M8 (incomplete observation).** The monitor may miss any packet. In
//!   particular it may miss an entire handshake, one whole direction, or
//!   everything before some point. Capture timestamps are exact. Delivery
//!   to the tracker may be delayed and reordered.
//!
//! No rule bounds how long a connection may be silent, and no rule relates
//! a new connection's client endpoint to any earlier one.

/// M7: the shortest time between the last packet of one connection and the
/// first packet of a different connection on the same 4-tuple.
pub const MIN_TUPLE_REUSE_GAP_US: u64 = 1_000_000;

/// M3: the longest time between the first and last long-header packets of
/// one connection's handshake.
pub const HANDSHAKE_SPAN_MAX_US: u64 = 100_000;
