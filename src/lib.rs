//! `quicscope` is a fully offline synthetic benchmark for one question:
//! under partial passive observation of encrypted QUIC traffic, when can a
//! monitor safely associate observations with the same underlying
//! connection, and when should it abstain because the visible evidence is
//! insufficient?
//!
//! Everything here is simulated. The crate opens no sockets, reads no
//! captures, and touches no network interface. Traces are generated from a
//! seed, and every address in them comes from the RFC 5737 documentation
//! ranges.
//!
//! Three separations hold the design together:
//!
//! * [`model`]: a tracker is handed an [`model::Observation`], which holds
//!   only what a passive observer could record. Ground truth lives beside
//!   it in [`model::Event`] and is read only by [`eval`].
//! * [`oracle`]: the ambiguity oracle reads observations and the declared
//!   simulator model ([`simmodel`]). It reads no ground truth and shares no
//!   code with any tracker.
//! * [`tracker`]: the forced and abstaining continuity methods share one
//!   evidence computation and differ only in the final decision policy.

pub mod basis;
pub mod error;
pub mod eval;
pub mod experiment;
pub mod figures;
pub mod gen;
pub mod model;
pub mod oracle;
pub mod protocol;
pub mod report;
pub mod rng;
pub mod simmodel;
pub mod stats;
pub mod tracker;

pub use error::Error;

#[cfg(test)]
pub(crate) mod testkit;
