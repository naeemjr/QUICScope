//! Which classes of metadata a decision depended on.
//!
//! Every [`crate::tracker::Decision`] reports its basis. Reports count how
//! often each field was used. This is descriptive only: the preliminary
//! version's weighted "privacy cost" was removed because its weights had no
//! empirical grounding.

use crate::model::labelled_enum;

labelled_enum! {
    /// A class of metadata a tracker can base a decision on.
    pub enum Field {
        ClientAddr => "client-addr",
        ClientPort => "client-port",
        ServerEndpoint => "server-endpoint",
        /// A QUIC connection ID.
        ConnectionId => "connection-id",
        /// Long-header fields: packet type and version.
        Handshake => "handshake-header",
        /// Timestamps, gaps, and ordering.
        Timing => "timing",
        /// State kept about *other* flows and correlated with this one.
        CrossFlow => "cross-flow-state",
    }
}

impl Field {
    fn bit(self) -> u8 {
        1 << (self as u8)
    }
}

/// A set of [`Field`]s.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FieldSet(u8);

impl FieldSet {
    pub const EMPTY: FieldSet = FieldSet(0);

    pub fn of(fields: &[Field]) -> Self {
        fields.iter().fold(Self::EMPTY, |set, f| set.with(*f))
    }

    #[must_use]
    pub fn with(self, field: Field) -> Self {
        FieldSet(self.0 | field.bit())
    }

    pub fn contains(self, field: Field) -> bool {
        self.0 & field.bit() != 0
    }

    pub fn iter(self) -> impl Iterator<Item = Field> {
        Field::ALL
            .iter()
            .copied()
            .filter(move |f| self.contains(*f))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_membership() {
        let set = FieldSet::of(&[Field::ClientAddr, Field::Timing]);
        assert!(set.contains(Field::ClientAddr));
        assert!(set.contains(Field::Timing));
        assert!(!set.contains(Field::ConnectionId));
        assert_eq!(set.iter().count(), 2);
        assert_eq!(FieldSet::EMPTY.iter().count(), 0);
    }

    #[test]
    fn with_is_idempotent_and_every_field_has_its_own_bit() {
        let set = FieldSet::EMPTY
            .with(Field::CrossFlow)
            .with(Field::CrossFlow);
        assert_eq!(set, FieldSet::of(&[Field::CrossFlow]));
        assert_eq!(FieldSet::of(Field::ALL).iter().count(), Field::ALL.len());
    }
}
