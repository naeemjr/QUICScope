use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    UnknownTracker(String),
    /// A tracker name from the preliminary version. Its implementation was
    /// different, so it is not accepted as an alias.
    RetiredTracker {
        name: String,
        replacement: &'static str,
    },
    /// A tracker broke the interface contract: it linked to a track it never
    /// opened, or reused a track id for a new track.
    TrackerContract {
        tracker: String,
        seq: u64,
        message: String,
    },
    /// Events, decisions, and oracle annotations must be parallel.
    LengthMismatch {
        events: usize,
        decisions: usize,
        annotations: usize,
    },
    /// The held-out evaluation was requested before a threshold was frozen.
    ThresholdNotFrozen,
    Io(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::UnknownTracker(name) => write!(f, "unknown tracker `{name}`"),
            Error::RetiredTracker { name, replacement } => write!(
                f,
                "`{name}` is a tracker of the preliminary version; its successor is `{replacement}` (a different implementation, see docs/PRELIMINARY_VS_FINAL_EVALUATION.md)"
            ),
            Error::TrackerContract {
                tracker,
                seq,
                message,
            } => write!(
                f,
                "tracker `{tracker}` broke its contract at event {seq}: {message}"
            ),
            Error::LengthMismatch {
                events,
                decisions,
                annotations,
            } => write!(
                f,
                "{events} events, {decisions} decisions, {annotations} annotations"
            ),
            Error::ThresholdNotFrozen => write!(
                f,
                "no abstention threshold has been frozen in src/protocol.rs; run `quicscope dev` and record its selection first"
            ),
            Error::Io(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for Error {}
