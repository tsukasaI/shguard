use std::path::PathBuf;

use crate::verdict::Verdict;

/// One finding that bears on the final decision. The enum is closed and
/// matched exhaustively in [`super::decide`], so a new kind of finding
/// cannot be added without deciding what it means there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Evidence {
    /// A verdict the structural gate already folded. Interim variant: later
    /// stages split it into the findings it is built from.
    GateVerdict(Verdict),
    /// Shell syntax shguard cannot read. `construct` names the construct
    /// when the parser recognises but cannot represent it.
    ParseFailure {
        message: String,
        construct: Option<String>,
    },
    InputRejected {
        stage: InputStage,
    },
    /// The user config failed to load. `path` is the config path the loader
    /// resolved (issue #630), `None` when it resolved none.
    ConfigUnavailable {
        path: Option<PathBuf>,
        error: String,
    },
    ResourceLimit {
        kind: LimitKind,
    },
}

/// Why the hook payload was refused before any command was analysed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputStage {
    MalformedJson(String),
    MissingCommand,
    StdinOverCap(u64),
    StdinReadError(String),
}

/// Which bound, trip or internal failure cut evaluation short. Payloads
/// are the measurements the reason text reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitKind {
    InnerTime,
    InnerMemory(u64),
    OuterTime,
    OuterMemory(u64),
    Disconnected,
    SpawnFailed,
    Panic,
    RecursionDepth(usize),
}
