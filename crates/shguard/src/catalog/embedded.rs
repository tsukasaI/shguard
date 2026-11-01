//! The catalog files compiled into the binary.

use super::{Origin, Source};

/// The embedded default catalog: `core.toml` holds the shell builtins and
/// the read-mostly tools, `git.toml` the read-only git subcommands and
/// `push`, `gh.toml` the read-only gh subcommands and `cargo.toml` build,
/// test, check, clippy, fmt and doc. Later parts add more files to this list.
pub const EMBEDDED: &[Source<'static>] = &[
    Source {
        origin: Origin::Embedded,
        name: "embedded:core.toml",
        text: include_str!("../../../../catalog/core.toml"),
    },
    Source {
        origin: Origin::Embedded,
        name: "embedded:git.toml",
        text: include_str!("../../../../catalog/git.toml"),
    },
    Source {
        origin: Origin::Embedded,
        name: "embedded:gh.toml",
        text: include_str!("../../../../catalog/gh.toml"),
    },
    Source {
        origin: Origin::Embedded,
        name: "embedded:cargo.toml",
        text: include_str!("../../../../catalog/cargo.toml"),
    },
];

#[cfg(test)]
mod tests {
    use super::EMBEDDED;
    use crate::catalog::load;

    #[test]
    fn embedded_catalog_loads() {
        assert!(load(EMBEDDED).is_ok());
    }
}
