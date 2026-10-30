//! The catalog files compiled into the binary.

use super::Source;

/// The embedded default catalog. M13 ships `core.toml` empty; the rows come
/// in M14.
pub const EMBEDDED: &[Source<'static>] = &[Source {
    name: "embedded:core.toml",
    text: include_str!("../../../../catalog/core.toml"),
}];

#[cfg(test)]
mod tests {
    use super::EMBEDDED;
    use crate::catalog::load;

    #[test]
    fn embedded_catalog_loads() {
        assert!(load(EMBEDDED).is_ok());
    }
}
