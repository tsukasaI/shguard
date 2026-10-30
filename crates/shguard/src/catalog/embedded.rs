//! The catalog files compiled into the binary.

use super::Source;

/// The embedded default catalog: `core.toml` holds the shell builtins and
/// the read-mostly tools. Later parts add more files to this list.
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
