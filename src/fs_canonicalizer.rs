//! Filesystem adapter for `crate::rules`'s symlink-resolution port
//! ([`crate::rules::CanonicalizeFn`]). The composition root (`src/lib.rs`)
//! wires [`canonicalize`] into the rule set; nothing inward of it names this
//! module.

/// The `std::fs::canonicalize`d spelling of `path`, or `None` when the path
/// does not exist, cannot be read, or resolves to a non-UTF-8 name. Blocks
/// for as long as the underlying `stat` calls do, so a hung network mount
/// on the path stalls the caller until the evaluation watchdog trips.
pub(crate) fn canonicalize(path: &str) -> Option<String> {
    std::fs::canonicalize(path)
        .ok()?
        .into_os_string()
        .into_string()
        .ok()
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn temp() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let canonical = dir.path().canonicalize().unwrap();
        (dir, canonical)
    }

    fn resolve(path: &std::path::Path) -> Option<String> {
        canonicalize(path.to_str().unwrap())
    }

    #[test]
    fn resolve_symlinks_adapter_returns_a_regular_file_unchanged() {
        let (_guard, root) = temp();
        std::fs::write(root.join("ok.md"), "x").unwrap();
        assert_eq!(
            resolve(&root.join("ok.md")),
            Some(root.join("ok.md").to_str().unwrap().to_string())
        );
    }

    #[test]
    fn resolve_symlinks_adapter_follows_a_symlink_out_of_the_directory() {
        let (_guard, root) = temp();
        std::fs::write(root.join("secret"), "x").unwrap();
        symlink(root.join("secret"), root.join("link.md")).unwrap();
        assert_eq!(
            resolve(&root.join("link.md")),
            Some(root.join("secret").to_str().unwrap().to_string())
        );
    }

    #[test]
    fn resolve_symlinks_adapter_fails_on_dangling_and_missing_paths() {
        let (_guard, root) = temp();
        symlink(root.join("gone"), root.join("dangling.md")).unwrap();
        assert_eq!(resolve(&root.join("dangling.md")), None);
        assert_eq!(resolve(&root.join("missing.md")), None);
    }
}
