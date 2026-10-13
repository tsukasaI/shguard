//! Filesystem adapter for `crate::rules`'s symlink-resolution port
//! ([`crate::rules::CanonicalizeFn`]). The composition root (`src/lib.rs`)
//! wires [`canonicalize`] into the rule set; nothing inward of it names this
//! module.

use crate::rules::ResolvedPath;

/// The `std::fs::canonicalize`d spelling of `path` with its directory flag
/// and hard-link count, or `None` when the path does not exist, cannot be
/// read, or resolves to a non-UTF-8 name. Blocks for as long as the
/// underlying `stat` calls do, so a hung network mount on the path stalls
/// the caller until the evaluation watchdog trips.
pub(crate) fn canonicalize(path: &str) -> Option<ResolvedPath> {
    let canonical = std::fs::canonicalize(path).ok()?;
    let metadata = std::fs::metadata(&canonical).ok()?;
    Some(ResolvedPath {
        path: canonical.into_os_string().into_string().ok()?,
        is_dir: metadata.is_dir(),
        link_count: link_count(&metadata),
    })
}

#[cfg(unix)]
fn link_count(metadata: &std::fs::Metadata) -> u64 {
    std::os::unix::fs::MetadataExt::nlink(metadata)
}

/// Windows has no cheap hard-link count in `std`; report a single link, as
/// symlink resolution there is not a supported configuration anyway.
#[cfg(not(unix))]
fn link_count(_: &std::fs::Metadata) -> u64 {
    1
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

    fn resolve(path: &std::path::Path) -> Option<ResolvedPath> {
        canonicalize(path.to_str().unwrap())
    }

    fn resolved(path: &std::path::Path, is_dir: bool, link_count: u64) -> Option<ResolvedPath> {
        Some(ResolvedPath {
            path: path.to_str().unwrap().to_string(),
            is_dir,
            link_count,
        })
    }

    #[test]
    fn resolve_symlinks_adapter_returns_a_regular_file_unchanged() {
        let (_guard, root) = temp();
        std::fs::write(root.join("ok.md"), "x").unwrap();
        assert_eq!(
            resolve(&root.join("ok.md")),
            resolved(&root.join("ok.md"), false, 1)
        );
    }

    #[test]
    fn resolve_symlinks_adapter_follows_a_symlink_out_of_the_directory() {
        let (_guard, root) = temp();
        std::fs::write(root.join("secret"), "x").unwrap();
        symlink(root.join("secret"), root.join("link.md")).unwrap();
        assert_eq!(
            resolve(&root.join("link.md")),
            resolved(&root.join("secret"), false, 1)
        );
    }

    #[test]
    fn resolve_symlinks_adapter_reports_directories_and_hard_link_counts() {
        let (_guard, root) = temp();
        std::fs::create_dir(root.join("dir")).unwrap();
        std::fs::write(root.join("a.md"), "x").unwrap();
        std::fs::hard_link(root.join("a.md"), root.join("b.md")).unwrap();
        assert_eq!(resolve(&root.join("dir")).map(|r| r.is_dir), Some(true));
        assert_eq!(
            resolve(&root.join("b.md")),
            resolved(&root.join("b.md"), false, 2)
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
