//! Filesystem adapter for `crate::rules`'s symlink-resolution port
//! ([`crate::rules::CanonicalizeFn`]). The composition root (`src/lib.rs`)
//! wires [`canonicalize`] into the rule set; nothing inward of it names this
//! module.

use crate::rules::{ProbeError, ResolvedPath};

/// The `std::fs::canonicalize`d spelling of `path` with its directory flag
/// and hard-link count. Blocks for as long as the underlying `stat` calls
/// do, so a hung network mount on the path stalls the caller until the
/// evaluation watchdog trips.
///
/// # Errors
///
/// [`ProbeError::NotFound`] for a path that does not exist (ENOENT, ENOTDIR,
/// or a dangling link), [`ProbeError::Loop`] for ELOOP,
/// [`ProbeError::Denied`] for EACCES/EPERM, and [`ProbeError::Other`] for
/// anything else, including a resolved name that is not valid UTF-8.
pub(crate) fn canonicalize(path: &str) -> Result<ResolvedPath, ProbeError> {
    let canonical = std::fs::canonicalize(path).map_err(probe_error)?;
    let metadata = std::fs::metadata(&canonical).map_err(probe_error)?;
    Ok(ResolvedPath {
        path: canonical
            .into_os_string()
            .into_string()
            .map_err(|_| ProbeError::Other)?,
        is_dir: metadata.is_dir(),
        link_count: link_count(&metadata),
    })
}

// Not `ErrorKind::FilesystemLoop`: still unstable (`io_error_more`).
fn probe_error(error: std::io::Error) -> ProbeError {
    match (error.kind(), error.raw_os_error()) {
        (std::io::ErrorKind::NotFound, _) | (_, Some(libc::ENOTDIR)) => ProbeError::NotFound,
        (_, Some(libc::ELOOP)) => ProbeError::Loop,
        (std::io::ErrorKind::PermissionDenied, _) => ProbeError::Denied,
        _ => ProbeError::Other,
    }
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

    fn resolve(path: &std::path::Path) -> Result<ResolvedPath, ProbeError> {
        canonicalize(path.to_str().unwrap())
    }

    fn resolved(
        path: &std::path::Path,
        is_dir: bool,
        link_count: u64,
    ) -> Result<ResolvedPath, ProbeError> {
        Ok(ResolvedPath {
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
        assert_eq!(resolve(&root.join("dir")).map(|r| r.is_dir), Ok(true));
        assert_eq!(
            resolve(&root.join("b.md")),
            resolved(&root.join("b.md"), false, 2)
        );
    }

    #[test]
    fn resolve_symlinks_adapter_fails_on_dangling_and_missing_paths() {
        let (_guard, root) = temp();
        symlink(root.join("gone"), root.join("dangling.md")).unwrap();
        assert_eq!(
            resolve(&root.join("dangling.md")),
            Err(ProbeError::NotFound)
        );
        assert_eq!(resolve(&root.join("missing.md")), Err(ProbeError::NotFound));
    }

    #[test]
    fn probe_adapter_maps_a_file_used_as_a_directory_to_not_found() {
        let (_guard, root) = temp();
        std::fs::write(root.join("file"), "x").unwrap();
        assert_eq!(
            resolve(&root.join("file").join("below")),
            Err(ProbeError::NotFound)
        );
    }

    #[test]
    fn probe_adapter_reports_a_symlink_loop_as_loop() {
        let (_guard, root) = temp();
        symlink(root.join("b"), root.join("a")).unwrap();
        symlink(root.join("a"), root.join("b")).unwrap();
        assert_eq!(resolve(&root.join("a")), Err(ProbeError::Loop));
    }

    #[test]
    fn probe_adapter_reports_an_unsearchable_directory_as_denied() {
        use std::os::unix::fs::PermissionsExt;
        let (_guard, root) = temp();
        std::fs::create_dir(root.join("locked")).unwrap();
        std::fs::write(root.join("locked").join("f"), "x").unwrap();
        std::fs::set_permissions(root.join("locked"), std::fs::Permissions::from_mode(0o000))
            .unwrap();
        let result = resolve(&root.join("locked").join("f"));
        std::fs::set_permissions(root.join("locked"), std::fs::Permissions::from_mode(0o755))
            .unwrap();
        // Root is not stopped by the mode bits.
        if result.is_ok() {
            return;
        }
        assert_eq!(result, Err(ProbeError::Denied));
    }
}
