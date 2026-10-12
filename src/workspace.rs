//! The workspace a check is about: its pixi.toml, its pixi.lock, and where its policy is.

use std::path::{Path, PathBuf};

use miette::Diagnostic;
use thiserror::Error;

/// The file pixi-policy reads its policy from, beside pixi.toml.
pub const POLICY_FILE: &str = "pixi-policy.toml";

/// Why the workspace could not be found.
#[derive(Debug, Error, Diagnostic)]
pub enum WorkspaceError {
    #[error("no pixi workspace in {start} or any directory above it")]
    #[diagnostic(
        code(pixi_policy::workspace::not_found),
        help(
            "run pixi policy inside a pixi workspace (a pixi.toml, or a pyproject.toml with [tool.pixi]), or pass \
             --manifest-path"
        )
    )]
    NotFound { start: String },

    #[error("{path} does not exist")]
    #[diagnostic(
        code(pixi_policy::workspace::manifest),
        help("pass the path of the workspace's pixi.toml")
    )]
    Manifest { path: String },

    #[error("the workspace has no lockfile: {path} does not exist")]
    #[diagnostic(
        code(pixi_policy::workspace::no_lockfile),
        help("run `pixi lock` in the workspace: the policy is checked against what pixi.lock resolved")
    )]
    NoLockfile { path: String },
}

/// A pixi workspace: its manifest and its lockfile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Workspace {
    pub root: PathBuf,
    pub manifest: PathBuf,
    pub lockfile: PathBuf,
}

impl Workspace {
    /// The workspace of `manifest_path`, or the nearest pixi.toml at or above `start`.
    pub fn find(manifest_path: Option<&Path>, start: &Path) -> Result<Self, WorkspaceError> {
        let manifest = match manifest_path {
            Some(path) if path.is_file() => path.to_path_buf(),
            Some(path) => {
                return Err(WorkspaceError::Manifest {
                    path: path.display().to_string(),
                });
            }
            None => start
                .ancestors()
                .find_map(manifest_in)
                .ok_or_else(|| WorkspaceError::NotFound {
                    start: start.display().to_string(),
                })?,
        };
        let root = manifest.parent().unwrap_or(Path::new(".")).to_path_buf();
        let lockfile = root.join("pixi.lock");
        Ok(Self {
            root,
            manifest,
            lockfile,
        })
    }

    /// Whether the workspace has a lockfile.
    pub fn has_lockfile(&self) -> bool {
        self.lockfile.is_file()
    }

    /// The error for a workspace without a lockfile, when the policy does not check for one itself (`lock.present`).
    pub fn no_lockfile(&self) -> WorkspaceError {
        WorkspaceError::NoLockfile {
            path: self.lockfile.display().to_string(),
        }
    }

    /// Where the policy is: `explicit`, or pixi-policy.toml beside pixi.toml.
    pub fn policy_path(&self, explicit: Option<&Path>) -> PathBuf {
        explicit.map_or_else(|| self.root.join(POLICY_FILE), Path::to_path_buf)
    }
}

/// The workspace manifest in `dir`, as pixi picks it: pixi.toml, else a pyproject.toml with a `[tool.pixi]` table.
fn manifest_in(dir: &Path) -> Option<PathBuf> {
    let pixi = dir.join("pixi.toml");
    if pixi.is_file() {
        return Some(pixi);
    }
    let pyproject = dir.join("pyproject.toml");
    let text = std::fs::read_to_string(&pyproject).ok()?;
    let table: toml::Table = toml::from_str(&text).ok()?;
    table
        .get("tool")
        .and_then(|tool| tool.get("pixi"))
        .is_some()
        .then_some(pyproject)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_nearest_manifest_above_is_the_workspace() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("pixi.toml"), "").unwrap();
        std::fs::write(dir.path().join("pixi.lock"), "").unwrap();
        let inner = dir.path().join("src/pkg");
        std::fs::create_dir_all(&inner).unwrap();
        let ws = Workspace::find(None, &inner).unwrap();
        assert_eq!(ws.root, dir.path());
        assert_eq!(ws.policy_path(None), dir.path().join(POLICY_FILE));
        assert_eq!(ws.policy_path(Some(Path::new("/x/p.toml"))), Path::new("/x/p.toml"));
        assert_eq!(
            Workspace::find(Some(&dir.path().join("pixi.toml")), Path::new("/")).unwrap(),
            ws
        );
    }

    #[test]
    fn a_pyproject_counts_only_with_a_tool_pixi_table_and_pixi_toml_wins() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("pyproject.toml"), "[project]\nname = \"x\"\n").unwrap();
        assert_eq!(manifest_in(dir.path()), None);
        std::fs::write(
            dir.path().join("pyproject.toml"),
            "[tool.pixi.workspace]\nchannels = []\n",
        )
        .unwrap();
        assert_eq!(manifest_in(dir.path()), Some(dir.path().join("pyproject.toml")));
        std::fs::write(dir.path().join("pixi.toml"), "").unwrap();
        assert_eq!(manifest_in(dir.path()), Some(dir.path().join("pixi.toml")));
        std::fs::write(dir.path().join("pyproject.toml"), "not toml [").unwrap();
        std::fs::remove_file(dir.path().join("pixi.toml")).unwrap();
        assert_eq!(manifest_in(dir.path()), None);
    }

    #[test]
    fn no_workspace_above_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let err = Workspace::find(None, dir.path()).unwrap_err();
        // A temporary directory can sit under a workspace on a developer's machine; then it is found instead.
        if let WorkspaceError::NotFound { start } = err {
            assert_eq!(start, dir.path().display().to_string());
        }
    }

    #[test]
    fn a_missing_manifest_or_lockfile_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            Workspace::find(Some(&dir.path().join("pixi.toml")), dir.path()),
            Err(WorkspaceError::Manifest { .. })
        ));
        std::fs::write(dir.path().join("pixi.toml"), "").unwrap();
        let ws = Workspace::find(None, dir.path()).unwrap();
        assert!(!ws.has_lockfile());
        assert!(matches!(ws.no_lockfile(), WorkspaceError::NoLockfile { .. }));
    }
}
