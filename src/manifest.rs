//! The workspace manifest, read for the `manifest.*` rules (#64): every dependency with its spec and line, and the
//! workspace's platforms. Read from `pixi.toml`, or from `[tool.pixi]` in a `pyproject.toml`.

use std::path::Path;

use miette::Diagnostic;
use thiserror::Error;
use toml::Spanned;
use toml::de::{DeTable, DeValue};

/// Why the manifest could not be read.
#[derive(Debug, Error, Diagnostic)]
pub enum ManifestError {
    #[error("cannot read the manifest {path}: {message}")]
    #[diagnostic(
        code(pixi_policy::manifest::read),
        help(
            "the [manifest] rules read pixi.toml (or pyproject.toml's [tool.pixi]); fix the file, or remove [manifest] from the policy"
        )
    )]
    Read { path: String, message: String },
}

/// Conda or PyPI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DependencyKind {
    Conda,
    Pypi,
}

/// One dependency as the manifest writes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dependency {
    pub name: String,
    pub kind: DependencyKind,
    /// The version spec: the value when it is a string, its `version` key when it is a table.
    pub spec: Option<String>,
    /// The table it is in (`dependencies`, `feature.test.pypi-dependencies`, `target.linux-64.dependencies`).
    pub table: String,
    pub line: u32,
}

/// What the `manifest.*` rules read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Manifest {
    /// Whether it is a pyproject.toml.
    pub pyproject: bool,
    pub dependencies: Vec<Dependency>,
    /// The workspace's platforms and the line they are on.
    pub platforms: Option<(Vec<String>, u32)>,
    /// The environments `[environments]` defines, with their features; `default` is implicit and not listed.
    pub environments: Vec<(String, Vec<String>)>,
    /// The platforms a feature narrows its environments to, when it sets any.
    pub feature_platforms: Vec<(String, Vec<String>)>,
    /// The workspace's `exclude-newer` and its line, or the line of the workspace table when it sets none (#55).
    pub exclude_newer: ExcludeNewer,
    /// `[project] requires-python` of the workspace's pyproject.toml (the manifest itself, or one beside pixi.toml),
    /// with its line (#56).
    pub requires_python: Option<(String, u32)>,
}

/// The workspace's `exclude-newer` and its per-package overrides, as written (#55).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExcludeNewer {
    /// The workspace's value and its line.
    pub workspace: Option<(String, u32)>,
    /// The line of the workspace table, for a finding about a value it does not set.
    pub table_line: u32,
    /// `[exclude-newer]` (conda) and `[pypi-exclude-newer]` entries: the table, the package, the value and its line.
    pub overrides: Vec<(&'static str, String, String, u32)>,
}

/// `[project] requires-python` in a pyproject.toml's `text`, with its line.
fn requires_python(text: &str) -> Option<(String, u32)> {
    let document = DeTable::parse(text).ok()?;
    let value = get(table(document.get_ref(), "project")?, "requires-python")?;
    Some((value.get_ref().as_str()?.to_string(), line_of(text, value.span().start)))
}

fn strings(value: &DeValue<'_>) -> Vec<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.get_ref().as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

const CONDA_TABLES: [&str; 4] = [
    "dependencies",
    "host-dependencies",
    "build-dependencies",
    "run-dependencies",
];

fn line_of(text: &str, offset: usize) -> u32 {
    u32::try_from(text[..offset.min(text.len())].matches('\n').count() + 1).unwrap_or(u32::MAX)
}

fn get<'a, 'i>(table: &'a DeTable<'i>, key: &str) -> Option<&'a Spanned<DeValue<'i>>> {
    table.iter().find(|(k, _)| k.get_ref() == key).map(|(_, v)| v)
}

fn table<'a, 'i>(table: &'a DeTable<'i>, key: &str) -> Option<&'a DeTable<'i>> {
    get(table, key).and_then(|v| v.get_ref().as_table())
}

impl Manifest {
    /// Parse a manifest's text; `pyproject` reads its `[tool.pixi]` table.
    pub fn parse(text: &str, pyproject: bool) -> Result<Self, String> {
        let document = DeTable::parse(text).map_err(|err| err.to_string())?;
        let root = document.get_ref();
        let python = pyproject.then(|| requires_python(text)).flatten();
        let root = if pyproject {
            match table(root, "tool").and_then(|tool| table(tool, "pixi")) {
                Some(pixi) => pixi,
                None => {
                    return Ok(Self {
                        pyproject,
                        requires_python: python,
                        ..Self::default()
                    });
                }
            }
        } else {
            root
        };
        let mut manifest = Self {
            pyproject,
            requires_python: python,
            ..Self::default()
        };
        manifest.collect(text, root, "");
        if let Some(target) = table(root, "target") {
            for (platform, value) in target.iter() {
                if let Some(t) = value.get_ref().as_table() {
                    manifest.collect(text, t, &format!("target.{}.", platform.get_ref()));
                }
            }
        }
        if let Some(features) = table(root, "feature") {
            for (name, value) in features.iter() {
                let Some(feature) = value.get_ref().as_table() else {
                    continue;
                };
                if let Some(platforms) = get(feature, "platforms") {
                    manifest
                        .feature_platforms
                        .push((name.get_ref().to_string(), strings(platforms.get_ref())));
                }
                let prefix = format!("feature.{}.", name.get_ref());
                manifest.collect(text, feature, &prefix);
                if let Some(target) = table(feature, "target") {
                    for (platform, value) in target.iter() {
                        if let Some(t) = value.get_ref().as_table() {
                            manifest.collect(text, t, &format!("{prefix}target.{}.", platform.get_ref()));
                        }
                    }
                }
            }
        }
        if let Some(environments) = table(root, "environments") {
            for (name, value) in environments.iter() {
                let features = match value.get_ref() {
                    DeValue::Table(t) => get(t, "features").map(|f| strings(f.get_ref())).unwrap_or_default(),
                    other => strings(other),
                };
                manifest.environments.push((name.get_ref().to_string(), features));
            }
        }
        if let Some(package) = table(root, "package") {
            manifest.collect(text, package, "package.");
        }
        // The parsed tables are sorted maps; give the dependencies back in the file's order.
        manifest.dependencies.sort_by_key(|dep| dep.line);
        let workspace = table(root, "workspace").or_else(|| table(root, "project"));
        if let Some(platforms) = workspace.and_then(|w| get(w, "platforms")) {
            manifest.platforms = Some((strings(platforms.get_ref()), line_of(text, platforms.span().start)));
        }
        manifest.exclude_newer.workspace = workspace
            .and_then(|w| get(w, "exclude-newer"))
            .and_then(|value| Some((value.get_ref().as_str()?.to_string(), line_of(text, value.span().start))));
        let header = if pyproject {
            "[tool.pixi.workspace]"
        } else {
            "[workspace]"
        };
        manifest.exclude_newer.table_line = text
            .lines()
            .position(|line| line.trim() == header || (!pyproject && line.trim() == "[project]"))
            .map_or(1, |at| u32::try_from(at + 1).unwrap_or(1));
        for name in ["exclude-newer", "pypi-exclude-newer"] {
            let label = if name == "exclude-newer" {
                "exclude-newer"
            } else {
                "pypi-exclude-newer"
            };
            for (package, value) in table(root, name).into_iter().flat_map(DeTable::iter) {
                if let Some(text_value) = value.get_ref().as_str() {
                    manifest.exclude_newer.overrides.push((
                        label,
                        package.get_ref().to_string(),
                        text_value.to_string(),
                        line_of(text, value.span().start),
                    ));
                }
            }
        }
        manifest.exclude_newer.overrides.sort_by_key(|entry| entry.3);
        Ok(manifest)
    }

    /// Read the manifest at `path`.
    pub fn load(path: &Path) -> Result<Self, ManifestError> {
        let shown = path.display().to_string();
        let error = |message: String| ManifestError::Read {
            path: shown.clone(),
            message,
        };
        let text = std::fs::read_to_string(path).map_err(|err| error(err.to_string()))?;
        let pyproject = path.file_name().is_some_and(|name| name == "pyproject.toml");
        let mut manifest = Self::parse(&text, pyproject).map_err(error)?;
        if !pyproject && let Ok(beside) = std::fs::read_to_string(path.with_file_name("pyproject.toml")) {
            manifest.requires_python = requires_python(&beside);
        }
        Ok(manifest)
    }

    /// Every environment the workspace defines, `default` first, with the platforms it is solved for: the workspace's,
    /// narrowed by any of its features that set `platforms`.
    pub fn environment_platforms(&self) -> Vec<(String, Vec<String>)> {
        let workspace = self.platforms.as_ref().map(|(p, _)| p.clone()).unwrap_or_default();
        let mut out = vec![("default".to_string(), workspace.clone())];
        for (name, features) in &self.environments {
            if name == "default" {
                continue;
            }
            let platforms = workspace
                .iter()
                .filter(|platform| {
                    features.iter().all(|feature| {
                        self.feature_platforms
                            .iter()
                            .find(|(f, _)| f == feature)
                            .is_none_or(|(_, allowed)| allowed.contains(platform))
                    })
                })
                .cloned()
                .collect();
            out.push((name.clone(), platforms));
        }
        out
    }

    /// The dependencies of one table set (`""`, `target.linux-64.`, `feature.test.`, …).
    fn collect(&mut self, text: &str, root: &DeTable<'_>, prefix: &str) {
        let tables = CONDA_TABLES
            .iter()
            .map(|t| (*t, DependencyKind::Conda))
            .chain([("pypi-dependencies", DependencyKind::Pypi)]);
        for (name, kind) in tables {
            let Some(deps) = table(root, name) else { continue };
            for (key, value) in deps.iter() {
                let spec = match value.get_ref() {
                    DeValue::String(spec) => Some(spec.to_string()),
                    DeValue::Table(t) => get(t, "version").and_then(|v| v.get_ref().as_str()).map(str::to_string),
                    _ => None,
                };
                self.dependencies.push(Dependency {
                    name: key.get_ref().to_string(),
                    kind,
                    spec,
                    table: format!("{prefix}{name}"),
                    line: line_of(text, key.span().start),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_python_is_read_from_the_pyproject() {
        let text = "[project]\nname = \"x\"\nrequires-python = \">=3.12\"\n\n[tool.pixi.workspace]\nplatforms = []\n";
        assert_eq!(
            Manifest::parse(text, true).unwrap().requires_python,
            Some((">=3.12".into(), 3))
        );
        let bare = "[project]\nrequires-python = \">=3.14\"\n";
        assert_eq!(
            Manifest::parse(bare, true).unwrap().requires_python,
            Some((">=3.14".into(), 2)),
            "without [tool.pixi] too"
        );
        assert_eq!(Manifest::parse("[workspace]\n", false).unwrap().requires_python, None);
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("pixi.toml"), "[workspace]\nplatforms = []\n").unwrap();
        std::fs::write(dir.path().join("pyproject.toml"), bare).unwrap();
        let beside = Manifest::load(&dir.path().join("pixi.toml")).unwrap();
        assert_eq!(
            beside.requires_python,
            Some((">=3.14".into(), 2)),
            "a pyproject.toml beside pixi.toml"
        );
    }

    const MANIFEST: &str = r#"[workspace]
name = "w"
channels = ["conda-forge"]
platforms = ["linux-64", "osx-arm64"]

[dependencies]
python = "3.12.*"
numpy = "*"

[pypi-dependencies]
requests = { version = ">=2", extras = ["socks"] }
local = { path = "./local" }

[target.linux-64.dependencies]
libgcc = "*"

[feature.test.dependencies]
pytest = ">=8"

[feature.test.target.osx-arm64.pypi-dependencies]
mac-only = "*"

[package.host-dependencies]
hatchling = { version = "*" }
"#;

    #[test]
    fn every_table_pixi_takes_dependencies_from_is_read_with_lines() {
        let manifest = Manifest::parse(MANIFEST, false).unwrap();
        let got: Vec<(&str, &str, Option<&str>, u32)> = manifest
            .dependencies
            .iter()
            .map(|d| (d.table.as_str(), d.name.as_str(), d.spec.as_deref(), d.line))
            .collect();
        assert_eq!(
            got,
            [
                ("dependencies", "python", Some("3.12.*"), 7),
                ("dependencies", "numpy", Some("*"), 8),
                ("pypi-dependencies", "requests", Some(">=2"), 11),
                ("pypi-dependencies", "local", None, 12),
                ("target.linux-64.dependencies", "libgcc", Some("*"), 15),
                ("feature.test.dependencies", "pytest", Some(">=8"), 18),
                (
                    "feature.test.target.osx-arm64.pypi-dependencies",
                    "mac-only",
                    Some("*"),
                    21
                ),
                ("package.host-dependencies", "hatchling", Some("*"), 24),
            ]
        );
        assert_eq!(manifest.dependencies[2].kind, DependencyKind::Pypi);
        assert_eq!(
            manifest.platforms,
            Some((vec!["linux-64".into(), "osx-arm64".into()], 4))
        );
    }

    #[test]
    fn environments_get_the_workspace_platforms_narrowed_by_their_features() {
        let text = "[workspace]\nplatforms = [\"linux-64\", \"osx-arm64\", \"win-64\"]\n\n[feature.cuda]\nplatforms = [\"linux-64\"]\n\n[feature.test.dependencies]\npytest = \"*\"\n\n[environments]\ntest = [\"test\"]\ngpu = { features = [\"cuda\", \"test\"], solve-group = \"x\" }\n";
        let manifest = Manifest::parse(text, false).unwrap();
        let all = vec!["linux-64".to_string(), "osx-arm64".to_string(), "win-64".to_string()];
        assert_eq!(
            manifest.environment_platforms(),
            [
                ("default".to_string(), all.clone()),
                ("gpu".to_string(), vec!["linux-64".to_string()]),
                ("test".to_string(), all)
            ]
        );
        assert_eq!(
            Manifest::default().environment_platforms(),
            [("default".to_string(), Vec::<String>::new())]
        );
    }

    #[test]
    fn a_pyproject_is_read_from_tool_pixi() {
        let pyproject = "[project]\nname = \"x\"\n\n[tool.pixi.project]\nplatforms = [\"linux-64\"]\n\n[tool.pixi.dependencies]\npython = \">=3.10\"\n";
        let manifest = Manifest::parse(pyproject, true).unwrap();
        assert!(manifest.pyproject);
        assert_eq!(manifest.dependencies[0].line, 8);
        assert_eq!(manifest.platforms, Some((vec!["linux-64".into()], 5)));
        assert_eq!(
            Manifest::parse("[project]\nname = \"x\"\n", true)
                .unwrap()
                .dependencies
                .len(),
            0
        );
    }

    #[test]
    fn an_unreadable_manifest_is_an_error() {
        assert!(Manifest::parse("[workspace", false).is_err());
        let dir = tempfile::tempdir().unwrap();
        let err = Manifest::load(&dir.path().join("pixi.toml")).unwrap_err();
        assert!(err.to_string().starts_with("cannot read the manifest"));
        std::fs::write(dir.path().join("pixi.toml"), "x = [").unwrap();
        assert!(Manifest::load(&dir.path().join("pixi.toml")).is_err());
    }
}
