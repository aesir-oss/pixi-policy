//! The GitHub Action in `actions/pixi-policy` (#4): which release binary it installs for a ref, and that its docs page
//! and the release job that publishes it keep up with it. The GitHub API is replaced by fixtures, served over
//! `file://` or a local HTTP server, so a floating `@v0` is resolved without a network or a real tag.

use std::path::{Path, PathBuf};

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(path: &str) -> String {
    std::fs::read_to_string(crate_dir().join(path)).unwrap()
}

/// The keys of a top-level `action.yml` mapping (`inputs:` or `outputs:`), in order.
fn keys(action: &str, section: &str) -> Vec<String> {
    action
        .lines()
        .skip_while(|line| *line != format!("{section}:"))
        .skip(1)
        .take_while(|line| line.is_empty() || line.starts_with(' '))
        .filter_map(|line| line.strip_prefix("  ")?.strip_suffix(':'))
        .filter(|key| !key.starts_with(' '))
        .map(str::to_string)
        .collect()
}

#[test]
fn the_action_installs_release_archives_from_this_repository() {
    let action = read("actions/pixi-policy/action.yml");
    assert!(
        action.contains(r#"base="https://github.com/aesir-oss/pixi-policy/releases/download/v${VERSION}""#),
        "{action}"
    );
    assert!(
        action.contains(r#"name="pixi-policy-v${VERSION}-${PLATFORM}""#),
        "{action}"
    );
    let script = read("actions/pixi-policy/action-version.sh");
    assert!(script.contains(r#"RELEASES_API:-https://api.github.com/repos/aesir-oss/pixi-policy/releases}""#));
    assert!(!script.contains("pixi-ext-contrib/releases"), "{script}");
}

#[test]
fn every_input_and_output_is_documented() {
    let action = read("actions/pixi-policy/action.yml");
    let page = read("docs/github-action.md");
    let inputs = keys(&action, "inputs");
    let outputs = keys(&action, "outputs");
    assert!(inputs.len() >= 8 && outputs.len() >= 4, "{inputs:?} {outputs:?}");
    for key in inputs.iter().chain(&outputs) {
        assert!(
            page.contains(&format!("| `{key}` |")),
            "docs/github-action.md has no row for `{key}`"
        );
    }
}

#[test]
fn the_release_job_copies_every_file_the_action_needs() {
    let workflow = read(".github/workflows/release-artifacts.yml");
    for entry in std::fs::read_dir(crate_dir().join("actions/pixi-policy")).unwrap() {
        let name = entry.unwrap().file_name().into_string().unwrap();
        assert!(
            workflow.contains(&format!("../source/actions/pixi-policy/{name}")),
            "release-artifacts.yml does not copy actions/pixi-policy/{name} to the action repository"
        );
    }
    assert!(workflow.contains("repositories: pixi-policy-action"), "{workflow}");
}

#[cfg(unix)]
mod version {
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::process::{Command, Output};

    use super::*;

    const RELEASES: &[&str] = &["v1.0.0-rc.1", "v1.0.0", "v0.12.0", "v0.9.5", "v0.10.1", "v0.13.0-rc.1"];

    fn release_list(tags: &[&str]) -> String {
        let items: Vec<String> = tags
            .iter()
            .map(|tag| format!("  {{\n    \"tag_name\": \"{tag}\"\n  }}"))
            .collect();
        format!("[\n{}\n]", items.join(",\n"))
    }

    /// A release list served over `file://`; curl drops the `?per_page=100` query, so this is what it reads.
    fn fixture(tags: &[&str]) -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("releases"), release_list(tags)).unwrap();
        let api = format!("file://{}", dir.path().join("releases").display());
        (dir, api)
    }

    fn resolve(api: &str, env: &[(&str, &str)]) -> Output {
        Command::new("bash")
            .arg(crate_dir().join("actions/pixi-policy/action-version.sh"))
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap())
            .env("RELEASES_API", api)
            .envs(env.iter().copied())
            .output()
            .unwrap()
    }

    fn version(api: &str, env: &[(&str, &str)]) -> String {
        let output = resolve(api, env);
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        String::from_utf8(output.stdout).unwrap().trim().to_string()
    }

    #[test]
    fn the_input_wins_over_the_ref() {
        let (_dir, api) = fixture(RELEASES);
        assert_eq!(
            version(&api, &[("INPUT_VERSION", "v0.9.5"), ("ACTION_REF", "v0")]),
            "0.9.5"
        );
    }

    #[test]
    fn an_exact_tag_pins_that_release() {
        let (_dir, api) = fixture(RELEASES);
        assert_eq!(version(&api, &[("ACTION_REF", "v0.12.0")]), "0.12.0");
    }

    #[test]
    fn a_major_tag_resolves_within_its_major() {
        // Newest by version, not by list order, and never a pre-release or a v1.
        let (_dir, api) = fixture(RELEASES);
        assert_eq!(version(&api, &[("ACTION_REF", "v0")]), "0.12.0");
        assert_eq!(version(&api, &[("ACTION_REF", "v1")]), "1.0.0");
    }

    #[test]
    fn a_branch_or_a_local_action_takes_the_newest_release() {
        let (_dir, api) = fixture(RELEASES);
        assert_eq!(version(&api, &[("ACTION_REF", "main")]), "1.0.0");
        assert_eq!(version(&api, &[]), "1.0.0");
    }

    #[test]
    fn a_major_without_a_release_falls_back_to_the_newest() {
        let (_dir, api) = fixture(RELEASES);
        assert_eq!(version(&api, &[("ACTION_REF", "v7")]), "1.0.0");
    }

    #[test]
    fn an_unreachable_api_is_an_error() {
        let output = resolve("file:///nonexistent/releases", &[("ACTION_REF", "main")]);
        assert!(!output.status.success());
    }

    #[test]
    fn every_page_of_releases_is_read() {
        // A release on the second page is still found by following the Link header.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let first: Vec<String> = (1..100)
            .map(|n| format!("v0.0.{n}-rc.1"))
            .chain(["v0.1.0".into()])
            .collect();
        let first: Vec<&str> = first.iter().map(String::as_str).collect();
        let pages = [release_list(&first), release_list(&["v0.3.0", "v0.2.0"])];
        let server = std::thread::spawn(move || {
            let mut seen = Vec::new();
            for stream in listener.incoming().take(4) {
                let mut stream = stream.unwrap();
                let mut request = String::new();
                BufReader::new(&stream).read_line(&mut request).unwrap();
                let page = usize::from(request.contains("page=2"));
                seen.push(request.trim().to_string());
                let link = if page == 0 {
                    format!("Link: <http://127.0.0.1:{port}/releases?per_page=100&page=2>; rel=\"next\"\r\n")
                } else {
                    String::new()
                };
                let body = &pages[page];
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{link}Connection: close\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
            }
            seen
        });
        let api = format!("http://127.0.0.1:{port}/releases");
        assert_eq!(version(&api, &[]), "0.3.0");
        assert_eq!(version(&api, &[("ACTION_REF", "v0")]), "0.3.0");
        let seen = server.join().unwrap();
        assert_eq!(seen.len(), 4, "{seen:?}");
    }

    #[test]
    fn the_script_is_a_path_the_action_calls() {
        let action = read("actions/pixi-policy/action.yml");
        assert!(
            action.contains(r#"bash "$GITHUB_ACTION_PATH/action-version.sh""#),
            "{action}"
        );
        assert!(Path::new(&crate_dir().join("actions/pixi-policy/action-version.sh")).is_file());
    }
}
