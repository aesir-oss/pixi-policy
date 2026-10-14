//! The GitHub Action in `actions/pixi-policy` (#4): which release binary it installs for a ref, and that its docs page
//! and the release job that publishes it keep up with it. The GitHub API is replaced by fixtures, served over
//! `file://` or a local HTTP server, so a floating `@v0` is resolved without a network or a real tag.

use std::path::{Path, PathBuf};

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// A file with `\n` line endings, as a Windows checkout's CRLF would break the multi-line matches.
fn read(path: &str) -> String {
    std::fs::read_to_string(crate_dir().join(path))
        .unwrap()
        .replace("\r\n", "\n")
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

/// The `run:` script of the release workflow step named `step`, without its YAML indentation.
fn step_script(step: &str) -> String {
    let workflow = read(".github/workflows/release-artifacts.yml");
    let mut lines = workflow
        .lines()
        .skip_while(|line| line.trim() != format!("- name: {step}"))
        .skip(1);
    lines.by_ref().find(|line| line.trim() == "run: |");
    lines
        .take_while(|line| line.is_empty() || line.starts_with("          "))
        .map(|line| line.get(10..).unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn the_action_release_is_for_finals_only() {
    // The Marketplace ignores pre-releases, so a release candidate stays a tag (#15).
    let workflow = read(".github/workflows/release-artifacts.yml");
    let step = workflow
        .split("- name: Release the action\n")
        .nth(1)
        .expect("release-artifacts.yml has no `Release the action` step");
    let condition = step.lines().next().unwrap().trim();
    assert_eq!(condition, "if: needs.tag.outputs.prerelease != 'true'");
    assert!(step.contains("MOVED: ${{ steps.copy.outputs.moved }}"), "{step}");
}

#[cfg(unix)]
mod release {
    use std::process::{Command, Output};

    use super::*;

    /// Runs the `Release the action` step with a `gh` that logs its arguments and says whether the release exists.
    fn run(tag: &str, moved: &str, exists: bool) -> (Output, String, String) {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        let log = dir.path().join("gh.log");
        std::fs::write(
            bin.join("gh"),
            format!(
                "#!/usr/bin/env bash\nprintf '%s\\n' \"$*\" >> '{log}'\n\
                 if [ \"$1 $2\" = 'release view' ]; then exit {view}; fi\n\
                 if [ \"$1 $2\" = 'release create' ]; then cp notes.md '{log}.notes'; fi\n",
                log = log.display(),
                view = if exists { 0 } else { 1 },
            ),
        )
        .unwrap();
        Command::new("chmod").arg("+x").arg(bin.join("gh")).status().unwrap();
        let summary = dir.path().join("summary.md");
        let output = Command::new("bash")
            .arg("-c")
            .arg(step_script("Release the action"))
            .current_dir(dir.path())
            .env("PATH", format!("{}:{}", bin.display(), std::env::var("PATH").unwrap()))
            .env("TAG", tag)
            .env("MOVED", moved)
            .env("REPO", "aesir-oss/pixi-policy-action")
            .env("SOURCE", "aesir-oss/pixi-policy")
            .env("GITHUB_STEP_SUMMARY", &summary)
            .output()
            .unwrap();
        let calls = std::fs::read_to_string(&log).unwrap_or_default();
        let notes = std::fs::read_to_string(format!("{}.notes", log.display())).unwrap_or_default();
        (output, calls, notes)
    }

    #[test]
    fn a_final_that_moved_the_major_tag_is_latest() {
        let (output, calls, notes) = run("v0.2.0", "v0 -> v0.2.0", false);
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        let create = calls
            .lines()
            .find(|call| call.starts_with("release create"))
            .expect(&calls);
        assert!(
            create.starts_with("release create v0.2.0 --repo aesir-oss/pixi-policy-action --verify-tag"),
            "{create}"
        );
        assert!(create.ends_with(" --latest"), "{create}");
        assert!(notes.contains("- uses: aesir-oss/pixi-policy-action@v0\n"), "{notes}");
        assert!(
            notes.contains("`@v0` always runs the newest 0.x release; pin `@v0.2.0` for this one."),
            "{notes}"
        );
        assert!(
            notes.contains("https://github.com/aesir-oss/pixi-policy/releases/tag/v0.2.0"),
            "{notes}"
        );
        assert!(
            notes.contains("https://aesir-oss.github.io/pixi-policy/latest/github-action/"),
            "{notes}"
        );
        assert!(notes.contains("open issues and pull requests there"), "{notes}");
    }

    #[test]
    fn a_fix_on_an_older_line_is_not_latest() {
        let (output, calls, _) = run("v0.1.2", "no", false);
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        let create = calls
            .lines()
            .find(|call| call.starts_with("release create"))
            .expect(&calls);
        assert!(create.ends_with(" --latest=false"), "{create}");
    }

    #[test]
    fn an_existing_release_is_left_alone() {
        // A re-run of the job finds the release it already made.
        let (output, calls, _) = run("v0.2.0", "v0 -> v0.2.0", true);
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        assert_eq!(
            calls.lines().collect::<Vec<_>>(),
            ["release view v0.2.0 --repo aesir-oss/pixi-policy-action"]
        );
    }
}
