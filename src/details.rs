//! `--version-details` (#75): the build and the settings a run would use, so two machines that disagree can be
//! compared. Every setting comes from the environment, which is invisible from outside the process.

use std::ffi::OsString;
use std::path::Path;

/// The variables that move one upstream to a mirror, in the order the banner lists them.
pub const URL_OVERRIDES: &[&str] = &[
    "PIXI_POLICY_OSV_URL",
    "PIXI_POLICY_EPSS_URL",
    "PIXI_POLICY_KEV_URL",
    "PIXI_POLICY_PYPI_URL",
    "PIXI_POLICY_WHEEL_URL",
    "PIXI_POLICY_MAPPING_URL",
    "PIXI_POLICY_FEEDSTOCKS_URL",
    "PIXI_POLICY_FEEDSTOCK_OUTPUTS_URL",
];

/// The proxy variables, in the order the HTTP client tries them.
const PROXIES: &[&str] = &[
    "ALL_PROXY",
    "all_proxy",
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
];

/// The banner, from `var` (the environment) and `pixi` (pixi's `--version` line and where that pixi came from).
pub fn render(var: &dyn Fn(&str) -> Option<OsString>, pixi: Option<(String, &str)>) -> String {
    let set = |name: &str| {
        var(name)
            .filter(|value| !value.is_empty())
            .map(|value| value.to_string_lossy().into_owned())
    };
    let pixi = pixi.map_or("not found".to_string(), |(version, from)| format!("{version} ({from})"));
    let cache = match crate::fetch::cache_dir(var) {
        Some((dir, source)) => format!("{} ({source}; {})", dir.display(), created(&dir)),
        None => "none: no cache directory could be found, so nothing is cached".to_string(),
    };
    let offline = match crate::fetch::offline(var) {
        true => "yes (PIXI_POLICY_OFFLINE)",
        false => "no",
    };
    let proxy = PROXIES
        .iter()
        .find_map(|name| set(name).map(|value| (name, value)))
        .map_or("none".to_string(), |(name, value)| {
            let socks = match value.starts_with("socks") {
                true => "; SOCKS is not supported by this build",
                false => "",
            };
            format!("{} ({name}{socks})", redact(&value))
        });
    let no_proxy = set("NO_PROXY").or_else(|| set("no_proxy")).unwrap_or("none".into());
    let overrides: Vec<String> = URL_OVERRIDES
        .iter()
        .filter_map(|name| set(name).map(|value| format!("{name}={value}")))
        .collect();
    let overrides = match overrides.is_empty() {
        true => "none".to_string(),
        false => overrides.join("\n           "),
    };
    [
        format!(
            "pixi-policy {} ({} {})",
            env!("CARGO_PKG_VERSION"),
            std::env::consts::ARCH,
            std::env::consts::OS
        ),
        format!("pixi:      {pixi}"),
        format!("cache:     {cache}"),
        format!("offline:   {offline}"),
        format!("proxy:     {proxy}"),
        format!("no-proxy:  {no_proxy}"),
        "TLS:       the operating system's trust store (platform verifier)".to_string(),
        format!("overrides: {overrides}"),
        format!(
            "schemas:   report {}, facts {}",
            crate::report::JSON_VERSION,
            crate::facts::VERSION
        ),
        String::new(),
    ]
    .join("\n")
}

fn created(dir: &Path) -> &'static str {
    match dir.is_dir() {
        true => "exists",
        false => "not created yet",
    }
}

/// `url` without the password in it, so the banner can be pasted into an issue.
fn redact(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_string();
    };
    match rest.split_once('@') {
        Some((user, host)) if !user.contains('/') => {
            let user = user.split(':').next().unwrap_or(user);
            format!("{scheme}://{user}:***@{host}")
        }
        _ => url.to_string(),
    }
}

/// The pixi `pixi policy lock` would run (`PIXI_EXE`, or pixi on PATH): its `--version` line and where it came from.
pub fn pixi() -> Option<(String, &'static str)> {
    let (program, from) = match std::env::var_os("PIXI_EXE") {
        Some(exe) => (exe, "PIXI_EXE"),
        None => ("pixi".into(), "on PATH"),
    };
    let output = std::process::Command::new(program).arg("--version").output().ok()?;
    let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (output.status.success() && !version.is_empty()).then_some((version, from))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(vars: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> + use<> {
        let vars: Vec<(String, String)> = vars.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        move |name| {
            vars.iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| OsString::from(value))
        }
    }

    #[test]
    fn every_setting_is_shown_with_where_it_came_from() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().to_string_lossy().into_owned();
        let vars = env(&[
            ("PIXI_POLICY_CACHE_DIR", &cache),
            ("PIXI_CACHE_DIR", "/ignored"),
            ("PIXI_POLICY_OFFLINE", "1"),
            ("HTTPS_PROXY", "http://me:secret@proxy.example:3128"),
            ("no_proxy", "localhost,.internal"),
            ("PIXI_POLICY_OSV_URL", "https://osv.mirror"),
            ("PIXI_POLICY_KEV_URL", "https://kev.mirror/kev.json"),
        ]);
        let text = render(&vars, Some(("pixi 0.58.0".into(), "PIXI_EXE")));
        let lines: Vec<&str> = text.lines().collect();
        assert!(lines[0].starts_with(&format!("pixi-policy {} (", env!("CARGO_PKG_VERSION"))));
        assert_eq!(lines[1], "pixi:      pixi 0.58.0 (PIXI_EXE)");
        assert_eq!(lines[2], format!("cache:     {cache} (PIXI_POLICY_CACHE_DIR; exists)"));
        assert_eq!(lines[3], "offline:   yes (PIXI_POLICY_OFFLINE)");
        assert_eq!(lines[4], "proxy:     http://me:***@proxy.example:3128 (HTTPS_PROXY)");
        assert_eq!(lines[5], "no-proxy:  localhost,.internal");
        assert_eq!(lines[7], "overrides: PIXI_POLICY_OSV_URL=https://osv.mirror");
        assert_eq!(lines[8], "           PIXI_POLICY_KEV_URL=https://kev.mirror/kev.json");
        assert_eq!(lines[9], "schemas:   report 1, facts 1");
        assert!(!text.contains("secret"));
    }

    #[test]
    fn nothing_set_says_so() {
        let text = render(&env(&[("RATTLER_CACHE_DIR", "/no/such/dir")]), None);
        let pixi_policy = Path::new("/no/such/dir").join("pixi-policy");
        assert!(text.contains("pixi:      not found\n"), "{text}");
        assert!(
            text.contains(&format!(
                "cache:     {} (RATTLER_CACHE_DIR; not created yet)\n",
                pixi_policy.display()
            )),
            "{text}"
        );
        for line in [
            "offline:   no\n",
            "proxy:     none\n",
            "no-proxy:  none\n",
            "overrides: none\n",
        ] {
            assert!(text.contains(line), "{line:?} in {text}");
        }
        assert!(render(&env(&[]), None).contains("cache:     none: no cache directory"));
        let socks = render(&env(&[("ALL_PROXY", "socks5://proxy:1080")]), None);
        assert!(socks.contains("socks5://proxy:1080 (ALL_PROXY; SOCKS is not supported by this build)"));
    }

    #[test]
    fn the_overrides_listed_are_the_ones_the_crate_reads() {
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut read = std::collections::BTreeSet::new();
        let mut stack = vec![src];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().is_some_and(|ext| ext == "rs") && !path.ends_with("details.rs") {
                    let text = std::fs::read_to_string(&path).unwrap();
                    for (at, _) in text.match_indices("\"PIXI_POLICY_") {
                        let name: String = text[at + 1..]
                            .chars()
                            .take_while(|c| c.is_ascii_uppercase() || *c == '_')
                            .collect();
                        if name.ends_with("_URL") {
                            read.insert(name);
                        }
                    }
                }
            }
        }
        let listed: std::collections::BTreeSet<String> = URL_OVERRIDES.iter().map(|s| s.to_string()).collect();
        assert_eq!(listed, read);
    }

    #[test]
    fn a_url_without_a_password_is_unchanged() {
        assert_eq!(redact("http://proxy:3128"), "http://proxy:3128");
        assert_eq!(redact("proxy:3128"), "proxy:3128");
        assert_eq!(redact("http://proxy/a@b"), "http://proxy/a@b");
    }
}
