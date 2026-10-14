//! Policies extended by URL (#1): pinned, fetched once and cached, so a check works offline once a base has been read.
//! A URL is pinned by a tag or commit in its path, or by the file's sha256; a cached copy of a pinned URL is used
//! without asking the network again. `PIXI_POLICY_CACHE_DIR` moves the cache, and `PIXI_POLICY_OFFLINE` forbids the
//! network, so a base that is not cached is an error.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use sha2::{Digest, Sha256};

/// The largest policy fetched, in bytes.
const MAX_BYTES: u64 = 1 << 20;

/// A base policy on the web, with the sha256 its content must have when one is given.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Remote {
    pub url: String,
    pub sha256: Option<String>,
}

/// Where the cache is and whether the network may be used. The default has no cache and may use the network.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Settings {
    pub cache: Option<PathBuf>,
    pub offline: bool,
}

impl Settings {
    /// From the environment: `PIXI_POLICY_CACHE_DIR` or the platform's cache directory, and `PIXI_POLICY_OFFLINE`.
    pub fn from_env() -> Self {
        let var = |name: &str| std::env::var_os(name).filter(|value| !value.is_empty());
        let cache = var("PIXI_POLICY_CACHE_DIR").map(PathBuf::from).or_else(|| {
            let base = if cfg!(windows) {
                var("LOCALAPPDATA").map(PathBuf::from)
            } else if cfg!(target_os = "macos") {
                var("HOME").map(|home| PathBuf::from(home).join("Library/Caches"))
            } else {
                var("XDG_CACHE_HOME")
                    .map(PathBuf::from)
                    .or_else(|| var("HOME").map(|home| PathBuf::from(home).join(".cache")))
            };
            base.map(|base| base.join("pixi-policy"))
        });
        Self {
            cache,
            offline: var("PIXI_POLICY_OFFLINE").is_some_and(|value| value != "0"),
        }
    }
}

/// The sha256 of `bytes`, in lower-case hex.
pub fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Whether `url` names a fixed version in its path: a commit (40 hex digits) or a version tag (`v3`, `1.2.0`).
pub fn pinned(url: &str) -> bool {
    let path = url.split_once("://").map_or(url, |(_, rest)| rest);
    let path = path.split(['?', '#']).next().unwrap_or(path);
    path.split('/').skip(1).any(|segment| {
        let commit = segment.len() == 40 && segment.bytes().all(|b| b.is_ascii_hexdigit());
        let version = segment.strip_prefix('v').unwrap_or(segment);
        let tag = version
            .split('.')
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
            && version.split('.').count() <= 3;
        commit || tag
    })
}

/// `entry` read relative to the URL `base`: `../team.toml` beside `https://host/a/b/base.toml` is
/// `https://host/a/team.toml`.
pub fn join(base: &str, entry: &str) -> String {
    let (scheme, rest) = base.split_once("://").unwrap_or(("https", base));
    let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
    let mut segments: Vec<&str> = path.split('/').collect();
    segments.pop();
    for part in entry.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            part => segments.push(part),
        }
    }
    format!("{scheme}://{host}/{}", segments.join("/"))
}

/// The text of `remote`: from the cache when it holds it, otherwise fetched, checked and cached.
pub fn fetch(remote: &Remote, settings: &Settings) -> Result<String, String> {
    let cached = settings
        .cache
        .as_ref()
        .map(|dir| dir.join("extends").join(sha256(remote.url.as_bytes())));
    let fresh = cached
        .as_deref()
        .and_then(|path| std::fs::read(path).ok())
        .filter(|text| remote.sha256.as_deref().is_none_or(|wanted| sha256(text) == wanted));
    if let Some(text) = fresh {
        return String::from_utf8(text).map_err(|_| "the cached copy is not UTF-8 text".to_string());
    }
    if settings.offline {
        return Err("it is not in the cache, and PIXI_POLICY_OFFLINE forbids fetching it".into());
    }
    let bytes = download(&remote.url)?;
    if let Some(wanted) = &remote.sha256 {
        let got = sha256(&bytes);
        if &got != wanted {
            return Err(format!("its sha256 is {got}, not the {wanted} the policy pins"));
        }
    }
    let text = String::from_utf8(bytes).map_err(|_| "it is not UTF-8 text".to_string())?;
    if let Some(path) = cached {
        // A cache that cannot be written only costs the next run a fetch.
        let _ = store(&path, text.as_bytes());
    }
    Ok(text)
}

fn download(url: &str) -> Result<Vec<u8>, String> {
    get(url, MAX_BYTES)
}

fn agent() -> ureq::Agent {
    let tls = ureq::tls::TlsConfig::builder()
        .root_certs(ureq::tls::RootCerts::PlatformVerifier)
        .build();
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(30)))
        .user_agent(concat!("pixi-policy/", env!("CARGO_PKG_VERSION")))
        .tls_config(tls)
        .build()
        .into()
}

/// GET `url`, at most `max` bytes of it.
pub fn get(url: &str, max: u64) -> Result<Vec<u8>, String> {
    let response = agent().get(url).call().map_err(|err| err.to_string())?;
    read_body(response.into_body(), max)
}

/// POST the JSON `body` to `url`, at most `max` bytes of the answer.
pub fn post_json(url: &str, body: &str, max: u64) -> Result<Vec<u8>, String> {
    let response = agent()
        .post(url)
        .header("Content-Type", "application/json")
        .send(body)
        .map_err(|err| err.to_string())?;
    read_body(response.into_body(), max)
}

fn read_body(body: ureq::Body, max: u64) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    body.into_reader()
        .take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(|err| err.to_string())?;
    if bytes.len() as u64 > max {
        return Err(format!("it is larger than {max} bytes"));
    }
    Ok(bytes)
}

/// Write `bytes` to `path` through a temporary file, so a reader never sees half of it.
pub fn store(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let dir = path.parent().expect("a cache file is in a directory");
    std::fs::create_dir_all(dir)?;
    let partial = dir.join(format!(
        ".{}.{}",
        path.file_name().unwrap().to_string_lossy(),
        std::process::id()
    ));
    std::fs::write(&partial, bytes)?;
    std::fs::rename(&partial, path)
}

#[cfg(test)]
pub mod tests {
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;

    use super::*;

    /// Serve `body` at every path, `times` times, on a local port; the URL of `/base.toml` there.
    pub fn serve(body: &'static str, times: usize) -> (String, std::thread::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let mut seen = Vec::new();
            for _ in 0..times {
                let (mut stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut request = String::new();
                reader.read_line(&mut request).unwrap();
                seen.push(request.split(' ').nth(1).unwrap_or_default().to_string());
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap() <= 2 {
                        break;
                    }
                }
                let status = if request.contains("/missing") {
                    "404 Not Found"
                } else {
                    "200 OK"
                };
                write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
            }
            seen
        });
        (format!("http://127.0.0.1:{port}/base.toml"), server)
    }

    fn settings(dir: &Path, offline: bool) -> Settings {
        Settings {
            cache: Some(dir.to_path_buf()),
            offline,
        }
    }

    #[test]
    fn a_pinned_url_names_a_commit_or_a_version_tag() {
        for url in [
            "https://github.com/acme/policies/raw/v3/base.toml",
            "https://raw.githubusercontent.com/acme/policies/1.2.0/base.toml",
            "https://raw.githubusercontent.com/acme/policies/0123456789abcdef0123456789abcdef01234567/base.toml",
        ] {
            assert!(pinned(url), "{url}");
        }
        for url in [
            "https://github.com/acme/policies/raw/main/base.toml",
            "https://example.com/v3.toml",
            "https://example.com/policies/1.2.3.4/base.toml",
            "https://v3/base.toml",
        ] {
            assert!(!pinned(url), "{url}");
        }
    }

    #[test]
    fn a_relative_entry_is_read_against_the_url() {
        let base = "https://host/a/b/base.toml";
        assert_eq!(join(base, "team.toml"), "https://host/a/b/team.toml");
        assert_eq!(join(base, "../c/./team.toml"), "https://host/a/c/team.toml");
    }

    #[test]
    fn a_fetched_policy_is_cached_and_read_offline_after() {
        let cache = tempfile::tempdir().unwrap();
        let (url, server) = serve("[bans]\n", 1);
        let remote = Remote {
            url: url.clone(),
            sha256: Some(sha256(b"[bans]\n")),
        };
        assert_eq!(fetch(&remote, &settings(cache.path(), false)).unwrap(), "[bans]\n");
        assert_eq!(server.join().unwrap(), ["/base.toml"]);
        // The server is gone: the cache answers, also offline.
        assert_eq!(fetch(&remote, &settings(cache.path(), true)).unwrap(), "[bans]\n");
        let other = Remote {
            url: url.replace("base", "other"),
            sha256: None,
        };
        let err = fetch(&other, &settings(cache.path(), true)).unwrap_err();
        assert!(err.contains("PIXI_POLICY_OFFLINE"), "{err}");
    }

    #[test]
    fn a_wrong_sha256_or_a_failed_fetch_is_an_error_and_caches_nothing() {
        let cache = tempfile::tempdir().unwrap();
        let (url, server) = serve("[bans]\n", 2);
        let wrong = Remote {
            url: url.clone(),
            sha256: Some("0".repeat(64)),
        };
        let err = fetch(&wrong, &settings(cache.path(), false)).unwrap_err();
        assert!(err.contains(&format!("its sha256 is {}", sha256(b"[bans]\n"))), "{err}");
        let missing = Remote {
            url: url.replace("base", "missing"),
            sha256: None,
        };
        let err = fetch(&missing, &settings(cache.path(), false)).unwrap_err();
        assert!(err.contains("404"), "{err}");
        server.join().unwrap();
        assert!(
            !cache.path().join("extends").exists()
                || std::fs::read_dir(cache.path().join("extends")).unwrap().count() == 0
        );
    }

    #[test]
    fn the_cache_follows_the_environment() {
        let settings = Settings::from_env();
        if std::env::var_os("PIXI_POLICY_CACHE_DIR").is_none() {
            assert!(settings.cache.is_some_and(|dir| dir.ends_with("pixi-policy")));
        }
    }
}
