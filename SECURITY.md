# Security policy

## Reporting a vulnerability

Report it privately through GitHub:
**[Report a vulnerability](https://github.com/aesir-oss/pixi-policy/security/advisories/new)**
(Security → Advisories → Report a vulnerability). The report is visible only to the maintainers until an advisory
is published.

Please do not open a public issue for a security problem, and please do not disclose it elsewhere before a fix is
out. If GitHub's form is not available to you, open a public issue asking for a private channel, with no details
in it, and one will be arranged.

**What to include:** the version (`pixi policy --version`), the platform, the command you ran, and the smallest
`pixi.toml`, `pixi.lock` and `pixi-policy.toml` that reproduce it. A crash needs a backtrace (`RUST_BACKTRACE=1`).

## What to expect

| | |
|---|---|
| Acknowledgment | Within 3 business days. This is a small project with one maintainer; if you have heard nothing after that, ping the advisory thread. |
| Assessment | Within 10 business days: whether it is in scope, how severe, and a rough fix timeline. |
| Fix and disclosure | A patch release, then a published GitHub Security Advisory with a CVE where one is warranted. |
| Credit | You are named in the advisory and the changelog unless you would rather not be. Say which you prefer. |

There is no bug bounty.

## Supported versions

**The latest release.** A fix ships in the next patch release from `main`; there are no maintenance branches, and
nothing is backported. A report against an older version is checked against the current release first.

## Scope

pixi-policy reads three files a repository's author controls, so treat each as untrusted:

- **`pixi.toml`**, the workspace's manifest.
- **`pixi.lock`**, the lockfile, with every package's source, version and license.
- **`pixi-policy.toml`**, the policy itself.

It makes no network request. One rule, `lock.in-sync`, runs `pixi list --locked` offline: the pixi that started
`pixi policy`, or the one on `PATH`.

**In scope:**

- Memory unsafety, a panic, an unbounded allocation, or a hang on any of those inputs. The shipped binary is
  `forbid(unsafe_code)`, so a memory-safety finding would almost certainly be in a dependency. Report it here anyway.
- A file written anywhere other than the path given to `--output` or `pixi policy init`.
- A check that passes when it should fail, in a way the author of one of those files can arrange on purpose: a
  banned package, a denied license or a disallowed source that is silently not reported. A policy gate an attacker
  can talk past is a vulnerability, not a bug.
- Running anything other than `pixi list --locked`, or passing it an argument taken from the inputs unchecked.
- Anything in the release workflow that would let a third party influence what a release contains.

**Out of scope:**

- Vulnerabilities in the packages a workspace contains. pixi-policy has no advisory rules yet.
- A wrong license in a package's own metadata, as `pixi.lock` records it. Report it as a normal bug if you think
  the lockfile is read wrongly.
- Anything requiring an attacker who already has write access to the machine.

## Verifying a release

Every release archive carries a signed build-provenance attestation. To check a download came from this
repository's release workflow, built from that release's tag on a GitHub-hosted runner:

```sh
gh attestation verify pixi-policy-v<version>-<platform>.tar.gz --repo aesir-oss/pixi-policy \
  --signer-workflow aesir-oss/pixi-policy/.github/workflows/release-artifacts.yml \
  --source-ref refs/tags/v<version> \
  --deny-self-hosted-runners
```

Releases up to 0.1.0 were built in `aesir-oss/pixi-ext-contrib` and tagged `pixi-policy-v<version>`: verify those
with `--repo aesir-oss/pixi-ext-contrib`, `--signer-workflow aesir-oss/pixi-ext-contrib/.github/workflows/release-artifacts.yml`
and `--source-ref refs/tags/pixi-policy-v<version>`.
