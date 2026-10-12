use std::io::Write;
use std::process::ExitCode;

use clap::Parser;
use common::style::Palette;
use miette::{IntoDiagnostic, WrapErr};
use pixi_policy::check::Outcome;
use pixi_policy::cli::{Args, Command};
use pixi_policy::init::plural;
use pixi_policy::manifest::Manifest;
use pixi_policy::policy::Policy;
use pixi_policy::report::{self, Context};
use pixi_policy::workspace::Workspace;
use pixi_policy::{EXIT_ERROR, EXIT_FAILED, EXIT_OK, check};

fn main() -> ExitCode {
    let args = Args::parse();
    match run(&args) {
        Ok(code) => ExitCode::from(code as u8),
        Err(report) => {
            eprintln!("{report:?}");
            ExitCode::from(EXIT_ERROR as u8)
        }
    }
}

fn run(args: &Args) -> miette::Result<i32> {
    match args.command() {
        Command::Check => {
            let cwd = std::env::current_dir()
                .into_diagnostic()
                .wrap_err("cannot read the working directory")?;
            let workspace = Workspace::find(args.manifest_path.as_deref(), &cwd)?;
            let policy_path = workspace.policy_path(args.policy.as_deref());
            let policy = Policy::load(&policy_path)?;
            let lock_rules_present = policy.lock.as_ref().is_some_and(|lock| lock.present != Some(false));
            let lock = match workspace.has_lockfile() {
                true => Some(check::load_lockfile(&workspace.lockfile)?),
                false if lock_rules_present => None,
                false => return Err(workspace.no_lockfile().into()),
            };
            let rules = check::rules();
            let mut outcome = match &lock {
                Some(lock) => check::run(lock, &policy, &rules)?,
                None => Outcome::default(),
            };
            if policy.manifest.is_some() || policy.lock.is_some() {
                let manifest = Manifest::load(&workspace.manifest)?;
                check::run_manifest(&mut outcome, &manifest, &policy, &rules);
                let lock_findings = pixi_policy::rules::lock::check(
                    &policy,
                    &workspace,
                    &manifest,
                    lock.as_ref(),
                    &pixi_policy::rules::lock::run_pixi,
                );
                outcome.findings.extend(lock_findings);
            }
            pixi_policy::waivers::apply(&mut outcome, &policy, pixi_policy::waivers::Date::today());
            let context = Context {
                manifest: &workspace.manifest,
                lockfile: &workspace.lockfile,
                policy: &policy_path,
                base: &cwd,
                rules: &rules,
            };
            let text = report::render(args.format, &outcome, &context, Palette::new(args.colour()));
            match &args.output {
                Some(path) => std::fs::write(path, text)
                    .into_diagnostic()
                    .wrap_err_with(|| format!("cannot write the report to {}", path.display()))?,
                None => {
                    let mut out = common::pipe::stdout();
                    out.write_all(text.as_bytes())
                        .and_then(|()| out.flush())
                        .into_diagnostic()
                        .wrap_err("cannot write the report")?;
                }
            }
            Ok(if outcome.failed() { EXIT_FAILED } else { EXIT_OK })
        }
        Command::Init => {
            let cwd = std::env::current_dir()
                .into_diagnostic()
                .wrap_err("cannot read the working directory")?;
            let workspace = Workspace::find(args.manifest_path.as_deref(), &cwd)?;
            if !workspace.has_lockfile() {
                return Err(workspace.no_lockfile().into());
            }
            let lock = check::load_lockfile(&workspace.lockfile)?;
            let manifest = Manifest::load(&workspace.manifest)?;
            let used = pixi_policy::init::in_use(&lock)?;
            let path = workspace.policy_path(args.policy.as_deref());
            pixi_policy::init::write(&path, &pixi_policy::init::propose(&used, &manifest))?;
            let mut out = common::pipe::stdout();
            writeln!(
                out,
                "wrote {}: {}, {}, {}; check it with `pixi policy`",
                path.display(),
                plural(used.channels.len(), "channel", "channels"),
                plural(used.indexes.len(), "index", "indexes"),
                plural(used.licenses.len(), "license", "licenses")
            )
            .and_then(|()| out.flush())
            .into_diagnostic()?;
            Ok(EXIT_OK)
        }
        Command::Explain { rule } => {
            let text = match rule {
                None => pixi_policy::explain::list(),
                Some(id) => pixi_policy::explain::text(id).ok_or_else(|| {
                    let ids: Vec<&str> = pixi_policy::explain::catalog().iter().map(|(id, _)| *id).collect();
                    miette::miette!(
                        code = "pixi_policy::explain::unknown",
                        help = format!("the rules are: {}", ids.join(", ")),
                        "pixi-policy has no rule {id:?}"
                    )
                })?,
            };
            let mut out = common::pipe::stdout();
            out.write_all(text.as_bytes())
                .and_then(|()| out.flush())
                .into_diagnostic()?;
            Ok(EXIT_OK)
        }
    }
}
