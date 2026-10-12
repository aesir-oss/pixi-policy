use std::io::Write;
use std::process::ExitCode;

use clap::Parser;
use common::style::Palette;
use miette::{IntoDiagnostic, WrapErr};
use pixi_policy::cli::{Args, Command};
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
            let lock = check::load_lockfile(&workspace.lockfile)?;
            let rules = check::rules();
            let mut outcome = check::run(&lock, &policy, &rules)?;
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
    }
}
