use std::process::ExitCode;

use clap::Parser;
use pixi_policy::cli::{Args, Command};
use pixi_policy::policy::Policy;
use pixi_policy::workspace::Workspace;
use pixi_policy::{EXIT_ERROR, EXIT_FAILED, EXIT_OK, check, report};

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
            let cwd =
                std::env::current_dir().map_err(|err| miette::miette!("cannot read the working directory: {err}"))?;
            let workspace = Workspace::find(args.manifest_path.as_deref(), &cwd)?;
            let policy = Policy::load(&workspace.policy_path(args.policy.as_deref()))?;
            let lock = check::load_lockfile(&workspace.lockfile)?;
            let outcome = check::run(&lock, &policy, &check::rules())?;
            print!("{}", report::text(&outcome));
            Ok(if outcome.failed() { EXIT_FAILED } else { EXIT_OK })
        }
    }
}
