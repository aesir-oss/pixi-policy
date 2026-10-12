//! The command line: `pixi policy [check]`.

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use crate::style::ColorChoice;

use crate::report::Format;

/// Check what a pixi workspace's environments may contain against pixi-policy.toml.
#[derive(Debug, Parser)]
#[command(name = "pixi-policy", bin_name = "pixi policy", version)]
pub struct Args {
    /// The workspace's pixi.toml (default: the nearest one at or above the working directory).
    #[arg(long, value_name = "PATH", global = true)]
    pub manifest_path: Option<PathBuf>,

    /// The policy to check against (default: pixi-policy.toml beside pixi.toml).
    #[arg(long, value_name = "FILE", global = true)]
    pub policy: Option<PathBuf>,

    /// The report's format.
    #[arg(long, value_enum, default_value_t, global = true)]
    pub format: Format,

    /// Write the report to FILE instead of standard output.
    #[arg(long, value_name = "FILE", global = true)]
    pub output: Option<PathBuf>,

    /// When to colour the text report (never in a file unless `always`).
    #[arg(long, value_enum, default_value_t, global = true)]
    pub color: ColorChoice,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand, PartialEq, Eq)]
pub enum Command {
    /// Check every environment and platform in pixi.lock against the policy (what `pixi policy` alone does).
    Check,
    /// Write a starting pixi-policy.toml (or --policy FILE) that the workspace passes today; never overwrites.
    Init,
    /// Say what a rule checks, its keys and an example; without RULE, list every rule.
    Explain {
        /// A rule ID, such as licenses.deny.
        rule: Option<String>,
    },
}

impl Args {
    /// The subcommand to run: `check` when none was given.
    pub fn command(&self) -> &Command {
        self.command.as_ref().unwrap_or(&Command::Check)
    }

    /// Whether the text report is coloured: as `--color` says on standard output, only with `always` in a file.
    pub fn colour(&self) -> bool {
        match self.output {
            Some(_) => self.color == ColorChoice::Always,
            None => self.color.enabled(),
        }
    }
}
