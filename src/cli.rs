//! The command line: `pixi policy [check]`.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

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

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand, PartialEq, Eq)]
pub enum Command {
    /// Check every environment and platform in pixi.lock against the policy (what `pixi policy` alone does).
    Check,
}

impl Args {
    /// The subcommand to run: `check` when none was given.
    pub fn command(&self) -> &Command {
        self.command.as_ref().unwrap_or(&Command::Check)
    }
}
