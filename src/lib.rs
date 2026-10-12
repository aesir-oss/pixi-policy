//! `pixi-policy`: check what a pixi workspace's environments may contain against a written policy.
//!
//! **This library is not an API.** It exists so the tests can reach the binary's insides; every module may change in
//! any release. The command line, its exit codes and the policy file are the interface.

#![cfg_attr(not(test), forbid(unsafe_code))]

pub mod check;
pub mod cli;
pub mod policy;
pub mod report;
pub mod rules;
pub mod waivers;
pub mod workspace;

/// Nothing failed the policy.
pub const EXIT_OK: i32 = 0;
/// A finding failed the policy.
pub const EXIT_FAILED: i32 = 1;
/// The workspace, the lockfile or the policy could not be read.
pub const EXIT_ERROR: i32 = 2;
