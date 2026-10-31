//! `pixi-policy`: check what a pixi workspace's environments may contain against a written policy.
//!
//! **This library is not an API.** It exists so the tests can reach the binary's insides; every module may change in
//! any release. The command line, its exit codes and the policy file are the interface.

#![cfg_attr(not(test), forbid(unsafe_code))]

pub mod advisories;
pub mod check;
pub mod cli;
pub mod cvss;
pub mod details;
pub mod explain;
pub mod extends;
pub mod facts;
pub mod fetch;
pub mod freshness;
pub mod init;
pub mod keys;
pub mod license;
pub mod license_policy;
pub mod lockfile;
pub mod manifest;
pub mod pipe;
pub mod policy;
pub mod purl;
pub mod relock;
pub mod report;
pub mod rules;
pub mod style;
pub mod vex;
pub mod waivers;
pub mod wheel;
pub mod workspace;
pub mod zipread;

/// Nothing failed the policy.
pub const EXIT_OK: i32 = 0;
/// A finding failed the policy.
pub const EXIT_FAILED: i32 = 1;
/// The workspace, the lockfile or the policy could not be read.
pub const EXIT_ERROR: i32 = 2;
