//! The text report: findings grouped by severity, then a summary line.

use std::fmt::Write;

use crate::check::{Outcome, Severity};

/// The report people read.
pub fn text(outcome: &Outcome) -> String {
    let mut out = String::new();
    for finding in &outcome.findings {
        let package = match (&finding.package, &finding.version) {
            (Some(name), Some(version)) => format!("{name} {version}: "),
            (Some(name), None) => format!("{name}: "),
            _ => String::new(),
        };
        let _ = writeln!(
            out,
            "{}[{}] {package}{}",
            finding.severity, finding.rule, finding.message
        );
        let _ = writeln!(
            out,
            "  --> pixi.lock: environment {:?}, {}",
            finding.environment, finding.platform
        );
        if let Some(help) = &finding.help {
            let _ = writeln!(out, "  = help: {help}");
        }
        out.push('\n');
    }
    let count = |severity| outcome.findings.iter().filter(|f| f.severity == severity).count();
    let (errors, warnings) = (count(Severity::Error), count(Severity::Warning));
    let plural = |n: usize, word: &str| format!("{n} {word}{}", if n == 1 { "" } else { "s" });
    let _ = writeln!(
        out,
        "{}, {} in {} across {}",
        plural(errors, "error"),
        plural(warnings, "warning"),
        plural(outcome.packages, "package"),
        plural(outcome.targets, "environment-platform pair"),
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::check::Finding;

    #[test]
    fn findings_then_a_summary() {
        let outcome = Outcome {
            findings: vec![Finding {
                rule: "bans.deny",
                severity: Severity::Error,
                package: Some("pycrypto".into()),
                version: Some("2.6.1".into()),
                environment: "default".into(),
                platform: "linux-64".into(),
                message: "is denied (unmaintained)".into(),
                help: Some("use pycryptodome instead".into()),
            }],
            targets: 2,
            packages: 40,
        };
        let text = text(&outcome);
        assert!(
            text.starts_with("error[bans.deny] pycrypto 2.6.1: is denied (unmaintained)\n"),
            "{text}"
        );
        assert!(text.contains("  --> pixi.lock: environment \"default\", linux-64\n"));
        assert!(text.contains("  = help: use pycryptodome instead\n"));
        assert!(
            text.ends_with("1 error, 0 warnings in 40 packages across 2 environment-platform pairs\n"),
            "{text}"
        );
    }
}
