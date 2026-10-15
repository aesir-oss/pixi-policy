# Three of pixi-policy's built-in rules written in Rego over `pixi policy facts`, for organizations that keep their
# policy in OPA. The settings in `settings` play the part of pixi-policy.toml:
#
#   [sources]  allowed-channels = ["conda-forge"]   -> sources.channels
#   [bans]     deny = [{ name = "py" }]             -> bans.deny
#   [licenses] deny = ["GPL-3.0-only"]              -> licenses.deny
#
# The license rule compares single SPDX identifiers only; pixi-policy's own rule evaluates whole SPDX expressions
# (`MIT OR GPL-3.0-only` passes there, since MIT is an option).
package pixi.policy

settings := {
	"allowed_channels": {"conda-forge"},
	"banned": {"py"},
	"denied_licenses": {"GPL-3.0-only"},
}

# Every package of every environment and platform, with where it is.
packages contains [env.name, env.platform, pkg] if {
	some env in input.environments
	some pkg in env.packages
}

deny contains {"rule": "sources.channels", "package": pkg.name, "environment": env, "platform": platform} if {
	some [env, platform, pkg] in packages
	pkg.origin.type == "channel"
	not pkg.origin.channel in settings.allowed_channels
}

deny contains {"rule": "bans.deny", "package": pkg.name, "environment": env, "platform": platform} if {
	some [env, platform, pkg] in packages
	pkg.name in settings.banned
}

deny contains {"rule": "licenses.deny", "package": pkg.name, "environment": env, "platform": platform} if {
	some [env, platform, pkg] in packages
	pkg.license.spdx in settings.denied_licenses
}
