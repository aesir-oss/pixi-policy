# `opa test` with the facts of examples/projects/pixi/02-flask (written by `pixi run -e rego rego-test`) as data.flask,
# and the findings pixi-policy's built-in rules give for the same settings, which tests/facts.rs checks, as
# data.flask.expected.
package pixi.policy_test

import data.pixi.policy

test_flask_matches_the_built_in_rules if {
	policy.deny == {finding | some finding in data.flask.expected} with input as data.flask
}

test_a_package_from_another_channel_is_found if {
	pkg := {"name": "x", "origin": {"type": "channel", "channel": "pytorch"}, "license": {"spdx": "MIT"}}
	facts := {"environments": [{"name": "default", "platform": "linux-64", "packages": [pkg]}]}
	policy.deny == {{"rule": "sources.channels", "package": "x", "environment": "default", "platform": "linux-64"}} with input as facts
}
