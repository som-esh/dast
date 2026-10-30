# OPA/Rego gating policy (AR-6, FR-GTE-1).
#
# This is the production gate authority: the OpaPolicyEngine shells out to
# `opa eval` against this file. The BuiltinPolicyEngine mirrors these
# semantics for environments without an OPA binary. Both consume the same
# GateInput contract. Changes land only via Git PR with required
# security-engineer review (FR-GOV-4).
package asvp.gate

import rego.v1

default verdict := {"verdict": "pass", "evaluated_verdict": "pass", "reasons": []}

severity_rank := {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

new_at_least(level) := [f |
	some f in input.new_findings
	severity_rank[f.severity] >= severity_rank[level]
]

# Rule evaluations -----------------------------------------------------------

block_reasons contains msg if {
	count(new_at_least("critical")) > 0
	msg := sprintf("new critical findings: %d", [count(new_at_least("critical"))])
}

block_reasons contains msg if {
	input.profile == "preprod"
	count(new_at_least("high")) > 0
	msg := sprintf("new high findings block pre-prod: %d", [count(new_at_least("high"))])
}

block_reasons contains msg if {
	input.profile == "preprod"
	input.tier == "tier1"
	count(input.coverage_gaps) > 0
	msg := "tier-1 authz coverage gap blocks pre-prod promotion"
}

warn_reasons contains msg if {
	input.profile != "preprod"
	count(new_at_least("high")) > 0
	msg := "new high findings (warn at PR/QA)"
}

# Aggregate ------------------------------------------------------------------

evaluated := "block" if {
	count(block_reasons) > 0
} else := "warn" if {
	count(warn_reasons) > 0
} else := "pass"

applied := "pass" if {
	input.policy_mode == "report_only"
} else := "warn" if {
	input.policy_mode == "warn"
	evaluated == "block"
} else := evaluated

verdict := {
	"verdict": applied,
	"evaluated_verdict": evaluated,
	"reasons": array.concat([m | some m in block_reasons], [m | some m in warn_reasons]),
}
