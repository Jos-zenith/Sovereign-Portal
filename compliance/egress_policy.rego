package vict.egress

import rego.v1

# Mirrors src/egress/policy.py LocalPolicy. Load the allow-list as data:
#   opa run --server compliance/egress_policy.rego compliance/egress_allowlist.json
# Query: POST /v1/data/vict/egress/decision with {"input": {...}}

reasons contains "host-not-allow-listed" if {
	not input.host in data.vict_config.allowed_hosts
}

reasons contains "port-not-allowed" if {
	not input.port in data.vict_config.allowed_ports
}

reasons contains "host-not-in-token" if {
	not input.host in input.token.hosts
}

reasons contains input.consent.reason if {
	not input.consent.valid
}

default decision := {"allow": false, "reason": "policy-default-deny"}

decision := {"allow": true, "reason": "allowed"} if {
	count(reasons) == 0
}

decision := {"allow": false, "reason": min(reasons)} if {
	count(reasons) > 0
}
