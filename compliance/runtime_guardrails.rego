package vict.runtime_guardrails

import rego.v1

# Deny process spawning and unknown outbound domains in runtime policy checks.
default allow_exec := false

default allow_egress := false

allow_exec if {
  input.exec.binary == "wasmtime"
}

allow_exec if {
  input.exec.binary == "wasmedge"
}

allow_egress if {
  input.network.domain == "signoz.internal.vict"
}

allow_egress if {
  startswith(input.network.domain, "api.vict.in")
}

violation contains msg if {
  not allow_exec
  msg := sprintf("blocked process spawn: %v", [input.exec.binary])
}

violation contains msg if {
  not allow_egress
  msg := sprintf("blocked egress domain: %v", [input.network.domain])
}
