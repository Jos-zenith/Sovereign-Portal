package vict.runtime_guardrails

# Deny process spawning and unknown outbound domains in runtime policy checks.
default allow_exec = false

default allow_egress = false

allow_exec {
  input.exec.binary == "wasmtime"
}

allow_exec {
  input.exec.binary == "wasmedge"
}

allow_egress {
  input.network.domain == "signoz.internal.vict"
}

allow_egress {
  startswith(input.network.domain, "api.vict.in")
}

violation[msg] {
  not allow_exec
  msg := sprintf("blocked process spawn: %v", [input.exec.binary])
}

violation[msg] {
  not allow_egress
  msg := sprintf("blocked egress domain: %v", [input.network.domain])
}
