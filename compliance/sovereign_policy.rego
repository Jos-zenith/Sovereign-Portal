package vict.sovereignty

# Region guardrail: only India regions are allowed for sovereign data.
default allow_region = false

allow_region {
  input.region == "ap-south-1"
}

allow_region {
  input.region == "ap-south-2"
}

# Purpose guardrail for personal/payment data.
default allow_invocation = false

allow_invocation {
  input.data_classification == "non-personal"
}

allow_invocation {
  input.data_classification == "personal"
  input.consent.granted == true
  input.consent.withdrawn == false
  input.consent.purpose == input.requested_purpose
}

allow_invocation {
  input.data_classification == "payment"
  input.consent.granted == true
  input.consent.withdrawn == false
  input.consent.purpose == input.requested_purpose
}

violation[msg] {
  not allow_region
  msg := sprintf("non-sovereign region denied: %v", [input.region])
}

violation[msg] {
  not allow_invocation
  msg := "invocation denied by consent/purpose policy"
}
