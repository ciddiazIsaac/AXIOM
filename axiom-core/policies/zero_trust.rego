package axiom.pdp

# Default decisions
default allow = false
default requires_2fa = false
default requires_biometric = false
default block = false
default alert = false

# Rule 1: device_trust_score < 0.7 -> requires 2FA
requires_2fa if {
    input.device.trust_score < 0.7
}

# Rule 2: Geolocation changes in < 10 minutes to > 1000km -> block and alert
# Asumimos que el PIP pre-calculó distance_km y time_delta_mins
block if {
    input.context.distance_km > 1000
    input.context.time_delta_mins < 10
}

alert if {
    input.context.distance_km > 1000
    input.context.time_delta_mins < 10
}

# Rule 3: Resource is "Admin" -> require hardware-backed biometric signature
requires_biometric if {
    input.resource.name == "Admin"
}

# Permit if not explicitly blocked. The enforcement point must still respect 
# requires_2fa and requires_biometric flags.
allow if {
    not block
}
