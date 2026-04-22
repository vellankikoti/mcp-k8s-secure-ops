package secureops

import rego.v1

default allow := {"allow": false, "reasons": ["no_matching_rule"], "matched": []}

# Reads always allowed — reads are enforced by RBAC, not OPA.
allow := {"allow": true, "reasons": [], "matched": ["secureops.allow.read"]} if {
    input.tool_category == "read"
}

# Block scale to 0 on prod-labelled namespace.
allow := {"allow": false, "reasons": ["prod_scale_zero_denied"], "matched": ["secureops.allow.prod_scale_zero"]} if {
    input.tool == "scale_workload"
    input.target.namespace_labels["tier"] == "prod"
    input.parameters.replicas == 0
}

# Block any write that would violate a PDB.
allow := {"allow": false, "reasons": ["pdb_violation"], "matched": ["secureops.allow.pdb"]} if {
    input.tool_category == "write"
    count(input.blast_radius.pdb_violations) > 0
}

# Block writes on prod namespaces when p99 latency is elevated (> 1s) — require SRE ack.
allow := {"allow": false, "reasons": ["p99_elevated_require_sre_ack"], "matched": ["secureops.allow.p99_elevated"]} if {
    input.tool_category == "write"
    input.target.namespace_labels["tier"] == "prod"
    input.blast_radius.traffic.p99_latency_ms > 1000
    not input.actor.sre_ack
}

# Default allow for writes not caught above.
allow := {"allow": true, "reasons": [], "matched": ["secureops.allow.default_write"]} if {
    input.tool_category == "write"
    not _prod_scale_zero
    not _pdb_violates
    not _p99_elevated_no_ack
}

_prod_scale_zero if {
    input.tool == "scale_workload"
    input.target.namespace_labels["tier"] == "prod"
    input.parameters.replicas == 0
}

_pdb_violates if { count(input.blast_radius.pdb_violations) > 0 }

_p99_elevated_no_ack if {
    input.target.namespace_labels["tier"] == "prod"
    input.blast_radius.traffic.p99_latency_ms > 1000
    not input.actor.sre_ack
}
