package secureops

import rego.v1

test_read_allowed if {
    result := allow with input as {"tool_category": "read"}
    result.allow == true
}

test_prod_scale_zero_denied if {
    result := allow with input as {
        "tool_category": "write",
        "tool": "scale_workload",
        "target": {"namespace_labels": {"tier": "prod"}},
        "parameters": {"replicas": 0},
        "blast_radius": {"pdb_violations": [], "traffic": {"p99_latency_ms": 50}},
        "actor": {}
    }
    result.allow == false
    "prod_scale_zero_denied" in result.reasons
}

test_pdb_violation_denied if {
    result := allow with input as {
        "tool_category": "write",
        "tool": "restart_deployment",
        "target": {"namespace_labels": {"tier": "staging"}},
        "parameters": {},
        "blast_radius": {
            "pdb_violations": [{"pdb": {"name": "p"}, "current_available": 0, "min_available": 1}],
            "traffic": {"p99_latency_ms": 10}
        },
        "actor": {}
    }
    result.allow == false
    "pdb_violation" in result.reasons
}

test_p99_elevated_requires_ack if {
    base := {
        "tool_category": "write",
        "tool": "restart_deployment",
        "target": {"namespace_labels": {"tier": "prod"}},
        "parameters": {},
        "blast_radius": {"pdb_violations": [], "traffic": {"p99_latency_ms": 1500}},
    }
    denied := allow with input as object.union(base, {"actor": {}})
    denied.allow == false
    "p99_elevated_require_sre_ack" in denied.reasons

    allowed := allow with input as object.union(base, {"actor": {"sre_ack": true}})
    allowed.allow == true
}

test_default_write_allowed if {
    result := allow with input as {
        "tool_category": "write",
        "tool": "restart_deployment",
        "target": {"namespace_labels": {"tier": "staging"}},
        "parameters": {},
        "blast_radius": {"pdb_violations": [], "traffic": {"p99_latency_ms": 20}},
        "actor": {}
    }
    result.allow == true
}
