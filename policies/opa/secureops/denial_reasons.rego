package secureops.denial_reasons

code_to_human := {
    "prod_scale_zero_denied": "scaling a prod-tier workload to zero replicas is denied; use drain or rolling restart instead",
    "pdb_violation": "the proposed action would violate a PodDisruptionBudget; reduce concurrency or wait for rollout",
    "p99_elevated_require_sre_ack": "prod p99 latency > 1s indicates active incident; require --sre-ack to proceed",
    "no_matching_rule": "no explicit allow rule matched; default denied",
}
