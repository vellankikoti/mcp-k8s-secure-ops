package secureops.blast_radius

import rego.v1

summary[k] := v if {
    k := "pdb_count"
    v := count(input.blast_radius.pdb_violations)
}
