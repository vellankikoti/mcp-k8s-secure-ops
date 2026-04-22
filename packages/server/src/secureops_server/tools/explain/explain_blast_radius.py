from __future__ import annotations

from secureops_server.models import BlastRadius
from secureops_server.tools.explain.common import narrate_or_fallback


def explain_blast_radius_fallback(br: BlastRadius) -> str:
    direct = ", ".join(f"{r.kind}/{r.name}" for r in br.direct) or "(none)"
    pdbs = len(br.pdb_violations)
    t = br.traffic
    lines = [
        f"{len(br.direct)} direct target(s): {direct}",
        f"{len(br.one_hop)} one-hop dependencies, {len(br.transitive)} transitive.",
        f"Traffic: {t.rps} rps, err {t.error_rate}, p99 {t.p99_latency_ms} ms ({t.source}).",
        f"PDB violations: {pdbs}. Data-loss risk: {br.data_loss_risk}.",
    ]
    return " ".join(lines)


async def explain_blast_radius(br: BlastRadius) -> str:
    return await narrate_or_fallback(
        prompt="Explain this blast radius for an SRE: what breaks if we proceed?",
        structured=br.model_dump(mode="json"),
        fallback=explain_blast_radius_fallback(br),
    )
