from __future__ import annotations

from pathlib import Path

import yaml

WF = Path(".github/workflows/release.yml")


def test_release_has_expected_jobs():
    data = yaml.safe_load(WF.read_text())
    jobs = data["jobs"]
    for j in ("pypi-server", "pypi-policy-sdk", "image", "helm", "policy-bundle"):
        assert j in jobs, f"missing job {j}"
    assert jobs["pypi-server"]["environment"] == "pypi-server"
    assert jobs["pypi-policy-sdk"]["environment"] == "pypi-policy-sdk"


def test_image_job_signs_and_sboms():
    data = yaml.safe_load(WF.read_text())
    image_steps = data["jobs"]["image"]["steps"]
    uses = [s.get("uses", "") for s in image_steps]
    names = [s.get("name", "") for s in image_steps]
    assert any(u.startswith("sigstore/cosign-installer") for u in uses)
    assert any("Sign image" in n for n in names)
    assert any(u.startswith("anchore/sbom-action") for u in uses)
    assert any("Attach SBOM" in n for n in names)
