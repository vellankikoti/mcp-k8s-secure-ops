from __future__ import annotations

from pathlib import Path

import pytest
from secureops_server.policy.opa_bundles import BundleSource, materialize_bundle


def test_bundle_source_from_env_picks_configmap(monkeypatch):
    monkeypatch.delenv("SECUREOPS_POLICY_OCI_REF", raising=False)
    monkeypatch.setenv("SECUREOPS_POLICY_CONFIGMAP_PATH", "/etc/policies")
    src = BundleSource.from_env()
    assert src.kind == "configmap"
    assert src.configmap_path == "/etc/policies"


def test_bundle_source_from_env_prefers_oci_when_set(monkeypatch):
    monkeypatch.setenv("SECUREOPS_POLICY_OCI_REF", "ghcr.io/vellankikoti/secureops-policies:v1.0.0")
    monkeypatch.setenv("SECUREOPS_POLICY_CONFIGMAP_PATH", "/etc/policies")
    src = BundleSource.from_env()
    assert src.kind == "oci"
    assert src.oci_ref and "secureops-policies" in src.oci_ref


def test_materialize_configmap_copies_to_target(tmp_path: Path):
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "allow.rego").write_text("package secureops\n")
    target = tmp_path / "out"
    src = BundleSource(kind="configmap", configmap_path=str(src_dir), oci_ref=None)
    materialize_bundle(src, str(target))
    assert (target / "allow.rego").read_text() == "package secureops\n"


def test_materialize_oci_not_implemented_raises(tmp_path: Path):
    src = BundleSource(kind="oci", configmap_path=None, oci_ref="ghcr.io/x/y:z")
    with pytest.raises(NotImplementedError, match="oras"):
        materialize_bundle(src, str(tmp_path))


def test_bundle_source_from_env_raises_when_neither_set(monkeypatch):
    monkeypatch.delenv("SECUREOPS_POLICY_OCI_REF", raising=False)
    monkeypatch.delenv("SECUREOPS_POLICY_CONFIGMAP_PATH", raising=False)
    with pytest.raises(RuntimeError, match="no policy bundle source"):
        BundleSource.from_env()
