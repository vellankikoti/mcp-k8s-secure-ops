from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from typing import Literal


@dataclass
class BundleSource:
    kind: Literal["configmap", "oci"]
    configmap_path: str | None
    oci_ref: str | None

    @staticmethod
    def from_env() -> BundleSource:
        oci = os.environ.get("SECUREOPS_POLICY_OCI_REF")
        cm = os.environ.get("SECUREOPS_POLICY_CONFIGMAP_PATH")
        if oci:
            return BundleSource(kind="oci", configmap_path=cm, oci_ref=oci)
        if cm:
            return BundleSource(kind="configmap", configmap_path=cm, oci_ref=None)
        raise RuntimeError(
            "no policy bundle source configured; "
            "set SECUREOPS_POLICY_CONFIGMAP_PATH or SECUREOPS_POLICY_OCI_REF"
        )


def materialize_bundle(src: BundleSource, target_dir: str) -> None:
    os.makedirs(target_dir, exist_ok=True)
    if src.kind == "configmap":
        if not src.configmap_path:
            raise ValueError("configmap_path required")
        for entry in os.listdir(src.configmap_path):
            s = os.path.join(src.configmap_path, entry)
            d = os.path.join(target_dir, entry)
            if os.path.isfile(s):
                shutil.copy2(s, d)
        return
    if src.kind == "oci":
        raise NotImplementedError(
            "OCI bundle loading requires oras-py; install as optional dep in v1.1"
        )
