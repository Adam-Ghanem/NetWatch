from __future__ import annotations

from pathlib import Path

import yaml  # type: ignore[import-untyped]

ROOT = Path(__file__).parents[1]


def load_documents(path: Path) -> list[dict]:
    documents = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
    return [document for document in documents if isinstance(document, dict)]


def main() -> None:
    base = load_documents(ROOT / "deploy" / "kubernetes.yaml")
    single = load_documents(ROOT / "deploy" / "kustomization-single-tenant.yaml")
    k3d = load_documents(ROOT / "deploy" / "kustomization-k3d.yaml")
    assert base and single and k3d

    overlay = k3d[0]
    assert overlay["kind"] == "Kustomization"
    assert "kubernetes.yaml" in overlay["resources"]
    assert overlay["namespace"] == "netwatch"
    assert overlay["images"][0]["newName"] == "netwatch"
    assert overlay["images"][0]["newTag"] == "local"

    text = (ROOT / "deploy" / "kustomization-k3d.yaml").read_text(encoding="utf-8")
    assert "value: NodePort" in text
    assert "value: 30080" in text
    assert 'value: "single-node-k3d-no-ha-no-shared-service"' in text

    base_text = (ROOT / "deploy" / "kubernetes.yaml").read_text(encoding="utf-8")
    assert "hostNetwork" not in base_text
    assert "NET_RAW" in base_text
    assert "ReadWriteOnce" in base_text
    assert "Recreate" in base_text

    runbook = (ROOT / "docs" / "k3d-local.md").read_text(encoding="utf-8")
    for marker in (
        "k3d cluster create netwatch-local",
        "k3d image import netwatch:local",
        "kubectl apply -k deploy/kustomization-k3d.yaml",
        "single-instance",
        "does not certify shared-service readiness",
    ):
        assert marker in runbook, marker

    print("k3d manifest and runbook checks: ok")


if __name__ == "__main__":
    main()
