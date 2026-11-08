"""Keep recovery runbook commands aligned with the runtime SQLite schema."""

from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def test_current_backup_runbooks_use_runtime_schema_version():
    runtime = (ROOT / "inventory_store.py").read_text(encoding="utf-8")
    versions = re.findall(r"conn\.execute\(\"PRAGMA user_version = (\d+)\"\)", runtime)
    assert versions, "Runtime schema assignment not found"
    current = versions[-1]

    for document in ("docs/backup-verification.md", "docs/enterprise-deployment.md"):
        text = (ROOT / document).read_text(encoding="utf-8")
        examples = re.findall(r"--expected-schema\s+(\d+)", text)
        assert examples, f"{document} has no pinned backup verification command"
        assert set(examples) == {current}, f"{document} uses stale schema versions"
