from __future__ import annotations

from pathlib import Path

MIGRATION = Path(__file__).parents[1] / "migrations" / "postgresql" / "001_tenant_foundation.sql"
REQUIRED_MARKERS = (
    "BEGIN;",
    "COMMIT;",
    "CREATE SCHEMA IF NOT EXISTS netwatch",
    "CREATE TABLE IF NOT EXISTS netwatch.tenants",
    "CREATE TABLE IF NOT EXISTS netwatch.tenant_memberships",
    "CREATE OR REPLACE FUNCTION netwatch.current_tenant_id()",
    "CREATE TABLE IF NOT EXISTS netwatch.scoped_assets",
    "ENABLE ROW LEVEL SECURITY",
    "FORCE ROW LEVEL SECURITY",
    "CREATE POLICY scoped_assets_tenant_isolation",
    "USING (tenant_id = netwatch.current_tenant_id())",
    "WITH CHECK (tenant_id = netwatch.current_tenant_id())",
)


def main() -> None:
    content = MIGRATION.read_text(encoding="utf-8")
    missing = [marker for marker in REQUIRED_MARKERS if marker not in content]
    if missing:
        raise SystemExit("missing migration markers: " + ", ".join(missing))
    if "password" in content.lower() or "secret" in content.lower():
        raise SystemExit("migration must not contain credentials or secret material")
    if not content.lstrip().startswith("BEGIN;") or not content.rstrip().endswith("COMMIT;"):
        raise SystemExit("migration must be transaction-wrapped")
    print("postgresql tenant foundation migration markers: ok")


if __name__ == "__main__":
    main()
