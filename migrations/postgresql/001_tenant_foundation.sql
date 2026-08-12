BEGIN;

CREATE SCHEMA IF NOT EXISTS netwatch;

CREATE TABLE IF NOT EXISTS netwatch.tenants (
    id UUID PRIMARY KEY,
    slug TEXT NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$'),
    display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 160),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'archived')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS netwatch.tenant_memberships (
    tenant_id UUID NOT NULL REFERENCES netwatch.tenants(id) ON DELETE CASCADE,
    subject_id TEXT NOT NULL CHECK (length(subject_id) BETWEEN 1 AND 240),
    role TEXT NOT NULL CHECK (role IN ('Viewer', 'Operator', 'Admin')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, subject_id)
);

CREATE INDEX IF NOT EXISTS idx_tenant_memberships_subject
    ON netwatch.tenant_memberships(subject_id, tenant_id);

CREATE OR REPLACE FUNCTION netwatch.current_tenant_id()
RETURNS UUID
LANGUAGE sql
STABLE
AS $$
    SELECT NULLIF(current_setting('netwatch.tenant_id', true), '')::UUID;
$$;

CREATE TABLE IF NOT EXISTS netwatch.scoped_assets (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES netwatch.tenants(id) ON DELETE CASCADE,
    ip_address INET NOT NULL,
    display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 240),
    mac_address MACADDR,
    hostname TEXT,
    manufacturer TEXT,
    identity_confidence TEXT NOT NULL DEFAULT 'Low'
        CHECK (identity_confidence IN ('Low', 'Medium', 'High')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, ip_address)
);

CREATE INDEX IF NOT EXISTS idx_scoped_assets_tenant_ip
    ON netwatch.scoped_assets(tenant_id, ip_address);

ALTER TABLE netwatch.scoped_assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE netwatch.scoped_assets FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS scoped_assets_tenant_isolation ON netwatch.scoped_assets;
CREATE POLICY scoped_assets_tenant_isolation
    ON netwatch.scoped_assets
    USING (tenant_id = netwatch.current_tenant_id())
    WITH CHECK (tenant_id = netwatch.current_tenant_id());

COMMENT ON SCHEMA netwatch IS
    'Enterprise tenant foundation; all application tables must be migrated and tested before shared-service readiness.';
COMMENT ON FUNCTION netwatch.current_tenant_id() IS
    'Reads a transaction-local tenant UUID. Missing or invalid context must fail closed.';
COMMENT ON TABLE netwatch.scoped_assets IS
    'Reference tenant-scoped asset table with PostgreSQL RLS. Not sufficient alone to enable shared service.';

COMMIT;
