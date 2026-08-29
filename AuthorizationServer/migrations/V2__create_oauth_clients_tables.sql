-- Flyway Migration: V2__create_oauth_clients_tables.sql
-- Description: Create OAuth 2.0 client tables (oauth_clients, client_redirect_uris, client_scopes)

-- Ensure pgcrypto extension is available for gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================================
-- 1. OAuth Clients Table
-- ============================================================================
CREATE TABLE IF NOT EXISTS oauth_clients (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id VARCHAR(255) NOT NULL UNIQUE,
    client_secret_hash TEXT,
    name VARCHAR(255) NOT NULL,
    client_type VARCHAR(50) NOT NULL DEFAULT 'confidential',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_oauth_clients_client_id ON oauth_clients (client_id);

-- ============================================================================
-- 2. Client Redirect URIs Table
-- ============================================================================
CREATE TABLE IF NOT EXISTS client_redirect_uris (
    client_id VARCHAR(255) NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    redirect_uri TEXT NOT NULL,
    CONSTRAINT uq_client_redirect_uris UNIQUE (client_id, redirect_uri)
);

CREATE INDEX IF NOT EXISTS idx_client_redirect_uris_client_id ON client_redirect_uris (client_id);

-- ============================================================================
-- 3. Client Scopes Table
-- ============================================================================
CREATE TABLE IF NOT EXISTS client_scopes (
    client_id VARCHAR(255) NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    scope VARCHAR(100) NOT NULL,
    CONSTRAINT uq_client_scopes UNIQUE (client_id, scope)
);

CREATE INDEX IF NOT EXISTS idx_client_scopes_client_id ON client_scopes (client_id);
