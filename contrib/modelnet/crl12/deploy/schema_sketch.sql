-- Illustrative PostgreSQL migration shape. Map to existing persistence and RLS.
-- This is NOT a new financial ledger. Store source observations and projections.
CREATE TABLE crl_observation (
  tenant_id text NOT NULL,
  entity_id text NOT NULL,
  provider_id text NOT NULL,
  source_generation text NOT NULL,
  source_sequence numeric(20,0) NOT NULL CHECK (source_sequence >= 0),
  position_key text NOT NULL,
  body_id char(96) NOT NULL,
  canonical_bytes bytea NOT NULL CHECK (octet_length(canonical_bytes) <= 1048576),
  effective_at numeric(20,0) NOT NULL,
  source_recorded_at numeric(20,0) NOT NULL,
  received_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, entity_id, provider_id, source_generation, source_sequence, position_key),
  UNIQUE (tenant_id, entity_id, body_id)
);
CREATE INDEX crl_observation_asof ON crl_observation
 (tenant_id,entity_id,position_key,effective_at,source_recorded_at);
CREATE TABLE crl_import_publication (
  tenant_id text NOT NULL,
  entity_id text NOT NULL,
  operation_id text NOT NULL,
  request_digest char(96) NOT NULL,
  validation_digest char(96) NOT NULL,
  projection_generation text NOT NULL,
  committed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(tenant_id,entity_id,operation_id)
);
-- Add engine-specific row-level security, source-binding FKs, signed envelope
-- storage, outbox integration and retention. A conflicting source sequence
-- must be recorded in reconciliation, not ON CONFLICT overwritten.
