-- Stripe Webhook Events Audit/Idempotency Table
-- This table stores all Stripe webhook events for audit, idempotency, and processing tracking.
-- 
-- Usage:
--   Execute this file manually in Supabase SQL Editor or via psql.
--
-- Idempotency:
--   The event_id column is UNIQUE to prevent duplicate processing of the same Stripe event.
--
-- Processing Status:
--   - 'received': Event received but not yet processed
--   - 'processed': Event successfully processed
--   - 'failed': Event processing failed
--   - 'ignored': Event intentionally ignored (e.g., not relevant to our system)

CREATE TABLE IF NOT EXISTS stripe_events (
    id BIGSERIAL PRIMARY KEY,
    event_id TEXT NOT NULL UNIQUE,
    event_type TEXT NOT NULL,
    api_version TEXT NULL,
    created_at_epoch BIGINT NULL,
    livemode BOOLEAN NOT NULL DEFAULT FALSE,
    tenant_id UUID NULL,
    data JSONB NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    processed_at TIMESTAMPTZ NULL,
    processing_status TEXT NOT NULL DEFAULT 'received',
    error TEXT NULL
);

-- Index on tenant_id for filtering events by tenant
CREATE INDEX IF NOT EXISTS idx_stripe_events_tenant_id ON stripe_events(tenant_id);

-- Index on received_at for time-based queries and ordering
CREATE INDEX IF NOT EXISTS idx_stripe_events_received_at ON stripe_events(received_at);

-- Index on event_type for filtering by event type
CREATE INDEX IF NOT EXISTS idx_stripe_events_event_type ON stripe_events(event_type);
