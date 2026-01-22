-- User Invite Tokens Table
-- This table stores invite tokens for tenant user invitations.
-- Tokens are stored hashed in the database for security.
-- 
-- Usage:
--   Execute this file manually in Supabase SQL Editor or via psql.
--
-- Token Lifecycle:
--   - Tokens are one-time use (marked with used_at when consumed)
--   - Tokens expire after a set period (expires_at)
--   - Multiple unused tokens can exist per user (for re-invites)

CREATE TABLE IF NOT EXISTS user_invite_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES tenant_users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by_user_id UUID NULL REFERENCES tenant_users(id) ON DELETE SET NULL
);

-- Index on user_id for finding tokens for a user
CREATE INDEX IF NOT EXISTS idx_user_invite_tokens_user_id ON user_invite_tokens(user_id);

-- Index on expires_at for cleanup queries
CREATE INDEX IF NOT EXISTS idx_user_invite_tokens_expires_at ON user_invite_tokens(expires_at);

-- Index on token_hash for fast token lookups (already unique, but index helps)
CREATE INDEX IF NOT EXISTS idx_user_invite_tokens_token_hash ON user_invite_tokens(token_hash);
