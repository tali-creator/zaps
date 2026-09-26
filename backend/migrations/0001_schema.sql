-- Migration: 0001_schema.sql
-- Initial schema for username mappings and user metadata.

-- Username mappings: enforce database-level uniqueness for registrations.
CREATE TABLE IF NOT EXISTS usernames (
    id BIGSERIAL PRIMARY KEY,
    username TEXT NOT NULL,
    user_id BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Unique index constraint on the usernames column to guarantee
-- database-level uniqueness for registrations.
CREATE UNIQUE INDEX IF NOT EXISTS usernames_username_unique_idx
    ON usernames (username);

-- Index for fast lowercase lookup operations (case-insensitive lookups).
CREATE INDEX IF NOT EXISTS usernames_username_lower_idx
    ON usernames (LOWER(username));

-- User metadata: index username mappings for fast lookups.
CREATE TABLE IF NOT EXISTS user_metadata (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL,
    username TEXT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Index username mappings on user metadata for fast lookups.
CREATE INDEX IF NOT EXISTS user_metadata_username_idx
    ON user_metadata (username);

-- Index for fast lowercase lookup operations on user metadata usernames.
CREATE INDEX IF NOT EXISTS user_metadata_username_lower_idx
    ON user_metadata (LOWER(username));
