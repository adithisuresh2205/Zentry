-- SentinelGate — PostgreSQL Initialization Script
-- Runs once on first DB container startup.
-- Sets up extensions and hardening.

-- Enable UUID generation
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Enable pg_crypto for HMAC operations (used by audit integrity chain)
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Revoke default public schema privileges
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT ALL ON SCHEMA public TO sentinelgate;

-- Log successful initialization
DO $$
BEGIN
    RAISE NOTICE 'SentinelGate database initialization complete.';
END $$;
