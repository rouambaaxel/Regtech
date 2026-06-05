-- ============================================================
-- ComplianceOS — Auth Migration
-- Ajouter à schema.sql (ou lancer en migration séparée)
-- ============================================================

-- Colonnes auth sur la table users existante
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS full_name           VARCHAR(255),
  ADD COLUMN IF NOT EXISTS password_hash       VARCHAR(255),
  ADD COLUMN IF NOT EXISTS is_active           BOOLEAN NOT NULL DEFAULT TRUE,
  ADD COLUMN IF NOT EXISTS email_verified      BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS email_verify_token  VARCHAR(255),
  ADD COLUMN IF NOT EXISTS invite_token        VARCHAR(255),
  ADD COLUMN IF NOT EXISTS password_reset_token    VARCHAR(255),
  ADD COLUMN IF NOT EXISTS password_reset_expires  TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS last_login_at       TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_users_email      ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_verify     ON users(email_verify_token) WHERE email_verify_token IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_reset      ON users(password_reset_token) WHERE password_reset_token IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_invite     ON users(invite_token) WHERE invite_token IS NOT NULL;

-- Refresh tokens (JWT rotation)
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    jti         VARCHAR(255) NOT NULL UNIQUE,
    revoked     BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_rt_user    ON refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_rt_jti     ON refresh_tokens(jti);
CREATE INDEX IF NOT EXISTS idx_rt_active  ON refresh_tokens(user_id) WHERE revoked = FALSE;

-- Auto-purge expired tokens (run via pg_cron or cron job)
-- DELETE FROM refresh_tokens WHERE expires_at < NOW() - INTERVAL '7 days';
