-- ============================================================
-- ComplianceOS — Billing Migration
-- Pay-per-use £1.00 + Abonnement £79/mois (Stripe GBP)
-- ============================================================

-- Colonnes billing sur la table tenants
ALTER TABLE tenants
  ADD COLUMN IF NOT EXISTS billing_mode             VARCHAR(20) NOT NULL DEFAULT 'payg',
  ADD COLUMN IF NOT EXISTS stripe_customer_id       VARCHAR(100),
  ADD COLUMN IF NOT EXISTS stripe_sub_id            VARCHAR(100),
  ADD COLUMN IF NOT EXISTS kyb_credits              INT NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS current_period_kyb_count INT NOT NULL DEFAULT 0;

-- Table des paiements
CREATE TABLE IF NOT EXISTS payments (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    stripe_payment_id   VARCHAR(100) UNIQUE,
    stripe_invoice_id   VARCHAR(100),
    amount              NUMERIC(10,2) NOT NULL,
    currency            CHAR(3) NOT NULL DEFAULT 'gbp',
    type                VARCHAR(50) NOT NULL,   -- 'payg_kyb' | 'subscription' | 'overage'
    status              VARCHAR(20) NOT NULL DEFAULT 'pending',
    metadata            JSONB NOT NULL DEFAULT '{}',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_payments_tenant   ON payments(tenant_id);
CREATE INDEX IF NOT EXISTS idx_payments_stripe   ON payments(stripe_payment_id);
CREATE INDEX IF NOT EXISTS idx_payments_status   ON payments(status);
CREATE INDEX IF NOT EXISTS idx_payments_type     ON payments(tenant_id, type, created_at DESC);

-- Réinitialisation mensuelle du compteur KYB
-- (exécuté par le scheduler APScheduler le 1er du mois à 00:05 UTC)
