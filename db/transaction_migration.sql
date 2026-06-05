-- ============================================================
-- ComplianceOS — Transaction Monitoring Migration
-- Surveillance continue des transactions financières
-- Compatible PostgreSQL 15+
-- ============================================================

-- ============================================================
-- TABLE : TRANSACTIONS
-- ============================================================

CREATE TABLE IF NOT EXISTS transactions (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    business_id         UUID REFERENCES businesses(id) ON DELETE SET NULL,
    amount              NUMERIC(18,2) NOT NULL,
    currency            CHAR(3) NOT NULL DEFAULT 'GBP',
    beneficiary_name    VARCHAR(500),
    beneficiary_country CHAR(2),
    beneficiary_iban    VARCHAR(50),
    reference           TEXT,
    tx_type             VARCHAR(50),       -- outbound_wire | inbound | internal | ...
    channel             VARCHAR(50),       -- api | web | mobile | branch
    risk_score          SMALLINT NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
    flagged             BOOLEAN NOT NULL DEFAULT FALSE,
    flagged_rules       TEXT[] DEFAULT '{}',
    raw_data            JSONB NOT NULL DEFAULT '{}',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tx_tenant_biz_created
    ON transactions(tenant_id, business_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_tx_flagged
    ON transactions(tenant_id, created_at DESC)
    WHERE flagged = TRUE;

CREATE INDEX IF NOT EXISTS idx_tx_business_created
    ON transactions(business_id, created_at DESC);

-- ============================================================
-- TABLE : TRANSACTION_RULES (configurables par tenant)
-- ============================================================

CREATE TABLE IF NOT EXISTS transaction_rules (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    rule_name       VARCHAR(100) NOT NULL,
    rule_type       VARCHAR(50) NOT NULL,   -- structuring | velocity | high_risk_country |
                                             -- unusual_hours | round_amount | behavior_change
    threshold       NUMERIC,               -- seuil configurable (montant, count, multiplier...)
    window_minutes  INT,                   -- fenêtre temporelle en minutes
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, rule_name)
);

CREATE INDEX IF NOT EXISTS idx_rules_tenant ON transaction_rules(tenant_id) WHERE enabled = TRUE;

-- ============================================================
-- SEED : Règles par défaut pour le tenant de dev
-- ============================================================

INSERT INTO transaction_rules (tenant_id, rule_name, rule_type, threshold, window_minutes, enabled)
VALUES
    -- Structuring : montant entre 8000 et 9999 GBP (juste sous le seuil de déclaration)
    ('00000000-0000-0000-0000-000000000001',
     'structuring', 'structuring', 9999, NULL, TRUE),

    -- Velocity : plus de 5 transactions en 60 minutes pour le même business
    ('00000000-0000-0000-0000-000000000001',
     'velocity', 'velocity', 5, 60, TRUE),

    -- High-risk country : pays sur liste FATF noire/grise + sanctionnés
    -- NG=Nigeria, IR=Iran, KP=Corée du Nord, SY=Syrie, YE=Yémen, MM=Myanmar, LY=Libye
    ('00000000-0000-0000-0000-000000000001',
     'high_risk_country', 'high_risk_country', NULL, NULL, TRUE),

    -- Unusual hours : transactions entre 01:00 et 05:00 UTC
    ('00000000-0000-0000-0000-000000000001',
     'unusual_hours', 'unusual_hours', NULL, NULL, TRUE),

    -- Round amount : montant rond (ex: 10000, 50000) supérieur à 5000 GBP
    ('00000000-0000-0000-0000-000000000001',
     'round_amount', 'round_amount', 5000, NULL, TRUE),

    -- Behavior change : montant > 3x la moyenne des 30 derniers jours
    ('00000000-0000-0000-0000-000000000001',
     'behavior_change', 'behavior_change', 3, 43200, TRUE)

ON CONFLICT (tenant_id, rule_name) DO NOTHING;
