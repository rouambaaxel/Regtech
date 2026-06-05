-- ============================================================
-- ComplianceOS — Schema PostgreSQL
-- Migration initiale : Core + KYB + AML + CASS 15
-- Compatible PostgreSQL 15+
-- ============================================================

-- EXTENSIONS
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================
-- ENUMS
-- ============================================================

CREATE TYPE tenant_plan AS ENUM ('starter', 'growth', 'scale', 'enterprise');

CREATE TYPE kyb_status AS ENUM (
    'pending', 'in_progress', 'approved',
    'rejected', 'review_required', 'expired'
);

CREATE TYPE risk_level AS ENUM ('low', 'medium', 'high', 'critical');

CREATE TYPE idv_status AS ENUM (
    'not_started', 'pending', 'verified', 'failed', 'expired'
);

CREATE TYPE subject_type AS ENUM ('business', 'person');

CREATE TYPE screening_type AS ENUM (
    'sanctions', 'pep', 'adverse_media', 'full_kyb', 'idv'
);

CREATE TYPE screening_status AS ENUM ('clear', 'hit', 'error', 'pending');

CREATE TYPE alert_type AS ENUM (
    'sanctions_hit', 'pep_identified', 'ubo_change',
    'adverse_media', 'sar_required', 'review_overdue',
    'cass15_shortfall', 'kyb_expired'
);

CREATE TYPE alert_severity AS ENUM ('info', 'medium', 'high', 'critical');
CREATE TYPE alert_status AS ENUM ('open', 'investigating', 'resolved', 'false_positive');

CREATE TYPE fca_report_type AS ENUM (
    'cass15_daily_recon',
    'sup16_14a_monthly',
    'cass10_resolution_pack',
    'sup3a_annual_audit'
);

CREATE TYPE report_status AS ENUM ('draft', 'ready', 'submitted', 'accepted', 'rejected');

-- ============================================================
-- CORE : TENANTS (multi-tenant SaaS)
-- ============================================================

CREATE TABLE tenants (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name            VARCHAR(255) NOT NULL,
    slug            VARCHAR(100) NOT NULL UNIQUE,
    fca_firm_ref    VARCHAR(20),                    -- référence FCA du client
    plan            tenant_plan NOT NULL DEFAULT 'starter',
    api_key_hash    VARCHAR(255),                   -- bcrypt hash de la clé API
    settings        JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_tenants_slug ON tenants(slug);

-- ============================================================
-- CORE : USERS
-- ============================================================

CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email           VARCHAR(255) NOT NULL,
    name            VARCHAR(255),
    role            VARCHAR(50) NOT NULL DEFAULT 'analyst',  -- admin | mlro | analyst
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, email)
);

-- ============================================================
-- KYB : BUSINESSES
-- ============================================================

CREATE TABLE businesses (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    company_number      VARCHAR(20) NOT NULL,
    registered_name     VARCHAR(500) NOT NULL,
    jurisdiction        CHAR(2) NOT NULL DEFAULT 'GB',
    incorporation_date  DATE,
    company_type        VARCHAR(100),
    sic_codes           TEXT[] DEFAULT '{}',
    registered_address  JSONB DEFAULT '{}',
    kyb_status          kyb_status NOT NULL DEFAULT 'pending',
    risk_score          SMALLINT CHECK (risk_score BETWEEN 0 AND 100),
    risk_level          risk_level,
    last_verified_at    TIMESTAMPTZ,
    next_review_due     DATE,
    raw_ch_data         JSONB DEFAULT '{}',         -- réponse brute Companies House
    metadata            JSONB DEFAULT '{}',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, company_number)
);

CREATE INDEX idx_businesses_tenant ON businesses(tenant_id);
CREATE INDEX idx_businesses_status ON businesses(kyb_status);
CREATE INDEX idx_businesses_review ON businesses(next_review_due) WHERE kyb_status = 'approved';
CREATE INDEX idx_businesses_risk ON businesses(risk_level);

-- ============================================================
-- KYC/KYB : PERSONS (dirigeants + UBOs)
-- ============================================================

CREATE TABLE persons (
    id                      UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id               UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    first_name              VARCHAR(255),
    last_name               VARCHAR(255) NOT NULL,
    full_name               VARCHAR(500) GENERATED ALWAYS AS (
                                COALESCE(first_name || ' ', '') || last_name
                            ) STORED,
    date_of_birth           DATE,
    nationality             CHAR(2),                -- ISO 3166-1 alpha-2
    country_of_residence    CHAR(2),
    is_pep                  BOOLEAN NOT NULL DEFAULT FALSE,
    pep_detail              JSONB,
    sanctions_hit           BOOLEAN NOT NULL DEFAULT FALSE,
    idv_status              idv_status NOT NULL DEFAULT 'not_started',
    idv_provider_ref        VARCHAR(255),           -- référence chez ComplyCube/Onfido
    screening_last_run      TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_persons_tenant ON persons(tenant_id);
CREATE INDEX idx_persons_pep ON persons(is_pep) WHERE is_pep = TRUE;
CREATE INDEX idx_persons_sanctions ON persons(sanctions_hit) WHERE sanctions_hit = TRUE;

-- ============================================================
-- KYB : UBOs (personnes avec contrôle significatif)
-- ============================================================

CREATE TABLE ubos (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    business_id     UUID NOT NULL REFERENCES businesses(id) ON DELETE CASCADE,
    person_id       UUID NOT NULL REFERENCES persons(id),
    ownership_pct   NUMERIC(5,2),                  -- % de détention
    ownership_type  VARCHAR(50),                   -- direct | indirect | voting
    is_controlling  BOOLEAN NOT NULL DEFAULT FALSE,
    source          VARCHAR(50) DEFAULT 'companies_house',
    verified_at     TIMESTAMPTZ,
    UNIQUE(business_id, person_id)
);

-- Structures d'actionnariat imbriquées (corporate PSCs)
CREATE TABLE ownership_chains (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    parent_id       UUID NOT NULL REFERENCES businesses(id),
    child_id        UUID NOT NULL REFERENCES businesses(id),
    ownership_pct   NUMERIC(5,2),
    depth           SMALLINT NOT NULL DEFAULT 1,   -- niveau d'imbrication
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (parent_id != child_id)
);

-- ============================================================
-- AML : SCREENINGS
-- ============================================================

CREATE TABLE screenings (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    subject_id      UUID NOT NULL,                 -- business_id ou person_id
    subject_type    subject_type NOT NULL,
    provider        VARCHAR(50) NOT NULL,           -- namescan | dilisense | complycube
    type            screening_type NOT NULL,
    status          screening_status NOT NULL DEFAULT 'pending',
    result          JSONB DEFAULT '{}',
    hits_count      SMALLINT NOT NULL DEFAULT 0,
    false_positive  BOOLEAN NOT NULL DEFAULT FALSE,
    reviewed_by     UUID REFERENCES users(id),
    reviewed_at     TIMESTAMPTZ,
    raw_response    JSONB DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_screenings_tenant ON screenings(tenant_id);
CREATE INDEX idx_screenings_subject ON screenings(subject_id);
CREATE INDEX idx_screenings_status ON screenings(status);
CREATE INDEX idx_screenings_created ON screenings(created_at DESC);

-- ============================================================
-- AML : ALERTS
-- ============================================================

CREATE TABLE alerts (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    business_id     UUID REFERENCES businesses(id),
    screening_id    UUID REFERENCES screenings(id),
    type            alert_type NOT NULL,
    severity        alert_severity NOT NULL,
    status          alert_status NOT NULL DEFAULT 'open',
    description     TEXT,
    sar_required    BOOLEAN NOT NULL DEFAULT FALSE,
    assigned_to     UUID REFERENCES users(id),
    resolved_at     TIMESTAMPTZ,
    notes           JSONB DEFAULT '[]',             -- [{user_id, text, created_at}]
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_alerts_tenant ON alerts(tenant_id);
CREATE INDEX idx_alerts_status ON alerts(status) WHERE status = 'open';
CREATE INDEX idx_alerts_severity ON alerts(severity);

-- ============================================================
-- CASS 15 : SAFEGUARDING RECORDS (réconciliation quotidienne)
-- ============================================================

CREATE TABLE safeguarding_records (
    id                      UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id               UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    record_date             DATE NOT NULL,
    total_relevant_funds    NUMERIC(18,2) NOT NULL,  -- fonds clients totaux (£)
    safeguarded_amount      NUMERIC(18,2) NOT NULL,  -- montant dans comptes ségrégués
    shortfall               NUMERIC(18,2) GENERATED ALWAYS AS (
                                total_relevant_funds - safeguarded_amount
                            ) STORED,
    accounts                JSONB DEFAULT '[]',       -- [{bank, account_no, balance}]
    reconciled              BOOLEAN NOT NULL DEFAULT FALSE,
    reconciled_at           TIMESTAMPTZ,
    discrepancy_notes       TEXT,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, record_date)
);

CREATE INDEX idx_safeguarding_tenant_date ON safeguarding_records(tenant_id, record_date DESC);
CREATE INDEX idx_safeguarding_unreconciled ON safeguarding_records(tenant_id)
    WHERE reconciled = FALSE;

-- ============================================================
-- FCA REPORTS : Rapports réglementaires
-- ============================================================

CREATE TABLE fca_reports (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    report_type     fca_report_type NOT NULL,
    period_start    DATE NOT NULL,
    period_end      DATE NOT NULL,
    status          report_status NOT NULL DEFAULT 'draft',
    submitted_at    TIMESTAMPTZ,
    payload         JSONB DEFAULT '{}',             -- données du rapport
    pdf_url         TEXT,                           -- URL S3/Storage du PDF généré
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, report_type, period_start)
);

CREATE INDEX idx_fca_reports_tenant ON fca_reports(tenant_id);
CREATE INDEX idx_fca_reports_status ON fca_reports(status);

-- ============================================================
-- AUDIT LOG (immuable — ne jamais faire de UPDATE/DELETE)
-- ============================================================

CREATE TABLE audit_log (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       UUID NOT NULL,                  -- pas de FK pour préserver après suppression tenant
    user_id         UUID,
    action          VARCHAR(100) NOT NULL,
    entity_type     VARCHAR(50),
    entity_id       UUID,
    before          JSONB,
    after           JSONB,
    ip_address      INET,
    user_agent      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Partition par mois pour les gros volumes (optionnel, activer si >10M rows/mois)
CREATE INDEX idx_audit_tenant ON audit_log(tenant_id);
CREATE INDEX idx_audit_entity ON audit_log(entity_id);
CREATE INDEX idx_audit_action ON audit_log(action);
CREATE INDEX idx_audit_created ON audit_log(created_at DESC);

-- ============================================================
-- FONCTIONS UTILITAIRES
-- ============================================================

-- Mise à jour auto du updated_at
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_tenants_updated_at    BEFORE UPDATE ON tenants    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER trg_businesses_updated_at BEFORE UPDATE ON businesses FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER trg_alerts_updated_at     BEFORE UPDATE ON alerts     FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER trg_fca_reports_updated   BEFORE UPDATE ON fca_reports FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ============================================================
-- SEED : Tenant de développement
-- ============================================================

INSERT INTO tenants (id, name, slug, fca_firm_ref, plan)
VALUES (
    '00000000-0000-0000-0000-000000000001',
    'Dev Fintech Ltd',
    'dev-fintech',
    '800000',
    'growth'
);

INSERT INTO users (tenant_id, email, name, role)
VALUES (
    '00000000-0000-0000-0000-000000000001',
    'admin@devfintech.co.uk',
    'Admin User',
    'admin'
);
