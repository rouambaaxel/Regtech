# ComplianceOS

RegTech SaaS — KYB · AML · CASS 15 · FCA Reporting for UK fintechs.

## Stack

- **Backend**: Python 3.11 · FastAPI · asyncpg
- **DB**: PostgreSQL 16
- **Auth**: JWT (Bearer) + API key headers
- **External APIs**: Companies House (free) · NameScan · Dilisense · ComplyCube

## Structure

```
complianceos/
├── api/
│   ├── main.py               # Entry point + router registration
│   ├── routes.py             # KYB, AML, CASS15, Reports, Audit endpoints
│   ├── auth.py               # JWT auth — register/login/refresh/invite
│   ├── companies_house.py    # CH API client
│   ├── aml_screening.py      # NameScan/Dilisense screening
│   └── kyb_pipeline.py       # Full KYB orchestrator
├── db/
│   ├── init.sql              # Combined schema (used by Docker)
│   ├── schema.sql            # Core schema
│   └── auth_migration.sql    # Auth tables
├── frontend/
│   └── api.js                # JS API client (Next.js ready)
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── .env.example
```

## Quick start (Docker)

```bash
cp .env.example .env
# Edit .env — set CH_API_KEY, NAMESCAN_API_KEY, JWT_SECRET at minimum

docker compose up -d
# API → http://localhost:8000
# Docs → http://localhost:8000/docs
```

## Quick start (local)

```bash
pip install -r requirements.txt
cp .env.example .env

createdb complianceos
psql complianceos < db/init.sql

cd api && uvicorn main:app --reload
```

## Authentication

Two methods supported:

| Method | Header | Use case |
|--------|--------|----------|
| JWT Bearer | `Authorization: Bearer <token>` | Dashboard / web app |
| API Key | `X-Tenant-Id` + `X-Api-Key` | Server-to-server |

Get tokens via `POST /auth/register` (new org) or `POST /auth/login`.

## Key endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | /auth/register | Create organisation + admin user |
| POST | /auth/login | Login → JWT tokens |
| POST | /auth/refresh | Rotate refresh token |
| POST | /auth/invite | Invite team member (admin only) |
| GET | /api/v1/stats | Dashboard KPIs |
| GET | /api/v1/businesses | List businesses (KYB) |
| POST | /api/v1/kyb | Trigger KYB pipeline |
| GET | /api/v1/alerts | AML alerts |
| PATCH | /api/v1/alerts/:id | Update alert status |
| POST | /api/v1/alerts/:id/sar | File SAR to NCA |
| GET | /api/v1/cass15/reconciliations | CASS 15 daily records |
| POST | /api/v1/cass15/reconciliations | Submit reconciliation |
| GET | /api/v1/cass15/sup16-return | Generate SUP 16.14A data |
| GET | /api/v1/reports | FCA reports |
| POST | /api/v1/reports/:id/submit | Submit to FCA |
| GET | /api/v1/audit | Immutable audit log |

## Tenant plans

`starter` · `growth` · `scale` · `enterprise`

## Required env vars

| Variable | Source | Cost |
|----------|--------|------|
| DATABASE_URL | Supabase / Railway / local | ~£5/mo |
| JWT_SECRET | Generate: `openssl rand -hex 32` | Free |
| CH_API_KEY | developer.company-information.service.gov.uk | Free |
| NAMESCAN_API_KEY | namescan.io | ~£50/mo |
| COMPLYCUBE_API_KEY | complycube.com | ~£0.50/check |
