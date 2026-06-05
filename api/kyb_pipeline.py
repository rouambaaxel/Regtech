"""
ComplianceOS — KYB Orchestrator
Pipeline complet : Companies House → AML Screening → Risk Score → DB

Dépendances :
    pip install httpx asyncpg python-dotenv

Usage :
    python kyb_pipeline.py
"""

import asyncio
import asyncpg
import uuid
import os
import json
import logging
from datetime import datetime, timezone, date
from dotenv import load_dotenv

from companies_house import CompaniesHouseClient
from aml_screening import AMLScreeningOrchestrator

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
# RISK SCORING
# ─────────────────────────────────────────────
def compute_final_risk(base_score: int, aml_bump: int, flags: list[str]) -> tuple[int, str]:
    """
    Combine le score de base KYB (structures) et le bump AML (sanctions/PEP).
    Retourne (score 0–100, level 'low'|'medium'|'high'|'critical')
    """
    total = min(base_score + aml_bump, 100)

    if total >= 80 or "sanctions_hit" in " ".join(flags):
        level = "critical"
    elif total >= 60 or any("pep" in f for f in flags):
        level = "high"
    elif total >= 30:
        level = "medium"
    else:
        level = "low"

    return total, level


# ─────────────────────────────────────────────
# DB HELPERS (asyncpg)
# ─────────────────────────────────────────────
async def upsert_business(conn, tenant_id: str, kyb_data: dict, risk_score: int, risk_level: str) -> str:
    """Insert ou update la table businesses. Retourne l'UUID."""
    business_id = str(uuid.uuid4())

    await conn.execute("""
        INSERT INTO businesses (
            id, tenant_id, company_number, registered_name, jurisdiction,
            incorporation_date, sic_codes, registered_address,
            kyb_status, risk_score, risk_level,
            last_verified_at, next_review_due, raw_ch_data
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,
            CURRENT_DATE + INTERVAL '12 months', $13)
        ON CONFLICT (tenant_id, company_number)
        DO UPDATE SET
            registered_name = EXCLUDED.registered_name,
            kyb_status = EXCLUDED.kyb_status,
            risk_score = EXCLUDED.risk_score,
            risk_level = EXCLUDED.risk_level,
            last_verified_at = EXCLUDED.last_verified_at,
            next_review_due = EXCLUDED.next_review_due,
            raw_ch_data = EXCLUDED.raw_ch_data
        RETURNING id
    """,
        business_id,
        tenant_id,
        kyb_data["company_number"],
        kyb_data["company_name"],
        "GB",
        date.fromisoformat(kyb_data["incorporation_date"]) if kyb_data.get("incorporation_date") else None,
        kyb_data.get("sic_codes", []),
        json.dumps(kyb_data.get("registered_address", {})),
        "approved" if risk_level in ("low", "medium") else "review_required",
        risk_score,
        risk_level,
        datetime.now(timezone.utc),
        json.dumps(kyb_data),
    )

    # Récupérer l'ID réel (peut être l'ancien si conflict)
    row = await conn.fetchrow(
        "SELECT id FROM businesses WHERE tenant_id=$1 AND company_number=$2",
        tenant_id, kyb_data["company_number"]
    )
    return str(row["id"])


async def insert_screening(conn, tenant_id: str, business_id: str, screening_data: dict) -> str:
    """Persiste le résultat du screening AML."""
    screening_id = str(uuid.uuid4())

    await conn.execute("""
        INSERT INTO screenings (
            id, tenant_id, subject_id, subject_type, provider,
            type, status, result, hits_count, raw_response, created_at
        ) VALUES ($1,$2,$3,'business','namescan','full_kyb',$4,$5,$6,$7,$8)
    """,
        screening_id,
        tenant_id,
        business_id,
        "hit" if screening_data["total_hits"] > 0 else "clear",
        json.dumps({
            "total_hits": screening_data["total_hits"],
            "any_pep": screening_data["any_pep"],
            "any_sanctions": screening_data["any_sanctions"],
            "persons": screening_data["person_results"],
        }),
        screening_data["total_hits"],
        json.dumps(screening_data),
        datetime.now(timezone.utc),
    )

    return screening_id


async def create_alert_if_needed(conn, tenant_id: str, business_id: str, screening_id: str, screening_data: dict):
    """Crée une alerte si le screening a des hits."""
    if not screening_data["requires_edd"]:
        return

    alert_id = str(uuid.uuid4())
    alert_type = "sanctions_hit" if screening_data["any_sanctions"] else "pep_identified"
    severity = "critical" if screening_data["any_sanctions"] else "high"

    pep_names = [p["name"] for p in screening_data["person_results"] if p["is_pep"]]
    description = []
    if screening_data["any_sanctions"]:
        description.append(f"{screening_data['total_hits']} hit(s) sanctions détecté(s)")
    if pep_names:
        description.append(f"PEP identifié(s): {', '.join(pep_names)}")

    await conn.execute("""
        INSERT INTO alerts (
            id, tenant_id, business_id, screening_id,
            type, severity, status, description, sar_required, created_at
        ) VALUES ($1,$2,$3,$4,$5,$6,'open',$7,$8,$9)
    """,
        alert_id, tenant_id, business_id, screening_id,
        alert_type, severity,
        " | ".join(description),
        severity == "critical",  # SAR requis si critical
        datetime.now(timezone.utc),
    )

    logger.warning(f"ALERTE créée [{severity.upper()}]: {' | '.join(description)}")


async def write_audit_log(conn, tenant_id: str, entity_id: str, action: str, after: dict):
    """Audit trail FCA-compliant — immuable."""
    await conn.execute("""
        INSERT INTO audit_log (tenant_id, action, entity_type, entity_id, after, created_at)
        VALUES ($1,$2,'business',$3,$4,$5)
    """,
        tenant_id, action, entity_id,
        json.dumps(after),
        datetime.now(timezone.utc),
    )


# ─────────────────────────────────────────────
# PIPELINE PRINCIPAL
# ─────────────────────────────────────────────
async def run_kyb_pipeline(
    tenant_id: str,
    company_number: str,
    triggered_by: str = "api",
) -> dict:
    """
    Pipeline KYB complet :
    1. Fetch Companies House
    2. AML screening (société + dirigeants + UBOs)
    3. Calcul risk score
    4. Persistance DB
    5. Alertes si nécessaire
    6. Audit log

    Retourne un rapport structuré prêt à envoyer au client.
    """
    logger.info(f"[KYB] Démarrage pour {company_number} (tenant: {tenant_id})")
    started_at = datetime.now(timezone.utc)

    # 1. Companies House
    async with CompaniesHouseClient(os.environ["CH_API_KEY"]) as ch:
        kyb_data = await ch.full_kyb(company_number)

    logger.info(f"[KYB] CH OK — {kyb_data['company_name']} ({kyb_data['status']})")

    # 2. AML Screening
    orchestrator = AMLScreeningOrchestrator(os.environ["NAMESCAN_API_KEY"])
    screening = await orchestrator.screen_business_full(
        company_name=kyb_data["company_name"],
        officers=kyb_data["active_officers"],
        pscs=kyb_data["pscs"],
    )
    logger.info(f"[AML] Screening OK — {screening['total_hits']} hits, PEP: {screening['any_pep']}")

    # 3. Risk Score final
    risk_score, risk_level = compute_final_risk(
        base_score=kyb_data["risk_score_base"],
        aml_bump=screening["aml_risk_bump"],
        flags=kyb_data["risk_flags"],
    )
    logger.info(f"[RISK] Score final: {risk_score}/100 — Level: {risk_level.upper()}")

    # 4–6. Persistance DB
    db = await asyncpg.connect(os.environ["DATABASE_URL"])
    try:
        async with db.transaction():
            business_id = await upsert_business(db, tenant_id, kyb_data, risk_score, risk_level)
            screening_id = await insert_screening(db, tenant_id, business_id, screening)
            await create_alert_if_needed(db, tenant_id, business_id, screening_id, screening)
            await write_audit_log(db, tenant_id, business_id, f"kyb_completed_by_{triggered_by}", {
                "risk_score": risk_score,
                "risk_level": risk_level,
                "total_screening_hits": screening["total_hits"],
            })
    finally:
        await db.close()

    duration_ms = int((datetime.now(timezone.utc) - started_at).total_seconds() * 1000)
    logger.info(f"[KYB] Terminé en {duration_ms}ms")

    # Rapport final — c'est ce que tu retournes dans ton API REST / envoies par email au client
    return {
        "business_id": business_id,
        "company_number": kyb_data["company_number"],
        "company_name": kyb_data["company_name"],
        "status": kyb_data["status"],
        "incorporation_date": kyb_data.get("incorporation_date"),
        "registered_address": kyb_data["registered_address"],
        "active_directors": len(kyb_data["active_officers"]),
        "ubos_identified": len(kyb_data["pscs"]),
        "risk_score": risk_score,
        "risk_level": risk_level,
        "risk_flags": kyb_data["risk_flags"],
        "aml_summary": {
            "total_hits": screening["total_hits"],
            "any_pep": screening["any_pep"],
            "any_sanctions": screening["any_sanctions"],
            "requires_edd": screening["requires_edd"],
        },
        "kyb_status": "approved" if risk_level in ("low", "medium") else "review_required",
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "duration_ms": duration_ms,
    }


# ─────────────────────────────────────────────
# FASTAPI ENDPOINT (optionnel — coller dans main.py)
# ─────────────────────────────────────────────
"""
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel

app = FastAPI(title="ComplianceOS API")

class KYBRequest(BaseModel):
    company_number: str

@app.post("/api/v1/kyb")
async def trigger_kyb(
    body: KYBRequest,
    x_tenant_id: str = Header(...),
    x_api_key: str = Header(...),
):
    # TODO: valider x_api_key contre la table tenants
    try:
        result = await run_kyb_pipeline(
            tenant_id=x_tenant_id,
            company_number=body.company_number,
            triggered_by="api",
        )
        return result
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=422, detail=f"Companies House error: {e.response.status_code}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
"""

if __name__ == "__main__":
    result = asyncio.run(run_kyb_pipeline(
        tenant_id="00000000-0000-0000-0000-000000000001",   # tenant de test
        company_number="08804411",                           # Revolut Ltd
    ))
    import pprint
    pprint.pprint(result)
