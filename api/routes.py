"""
ComplianceOS — FastAPI Routes
Endpoints complets : KYB, AML, CASS 15, Alerts, Reports, Audit
"""

from fastapi import FastAPI, HTTPException, Header, Depends, Query, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from typing import Optional, Literal
from datetime import date, datetime, timezone
from contextlib import asynccontextmanager
from enum import Enum
import asyncpg
import uuid
import os
import json
import logging

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Démarre le scheduler APScheduler au boot, l'arrête à l'extinction."""
    from scheduler import setup_scheduler, scheduler
    setup_scheduler()
    scheduler.start()
    logger.info("[BOOT] APScheduler started — 4 jobs active")
    yield
    scheduler.shutdown(wait=False)
    logger.info("[SHUTDOWN] APScheduler stopped")


app = FastAPI(
    title="ComplianceOS API",
    version="2.2.0",
    description="RegTech KYB/AML/CASS15 + Transaction Monitoring platform for UK fintechs",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─────────────────────────────────────────────
# DB DEPENDENCY
# ─────────────────────────────────────────────
async def get_db():
    conn = await asyncpg.connect(os.environ["DATABASE_URL"])
    try:
        yield conn
    finally:
        await conn.close()


# ─────────────────────────────────────────────
# AUTH DEPENDENCY  (JWT Bearer or API key headers)
# ─────────────────────────────────────────────
_bearer = HTTPBearer(auto_error=False)

async def get_tenant(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
    x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-Id"),
    x_api_key: Optional[str] = Header(None, alias="X-Api-Key"),
    db: asyncpg.Connection = Depends(get_db),
) -> str:
    """Accept JWT Bearer (from auth.py) or legacy X-Tenant-Id + X-Api-Key headers."""
    # --- JWT path ---
    if credentials:
        import jwt as pyjwt
        try:
            payload = pyjwt.decode(
                credentials.credentials,
                os.environ.get("JWT_SECRET", "change_me"),
                algorithms=["HS256"],
            )
            if payload.get("type") != "access":
                raise HTTPException(status_code=401, detail="Invalid token type")
            user = await db.fetchrow(
                "SELECT tenant_id FROM users WHERE id = $1 AND is_active = TRUE",
                payload["sub"],
            )
            if not user:
                raise HTTPException(status_code=401, detail="User not found")
            return str(user["tenant_id"])
        except pyjwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token expired")
        except pyjwt.InvalidTokenError:
            raise HTTPException(status_code=401, detail="Invalid token")

    # --- API key path ---
    if x_tenant_id and x_api_key:
        import bcrypt
        row = await db.fetchrow(
            "SELECT id, api_key_hash FROM tenants WHERE id = $1", x_tenant_id
        )
        if not row:
            raise HTTPException(status_code=401, detail="Invalid tenant")
        if not bcrypt.checkpw(x_api_key.encode(), row["api_key_hash"].encode()):
            raise HTTPException(status_code=401, detail="Invalid API key")
        return x_tenant_id

    raise HTTPException(status_code=401, detail="Authentication required")


# ─────────────────────────────────────────────
# SCHEMAS
# ─────────────────────────────────────────────
class KYBRequest(BaseModel):
    company_number: str = Field(..., min_length=6, max_length=8, example="08804411")
    notes: Optional[str] = None

class AlertUpdateRequest(BaseModel):
    status: Literal["open", "investigating", "resolved", "false_positive"]
    notes: Optional[str] = None

class SARRequest(BaseModel):
    alert_id: str
    suspicion_narrative: str = Field(..., min_length=50)
    persons_involved: list[str]

class ReconciliationRequest(BaseModel):
    record_date: date
    total_relevant_funds: float
    safeguarded_amount: float
    accounts: list[dict] = []
    discrepancy_notes: Optional[str] = None

class ReportRequest(BaseModel):
    report_type: Literal["cass15_daily_recon", "sup16_14a_monthly", "cass10_resolution_pack", "sup3a_annual_audit"]
    period_start: date
    period_end: date
    payload: dict = {}
    mlro_sign_off: bool = False

class PaginationParams(BaseModel):
    page: int = 1
    per_page: int = 25

class TransactionRequest(BaseModel):
    business_id: Optional[str] = None
    amount: float = Field(..., gt=0)
    currency: str = Field(default="GBP", min_length=3, max_length=3)
    beneficiary_name: Optional[str] = None
    beneficiary_country: Optional[str] = Field(None, min_length=2, max_length=2)
    beneficiary_iban: Optional[str] = None
    reference: Optional[str] = None
    tx_type: Optional[str] = None
    channel: Optional[str] = None
    raw_data: dict = {}


# ─────────────────────────────────────────────
# UTILS
# ─────────────────────────────────────────────
def paginate(query: str, page: int, per_page: int) -> tuple[str, int, int]:
    offset = (page - 1) * per_page
    return f"{query} LIMIT {per_page} OFFSET {offset}", per_page, offset

async def write_audit(db, tenant_id: str, action: str, entity_type: str, entity_id: str, after: dict, user_id: str = None):
    await db.execute(
        """INSERT INTO audit_log (tenant_id, user_id, action, entity_type, entity_id, after, created_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7)""",
        tenant_id, user_id, action, entity_type, entity_id,
        json.dumps(after), datetime.now(timezone.utc)
    )

def sc(v): return float(v) if v is not None else 0.0


# ═══════════════════════════════════════════════════════════
# ROOT
# ═══════════════════════════════════════════════════════════
@app.get("/")
async def root():
    return {"service": "ComplianceOS API", "version": "2.1.0", "status": "operational"}

@app.get("/health")
async def health(db: asyncpg.Connection = Depends(get_db)):
    await db.fetchval("SELECT 1")
    return {"status": "healthy", "db": "connected", "ts": datetime.now(timezone.utc).isoformat()}


# ═══════════════════════════════════════════════════════════
# KYB — BUSINESSES
# ═══════════════════════════════════════════════════════════
@app.get("/api/v1/businesses")
async def list_businesses(
    status: Optional[str] = Query(None),
    risk_level: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    per_page: int = Query(25, ge=1, le=100),
    tenant_id: str = Depends(get_tenant),
    db: asyncpg.Connection = Depends(get_db),
):
    """List all businesses with filtering and pagination."""
    conditions = ["tenant_id = $1"]
    params = [tenant_id]
    i = 2

    if status:
        conditions.append(f"kyb_status = ${i}"); params.append(status); i += 1
    if risk_level:
        conditions.append(f"risk_level = ${i}"); params.append(risk_level); i += 1
    if search:
        conditions.append(f"(registered_name ILIKE ${i} OR company_number ILIKE ${i})")
        params.append(f"%{search}%"); i += 1

    where = " AND ".join(conditions)
    total = await db.fetchval(f"SELECT COUNT(*) FROM businesses WHERE {where}", *params)
    rows = await db.fetch(
        f"""SELECT id, company_number, registered_name, jurisdiction,
               kyb_status, risk_score, risk_level, last_verified_at,
               next_review_due, created_at
            FROM businesses WHERE {where}
            ORDER BY created_at DESC
            LIMIT {per_page} OFFSET {(page-1)*per_page}""",
        *params
    )

    return {
        "data": [dict(r) for r in rows],
        "pagination": {"total": total, "page": page, "per_page": per_page, "pages": -(-total // per_page)},
    }


@app.get("/api/v1/businesses/{business_id}")
async def get_business(
    business_id: str,
    tenant_id: str = Depends(get_tenant),
    db: asyncpg.Connection = Depends(get_db),
):
    """Full business profile with UBOs, persons, and latest screening."""
    biz = await db.fetchrow(
        "SELECT * FROM businesses WHERE id = $1 AND tenant_id = $2",
        business_id, tenant_id
    )
    if not biz:
        raise HTTPException(status_code=404, detail="Business not found")

    ubos = await db.fetch(
        """SELECT u.*, p.first_name, p.last_name, p.nationality,
              p.is_pep, p.sanctions_hit, p.idv_status
           FROM ubos u JOIN persons p ON u.person_id = p.id
           WHERE u.business_id = $1""",
        business_id
    )

    screening = await db.fetchrow(
        """SELECT * FROM screenings
           WHERE subject_id = $1 AND subject_type = 'business'
           ORDER BY created_at DESC LIMIT 1""",
        business_id
    )

    alerts = await db.fetch(
        "SELECT id, type, severity, status, description, created_at FROM alerts WHERE business_id = $1 AND status != 'resolved' ORDER BY created_at DESC",
        business_id
    )

    return {
        **dict(biz),
        "ubos": [dict(u) for u in ubos],
        "latest_screening": dict(screening) if screening else None,
        "active_alerts": [dict(a) for a in alerts],
    }


@app.post("/api/v1/kyb", status_code=202)
async def run_kyb(
    body: KYBRequest,
    background_tasks: BackgroundTasks,
    tenant_id: str = Depends(get_tenant),
    db: asyncpg.Connection = Depends(get_db),
):
    """
    Trigger KYB pipeline asynchronously.
    Returns a job_id to poll via GET /api/v1/kyb/jobs/{job_id}
    """
    job_id = str(uuid.uuid4())

    # Store job in DB
    await db.execute(
        """INSERT INTO audit_log (tenant_id, action, entity_type, entity_id, after, created_at)
           VALUES ($1,'kyb_job_queued','kyb_job',$2,$3,$4)""",
        tenant_id, job_id,
        json.dumps({"company_number": body.company_number, "status": "queued"}),
        datetime.now(timezone.utc)
    )

    # Queue background task
    background_tasks.add_task(
        _run_kyb_background,
        tenant_id=tenant_id,
        company_number=body.company_number,
        job_id=job_id,
    )

    return {"job_id": job_id, "status": "queued", "company_number": body.company_number}


async def _run_kyb_background(tenant_id: str, company_number: str, job_id: str):
    """Background KYB pipeline execution."""
    try:
        from kyb_pipeline import run_kyb_pipeline
        result = await run_kyb_pipeline(tenant_id, company_number, triggered_by="api")
        logger.info(f"KYB completed: {company_number} — {result['risk_level']}")
    except Exception as e:
        logger.error(f"KYB failed for {company_number}: {e}")


@app.get("/api/v1/kyb/jobs/{job_id}")
async def get_kyb_job(
    job_id: str,
    tenant_id: str = Depends(get_tenant),
    db: asyncpg.Connection = Depends(get_db),
):
    """Poll KYB job status."""
    row = await db.fetchrow(
        "SELECT after FROM audit_log WHERE entity_id = $1 AND tenant_id = $2 ORDER BY created_at DESC LIMIT 1",
        job_id, tenant_id
    )
    if not row:
        raise HTTPException(status_code=404, detail="Job not found")
    return json.loads(row["after"])


@app.post("/api/v1/businesses/{business_id}/rescreen")
async def rescreen_business(
    business_id: str,
    background_tasks: BackgroundTasks,
    tenant_id: str = Depends(get_tenant),
    db: asyncpg.Connection = Depends(get_db),
):
    """Trigger AML re-screening for an existing business."""
    biz = await db.fetchrow(
        "SELECT company_number, registered_name FROM businesses WHERE id = $1 AND tenant_id = $2",
        business_id, tenant_id
    )
    if not biz:
        raise HTTPException(status_code=404, detail="Business not found")

    await write_audit(db, tenant_id, "rescreen_triggered", "business", business_id, {"triggered_by": "api"})
    return {"status": "queued", "business_id": business_id, "company": biz["registered_name"]}


# ═══════════════════════════════════════════════════════════
# AML ALERTS
# ═══════════════════════════════════════════════════════════
@app.get("/api/v1/alerts")
async def list_alerts(
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    per_page: int = Query(25, ge=1, le=100),
    tenant_id: str = Depends(get_tenant),
    db: asyncpg.Connection = Depends(get_db),
):
    """List AML alerts with filters."""
    conditions = ["a.tenant_id = $1"]
    params = [tenant_id]
    i = 2

    if status:
        conditions.append(f"a.status = ${i}"); params.append(status); i += 1
    if severity:
        conditions.append(f"a.severity = ${i}"); params.append(severity); i += 1

    where = " AND ".join(conditions)
    total = await db.fetchval(f"SELECT COUNT(*) FROM alerts a WHERE {where}", *params)
    rows = await db.fetch(
        f"""SELECT a.*, b.registered_name AS company_name, b.company_number
            FROM alerts a
            LEFT JOIN businesses b ON a.business_id = b.id
            WHERE {where}
            ORDER BY
              CASE a.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END,
              a.created_at DESC
            LIMIT {per_page} OFFSET {(page-1)*per_page}""",
        *params
    )

    return {
        "data": [dict(r) for r in rows],
        "pagination": {"total": total, "page": page, "per_page": per_page, "pages": -(-total // per_page)},
        "summary": {
            "open": await db.fetchval("SELECT COUNT(*) FROM alerts WHERE tenant_id=$1 AND status='open'", tenant_id),
            "critical": await db.fetchval("SELECT COUNT(*) FROM alerts WHERE tenant_id=$1 AND severity='critical' AND status!='resolved'", tenant_id),
            "sar_required": await db.fetchval("SELECT COUNT(*) FROM alerts WHERE tenant_id=$1 AND sar_required=TRUE AND status!='resolved'", tenant_id),
        }
    }


@app.get("/api/v1/alerts/{alert_id}")
async def get_alert(
    alert_id: str,
    tenant_id: str = Depends(get_tenant),
    db: asyncpg.Connection = Depends(get_db),
):
    row = await db.fetchrow(
        """SELECT a.*, b.registered_name, b.company_number, b.risk_level
           FROM alerts a LEFT JOIN businesses b ON a.business_id = b.id
           WHERE a.id = $1 AND a.tenant_id = $2""",
        alert_id, tenant_id
    )
    if not row:
        raise HTTPException(status_code=404, detail="Alert not found")
    return dict(row)


@app.patch("/api/v1/alerts/{alert_id}")
async def update_alert(
    alert_id: str,
    body: AlertUpdateRequest,
    tenant_id: str = Depends(get_tenant),
    db: asyncpg.Connection = Depends(get_db),
):
    """Update alert status (investigating, resolved, false_positive)."""
    existing = await db.fetchrow("SELECT id, status FROM alerts WHERE id=$1 AND tenant_id=$2", alert_id, tenant_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Alert not found")

    resolved_at = datetime.now(timezone.utc) if body.status == "resolved" else None
    await db.execute(
        "UPDATE alerts SET status=$1, resolved_at=$2, updated_at=$3 WHERE id=$4",
        body.status, resolved_at, datetime.now(timezone.utc), alert_id
    )

    if body.notes:
        await db.execute(
            "UPDATE alerts SET notes = notes || $1::jsonb WHERE id=$2",
            json.dumps([{"text": body.notes, "created_at": datetime.now(timezone.utc).isoformat()}]),
            alert_id
        )

    await write_audit(db, tenant_id, f"alert_{body.status}", "alert", alert_id,
                      {"status": body.status, "notes": body.notes})

    return {"status": "updated", "alert_id": alert_id, "new_status": body.status}


@app.post("/api/v1/alerts/{alert_id}/sar")
async def file_sar(
    alert_id: str,
    body: SARRequest,
    tenant_id: str = Depends(get_tenant),
    db: asyncpg.Connection = Depends(get_db),
):
    """
    File a Suspicious Activity Report to NCA.
    In production: integrate with NCA SARs Online API.
    """
    alert = await db.fetchrow("SELECT * FROM alerts WHERE id=$1 AND tenant_id=$2", alert_id, tenant_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    if not alert["sar_required"]:
        raise HTTPException(status_code=400, detail="SAR not required for this alert")

    # Generate SAR reference (in prod: submit to NCA SARs Online)
    sar_ref = f"SAR-{datetime.now().year}-{str(uuid.uuid4())[:8].upper()}"

    await db.execute(
        "UPDATE alerts SET status='resolved', notes = notes || $1::jsonb WHERE id=$2",
        json.dumps([{"sar_ref": sar_ref, "filed_at": datetime.now(timezone.utc).isoformat()}]),
        alert_id
    )

    await write_audit(db, tenant_id, "sar_filed", "alert", alert_id, {
        "sar_ref": sar_ref,
        "persons": body.persons_involved,
        "narrative_length": len(body.suspicion_narrative),
    })

    return {
        "sar_reference": sar_ref,
        "status": "filed",
        "filed_at": datetime.now(timezone.utc).isoformat(),
        "next_steps": "Do not tip off the subject. Monitor account. Keep SAR reference for FCA inspection.",
    }


# ═══════════════════════════════════════════════════════════
# CASS 15 — SAFEGUARDING
# ═══════════════════════════════════════════════════════════
@app.get("/api/v1/cass15/reconciliations")
async def list_reconciliations(
    days: int = Query(30, ge=1, le=365),
    tenant_id: str = Depends(get_tenant),
    db: asyncpg.Connection = Depends(get_db),
):
    """Daily reconciliation records for CASS 15 compliance."""
    rows = await db.fetch(
        """SELECT * FROM safeguarding_records
           WHERE tenant_id = $1 AND record_date >= CURRENT_DATE - $2::int
           ORDER BY record_date DESC""",
        tenant_id, days
    )

    total_days = len(rows)
    reconciled_days = sum(1 for r in rows if r["reconciled"])
    total_funds = sum(sc(r["total_relevant_funds"]) for r in rows)
    total_shortfall = sum(sc(r["shortfall"]) for r in rows if r["shortfall"])

    return {
        "data": [dict(r) for r in rows],
        "summary": {
            "days_total": total_days,
            "days_reconciled": reconciled_days,
            "reconciliation_rate": round(reconciled_days / total_days * 100, 1) if total_days else 0,
            "avg_daily_funds": round(total_funds / total_days, 2) if total_days else 0,
            "total_shortfall_days": sum(1 for r in rows if r["shortfall"] and sc(r["shortfall"]) > 0),
            "total_shortfall_amount": round(total_shortfall, 2),
        }
    }


@app.post("/api/v1/cass15/reconciliations", status_code=201)
async def create_reconciliation(
    body: ReconciliationRequest,
    tenant_id: str = Depends(get_tenant),
    db: asyncpg.Connection = Depends(get_db),
):
    """
    Submit daily safeguarding reconciliation.
    Required by FCA CASS 15 / PS25/12 from May 7, 2026.
    """
    # Check for duplicate
    existing = await db.fetchrow(
        "SELECT id FROM safeguarding_records WHERE tenant_id=$1 AND record_date=$2",
        tenant_id, body.record_date
    )
    if existing:
        raise HTTPException(status_code=409, detail=f"Reconciliation already exists for {body.record_date}")

    rec_id = str(uuid.uuid4())
    shortfall = body.total_relevant_funds - body.safeguarded_amount

    await db.execute(
        """INSERT INTO safeguarding_records
           (id, tenant_id, record_date, total_relevant_funds, safeguarded_amount,
            accounts, reconciled, reconciled_at, discrepancy_notes)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)""",
        rec_id, tenant_id, body.record_date,
        body.total_relevant_funds, body.safeguarded_amount,
        json.dumps(body.accounts),
        shortfall <= 0,
        datetime.now(timezone.utc) if shortfall <= 0 else None,
        body.discrepancy_notes,
    )

    # Auto-create alert if shortfall > 0
    if shortfall > 0:
        alert_id = str(uuid.uuid4())
        await db.execute(
            """INSERT INTO alerts (id, tenant_id, type, severity, status, description, sar_required, created_at)
               VALUES ($1,$2,'cass15_shortfall',$3,'open',$4,FALSE,$5)""",
            alert_id, tenant_id,
            "critical" if shortfall > 50000 else "high",
            f"CASS 15 shortfall of £{shortfall:,.0f} on {body.record_date}. {body.discrepancy_notes or 'Under investigation.'}",
            datetime.now(timezone.utc)
        )

    await write_audit(db, tenant_id, "cass15_recon_submitted", "safeguarding", rec_id, {
        "date": str(body.record_date),
        "funds": body.total_relevant_funds,
        "safeguarded": body.safeguarded_amount,
        "shortfall": shortfall,
    })

    return {
        "id": rec_id,
        "record_date": str(body.record_date),
        "total_relevant_funds": body.total_relevant_funds,
        "safeguarded_amount": body.safeguarded_amount,
        "shortfall": shortfall,
        "reconciled": shortfall <= 0,
        "alert_created": shortfall > 0,
    }


@app.get("/api/v1/cass15/sup16-return")
async def get_sup16_return(
    year: int = Query(...),
    month: int = Query(..., ge=1, le=12),
    tenant_id: str = Depends(get_tenant),
    db: asyncpg.Connection = Depends(get_db),
):
    """
    Generate SUP 16.14A Monthly Safeguarding Return data.
    Required monthly submission to FCA under PS25/12.
    """
    from calendar import monthrange
    _, last_day = monthrange(year, month)
    period_start = date(year, month, 1)
    period_end = date(year, month, last_day)

    rows = await db.fetch(
        """SELECT * FROM safeguarding_records
           WHERE tenant_id=$1 AND record_date BETWEEN $2 AND $3
           ORDER BY record_date""",
        tenant_id, period_start, period_end
    )

    if not rows:
        raise HTTPException(status_code=404, detail="No reconciliation data for this period")

    funds = [sc(r["total_relevant_funds"]) for r in rows]
    safeguarded = [sc(r["safeguarded_amount"]) for r in rows]
    shortfalls = [sc(r["shortfall"]) for r in rows if r["shortfall"] and sc(r["shortfall"]) > 0]

    return {
        "report_type": "SUP 16.14A",
        "period": {"start": str(period_start), "end": str(period_end)},
        "days_in_period": len(rows),
        "safeguarding_data": {
            "avg_daily_relevant_funds": round(sum(funds) / len(funds), 2),
            "min_daily_relevant_funds": round(min(funds), 2),
            "max_daily_relevant_funds": round(max(funds), 2),
            "avg_daily_safeguarded": round(sum(safeguarded) / len(safeguarded), 2),
            "avg_coverage_rate": round(sum(safeguarded) / sum(funds) * 100, 2),
            "days_with_shortfall": len(shortfalls),
            "total_shortfall_amount": round(sum(shortfalls), 2),
        },
        "reconciliation": {
            "days_reconciled": sum(1 for r in rows if r["reconciled"]),
            "days_total": len(rows),
            "rate": round(sum(1 for r in rows if r["reconciled"]) / len(rows) * 100, 1),
        },
        "ready_to_submit": len(shortfalls) == 0 or all(r.get("discrepancy_notes") for r in rows if r["shortfall"]),
    }


# ═══════════════════════════════════════════════════════════
# FCA REPORTS
# ═══════════════════════════════════════════════════════════
@app.get("/api/v1/reports")
async def list_reports(
    tenant_id: str = Depends(get_tenant),
    db: asyncpg.Connection = Depends(get_db),
):
    rows = await db.fetch(
        "SELECT * FROM fca_reports WHERE tenant_id=$1 ORDER BY created_at DESC",
        tenant_id
    )
    return {"data": [dict(r) for r in rows]}


@app.post("/api/v1/reports", status_code=201)
async def create_report(
    body: ReportRequest,
    tenant_id: str = Depends(get_tenant),
    db: asyncpg.Connection = Depends(get_db),
):
    report_id = str(uuid.uuid4())
    status = "ready" if body.mlro_sign_off else "draft"

    await db.execute(
        """INSERT INTO fca_reports
           (id, tenant_id, report_type, period_start, period_end, status, payload, created_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8)""",
        report_id, tenant_id, body.report_type,
        body.period_start, body.period_end, status,
        json.dumps(body.payload), datetime.now(timezone.utc)
    )

    await write_audit(db, tenant_id, "report_created", "fca_report", report_id, {
        "type": body.report_type,
        "period": f"{body.period_start} — {body.period_end}",
        "status": status,
    })

    return {"id": report_id, "status": status, "report_type": body.report_type}


@app.post("/api/v1/reports/{report_id}/submit")
async def submit_report(
    report_id: str,
    tenant_id: str = Depends(get_tenant),
    db: asyncpg.Connection = Depends(get_db),
):
    """Mark report as submitted to FCA. In prod: integrate with FCA RegData API."""
    report = await db.fetchrow("SELECT * FROM fca_reports WHERE id=$1 AND tenant_id=$2", report_id, tenant_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    if report["status"] not in ("ready", "draft"):
        raise HTTPException(status_code=400, detail=f"Cannot submit report with status '{report['status']}'")

    await db.execute(
        "UPDATE fca_reports SET status='submitted', submitted_at=$1 WHERE id=$2",
        datetime.now(timezone.utc), report_id
    )
    await write_audit(db, tenant_id, "report_submitted", "fca_report", report_id, {"submitted_at": datetime.now(timezone.utc).isoformat()})

    return {"status": "submitted", "report_id": report_id, "submitted_at": datetime.now(timezone.utc).isoformat()}


# ═══════════════════════════════════════════════════════════
# AUDIT LOG
# ═══════════════════════════════════════════════════════════
@app.get("/api/v1/audit")
async def list_audit(
    action: Optional[str] = Query(None),
    entity_type: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    tenant_id: str = Depends(get_tenant),
    db: asyncpg.Connection = Depends(get_db),
):
    conditions = ["tenant_id = $1"]
    params = [tenant_id]
    i = 2

    if action:
        conditions.append(f"action ILIKE ${i}"); params.append(f"%{action}%"); i += 1
    if entity_type:
        conditions.append(f"entity_type = ${i}"); params.append(entity_type); i += 1

    where = " AND ".join(conditions)
    total = await db.fetchval(f"SELECT COUNT(*) FROM audit_log WHERE {where}", *params)
    rows = await db.fetch(
        f"""SELECT id, action, entity_type, entity_id, after, user_id, created_at
            FROM audit_log WHERE {where}
            ORDER BY created_at DESC
            LIMIT {per_page} OFFSET {(page-1)*per_page}""",
        *params
    )

    return {
        "data": [dict(r) for r in rows],
        "pagination": {"total": total, "page": page, "per_page": per_page},
    }


# ═══════════════════════════════════════════════════════════
# DASHBOARD STATS
# ═══════════════════════════════════════════════════════════
@app.get("/api/v1/stats")
async def get_stats(
    tenant_id: str = Depends(get_tenant),
    db: asyncpg.Connection = Depends(get_db),
):
    """Aggregated KPIs for the Overview dashboard."""
    biz = await db.fetchrow(
        """SELECT
             COUNT(*) FILTER (WHERE kyb_status='approved') AS approved,
             COUNT(*) FILTER (WHERE kyb_status='review_required') AS review,
             COUNT(*) FILTER (WHERE kyb_status='pending') AS pending,
             COUNT(*) AS total,
             ROUND(AVG(risk_score),1) AS avg_score,
             COUNT(*) FILTER (WHERE next_review_due <= CURRENT_DATE + 30) AS reviews_due_30d
           FROM businesses WHERE tenant_id=$1""",
        tenant_id
    )

    alerts = await db.fetchrow(
        """SELECT
             COUNT(*) FILTER (WHERE status='open') AS open_alerts,
             COUNT(*) FILTER (WHERE severity='critical' AND status!='resolved') AS critical,
             COUNT(*) FILTER (WHERE sar_required AND status!='resolved') AS sar_pending
           FROM alerts WHERE tenant_id=$1""",
        tenant_id
    )

    today_recon = await db.fetchrow(
        "SELECT total_relevant_funds, safeguarded_amount, shortfall, reconciled FROM safeguarding_records WHERE tenant_id=$1 AND record_date=CURRENT_DATE",
        tenant_id
    )

    return {
        "businesses": dict(biz) if biz else {},
        "alerts": dict(alerts) if alerts else {},
        "cass15_today": dict(today_recon) if today_recon else None,
    }


# ═══════════════════════════════════════════════════════════
# TRANSACTIONS — Surveillance continue
# ═══════════════════════════════════════════════════════════

@app.post("/api/v1/transactions", status_code=201)
async def create_transaction(
    body: TransactionRequest,
    tenant_id: str = Depends(get_tenant),
    db: asyncpg.Connection = Depends(get_db),
):
    """
    Soumet une transaction et l'évalue immédiatement via le moteur de règles AML.
    Retourne risk_score, flagged, flagged_rules et alert_id si alerte créée.
    """
    from transaction_monitor import transaction_monitor

    tx_id = str(uuid.uuid4())

    # Persister la transaction (risk_score sera mis à jour après évaluation)
    await db.execute(
        """INSERT INTO transactions
           (id, tenant_id, business_id, amount, currency, beneficiary_name,
            beneficiary_country, beneficiary_iban, reference, tx_type, channel,
            risk_score, flagged, flagged_rules, raw_data, created_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,0,FALSE,'{}','{}',$12)""",
        tx_id,
        tenant_id,
        body.business_id,
        body.amount,
        body.currency.upper(),
        body.beneficiary_name,
        body.beneficiary_country.upper() if body.beneficiary_country else None,
        body.beneficiary_iban,
        body.reference,
        body.tx_type,
        body.channel,
        datetime.now(timezone.utc),
    )

    # Évaluer via le moteur de règles
    tx_dict = {
        "id": tx_id,
        "business_id": body.business_id,
        "amount": body.amount,
        "currency": body.currency.upper(),
        "beneficiary_name": body.beneficiary_name,
        "beneficiary_country": body.beneficiary_country.upper() if body.beneficiary_country else None,
        "tx_type": body.tx_type,
    }

    result = await transaction_monitor.evaluate(tx_dict, db, tenant_id)

    # Mettre à jour la transaction avec le résultat de l'évaluation
    await db.execute(
        """UPDATE transactions
           SET risk_score=$1, flagged=$2, flagged_rules=$3
           WHERE id=$4""",
        result["risk_score"],
        result["flagged"],
        result["flagged_rules"],
        tx_id,
    )

    return {
        "transaction_id": tx_id,
        "risk_score":     result["risk_score"],
        "flagged":        result["flagged"],
        "flagged_rules":  result["flagged_rules"],
        "alert_id":       result["alert_id"],
    }


@app.get("/api/v1/transactions")
async def list_transactions(
    flagged: Optional[bool] = Query(None),
    business_id: Optional[str] = Query(None),
    min_score: Optional[int] = Query(None, ge=0, le=100),
    page: int = Query(1, ge=1),
    per_page: int = Query(25, ge=1, le=100),
    tenant_id: str = Depends(get_tenant),
    db: asyncpg.Connection = Depends(get_db),
):
    """Liste les transactions avec filtres."""
    conditions = ["tenant_id = $1"]
    params = [tenant_id]
    i = 2

    if flagged is not None:
        conditions.append(f"flagged = ${i}"); params.append(flagged); i += 1
    if business_id:
        conditions.append(f"business_id = ${i}"); params.append(business_id); i += 1
    if min_score is not None:
        conditions.append(f"risk_score >= ${i}"); params.append(min_score); i += 1

    where = " AND ".join(conditions)
    total = await db.fetchval(f"SELECT COUNT(*) FROM transactions WHERE {where}", *params)
    rows = await db.fetch(
        f"""SELECT id, business_id, amount, currency, beneficiary_name,
                   beneficiary_country, tx_type, channel, risk_score,
                   flagged, flagged_rules, created_at
            FROM transactions WHERE {where}
            ORDER BY created_at DESC
            LIMIT {per_page} OFFSET {(page-1)*per_page}""",
        *params,
    )

    return {
        "data": [dict(r) for r in rows],
        "pagination": {
            "total": total,
            "page": page,
            "per_page": per_page,
            "pages": -(-total // per_page),
        },
    }


@app.get("/api/v1/transactions/{tx_id}")
async def get_transaction(
    tx_id: str,
    tenant_id: str = Depends(get_tenant),
    db: asyncpg.Connection = Depends(get_db),
):
    """Détail d'une transaction."""
    row = await db.fetchrow(
        "SELECT * FROM transactions WHERE id=$1 AND tenant_id=$2",
        tx_id, tenant_id,
    )
    if not row:
        raise HTTPException(status_code=404, detail="Transaction not found")
    return dict(row)


# ═══════════════════════════════════════════════════════════
# MONITORING STATS
# ═══════════════════════════════════════════════════════════

@app.get("/api/v1/monitoring/stats")
async def get_monitoring_stats(
    tenant_id: str = Depends(get_tenant),
    db: asyncpg.Connection = Depends(get_db),
):
    """KPIs de surveillance : transactions 24h, flaggées, risk moyen, SAR en attente."""
    stats = await db.fetchrow(
        """SELECT
             COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '24 hours')  AS tx_last_24h,
             COUNT(*) FILTER (WHERE flagged = TRUE)                              AS flagged_count,
             ROUND(AVG(risk_score), 1)                                           AS avg_risk_score,
             COUNT(*) FILTER (WHERE risk_score >= 60)                            AS high_risk_count,
             COUNT(*) FILTER (WHERE flagged = TRUE AND created_at >= NOW() - INTERVAL '7 days') AS flagged_7d
           FROM transactions
           WHERE tenant_id = $1""",
        tenant_id,
    )

    sar_pending = await db.fetchval(
        "SELECT COUNT(*) FROM alerts WHERE tenant_id=$1 AND sar_required=TRUE AND status!='resolved'",
        tenant_id,
    )

    top_rules = await db.fetch(
        """SELECT rule_flag, COUNT(*) AS count
           FROM (
               SELECT UNNEST(flagged_rules) AS rule_flag
               FROM transactions
               WHERE tenant_id=$1 AND flagged=TRUE
                 AND created_at >= NOW() - INTERVAL '7 days'
           ) sub
           GROUP BY rule_flag ORDER BY count DESC LIMIT 6""",
        tenant_id,
    )

    return {
        "tx_last_24h":    int(stats["tx_last_24h"] or 0),
        "flagged_count":  int(stats["flagged_count"] or 0),
        "flagged_7d":     int(stats["flagged_7d"] or 0),
        "avg_risk_score": float(stats["avg_risk_score"] or 0),
        "high_risk_count": int(stats["high_risk_count"] or 0),
        "sar_pending_count": int(sar_pending or 0),
        "top_rules_7d":   [{"rule": r["rule_flag"], "count": r["count"]} for r in top_rules],
    }
