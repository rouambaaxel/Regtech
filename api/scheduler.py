"""
ComplianceOS — Background Scheduler
Jobs de surveillance continue via APScheduler AsyncIOScheduler.

Jobs configurés :
  - toutes les 6h   : alerte des transactions flaggées sans alerte
  - tous les jours à 02:00 UTC : re-screening AML des businesses à revoir
  - tous les jours à 06:00 UTC : vérification CASS 15 de la veille
  - tous les jours à 03:00 UTC : purge des refresh tokens expirés
"""

import asyncpg
import uuid
import json
import logging
import os
from datetime import datetime, timezone, timedelta, date

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

logger = logging.getLogger(__name__)

scheduler = AsyncIOScheduler(timezone="UTC")


# ─────────────────────────────────────────────
# HELPER : connexion DB
# ─────────────────────────────────────────────
async def _get_conn() -> asyncpg.Connection:
    return await asyncpg.connect(os.environ["DATABASE_URL"])


# ─────────────────────────────────────────────
# JOB 1 — Alertes transactions manquantes (toutes les 6h)
# ─────────────────────────────────────────────
async def job_flag_missing_alerts():
    """
    Vérifie les transactions flagged=TRUE qui n'ont pas d'alerte associée
    et crée les alertes manquantes.
    """
    logger.info("[SCHEDULER] Job 1 — flag missing alerts — start")
    db = None
    try:
        db = await _get_conn()

        # Transactions flaggées sans alerte correspondante dans les notes
        rows = await db.fetch(
            """
            SELECT t.id, t.tenant_id, t.business_id, t.amount, t.currency,
                   t.risk_score, t.flagged_rules, t.beneficiary_name,
                   t.beneficiary_country
            FROM transactions t
            WHERE t.flagged = TRUE
              AND t.risk_score > 60
              AND NOT EXISTS (
                  SELECT 1 FROM audit_log al
                  WHERE al.entity_id = t.id
                    AND al.action = 'transaction_evaluated'
                    AND (al.after->>'risk_score')::int > 60
              )
            ORDER BY t.created_at DESC
            LIMIT 100
            """
        )

        created = 0
        for row in rows:
            alert_id = str(uuid.uuid4())
            severity = "critical" if row["risk_score"] > 80 else "high"
            rules = row["flagged_rules"] or []
            description = (
                f"[Scheduler] Transaction flaggée sans alerte — "
                f"score {row['risk_score']}/100 — règles : {', '.join(rules)}. "
                f"Montant : {row['currency']} {row['amount']:,.2f}."
            )

            await db.execute(
                """
                INSERT INTO alerts
                  (id, tenant_id, business_id, type, severity, status,
                   description, sar_required, created_at)
                VALUES ($1,$2,$3,'sar_required',$4,'open',$5,$6,$7)
                ON CONFLICT DO NOTHING
                """,
                alert_id, str(row["tenant_id"]), str(row["business_id"]) if row["business_id"] else None,
                severity, description, row["risk_score"] > 80,
                datetime.now(timezone.utc),
            )
            created += 1

        logger.info(f"[SCHEDULER] Job 1 — {created} alertes créées")

    except Exception as e:
        logger.error(f"[SCHEDULER] Job 1 error: {e}")
    finally:
        if db:
            await db.close()


# ─────────────────────────────────────────────
# JOB 2 — Re-screening AML (02:00 UTC quotidien)
# ─────────────────────────────────────────────
async def job_aml_rescreening():
    """
    Re-screening AML des businesses dont next_review_due <= TODAY.
    """
    logger.info("[SCHEDULER] Job 2 — AML re-screening — start")
    db = None
    try:
        db = await _get_conn()

        rows = await db.fetch(
            """
            SELECT id, tenant_id, company_number, registered_name
            FROM businesses
            WHERE next_review_due <= CURRENT_DATE
              AND kyb_status = 'approved'
            LIMIT 50
            """
        )

        for row in rows:
            try:
                from aml_screening import AMLScreeningOrchestrator
                namescan_key = os.getenv("NAMESCAN_API_KEY", "")

                if namescan_key and namescan_key != "dummy_for_now":
                    orchestrator = AMLScreeningOrchestrator(namescan_key)
                    result = await orchestrator.screen_business_full(
                        company_name=row["registered_name"],
                        officers=[],
                        pscs=[],
                    )
                    logger.info(
                        f"[SCHEDULER] Job 2 — {row['registered_name']} "
                        f"re-screened — hits: {result['total_hits']}"
                    )

                # Mettre à jour next_review_due + audit
                await db.execute(
                    "UPDATE businesses SET next_review_due = CURRENT_DATE + INTERVAL '12 months' "
                    "WHERE id = $1",
                    str(row["id"]),
                )
                await db.execute(
                    """
                    INSERT INTO audit_log (tenant_id, action, entity_type, entity_id, after, created_at)
                    VALUES ($1,'aml_rescreening_scheduled','business',$2,$3,$4)
                    """,
                    str(row["tenant_id"]), str(row["id"]),
                    json.dumps({"scheduled_by": "scheduler", "next_review": "12 months"}),
                    datetime.now(timezone.utc),
                )

            except Exception as e:
                logger.error(
                    f"[SCHEDULER] Job 2 — re-screen failed for {row['company_number']}: {e}"
                )

        logger.info(f"[SCHEDULER] Job 2 — {len(rows)} businesses processed")

    except Exception as e:
        logger.error(f"[SCHEDULER] Job 2 error: {e}")
    finally:
        if db:
            await db.close()


# ─────────────────────────────────────────────
# JOB 3 — Vérification CASS 15 (06:00 UTC quotidien)
# ─────────────────────────────────────────────
async def job_cass15_check():
    """
    Vérifie si safeguarding_records existe pour hier.
    Si non : crée une alerte cass15_shortfall pour chaque tenant.
    """
    logger.info("[SCHEDULER] Job 3 — CASS 15 check — start")
    db = None
    try:
        db = await _get_conn()
        yesterday = date.today() - timedelta(days=1)

        # Tenants actifs
        tenants = await db.fetch("SELECT id, name FROM tenants")

        missing = 0
        for tenant in tenants:
            tenant_id = str(tenant["id"])
            exists = await db.fetchval(
                "SELECT 1 FROM safeguarding_records WHERE tenant_id=$1 AND record_date=$2",
                tenant_id, yesterday,
            )

            if not exists:
                alert_id = str(uuid.uuid4())
                await db.execute(
                    """
                    INSERT INTO alerts
                      (id, tenant_id, type, severity, status, description, sar_required, created_at)
                    VALUES ($1,$2,'cass15_shortfall','high','open',$3,FALSE,$4)
                    """,
                    alert_id, tenant_id,
                    f"CASS 15 : aucune réconciliation soumise pour le {yesterday}. "
                    f"Action requise avant la clôture de journée (FCA PS25/12).",
                    datetime.now(timezone.utc),
                )
                missing += 1
                logger.warning(
                    f"[SCHEDULER] Job 3 — CASS 15 missing for tenant "
                    f"{tenant['name']} on {yesterday} → alert {alert_id}"
                )

        logger.info(f"[SCHEDULER] Job 3 — {missing} CASS 15 alerts created")

    except Exception as e:
        logger.error(f"[SCHEDULER] Job 3 error: {e}")
    finally:
        if db:
            await db.close()


# ─────────────────────────────────────────────
# JOB 4 — Purge refresh tokens (03:00 UTC quotidien)
# ─────────────────────────────────────────────
async def job_purge_refresh_tokens():
    """
    Purge les refresh_tokens expirés depuis plus de 7 jours.
    """
    logger.info("[SCHEDULER] Job 4 — purge refresh tokens — start")
    db = None
    try:
        db = await _get_conn()
        deleted = await db.fetchval(
            """
            WITH deleted AS (
                DELETE FROM refresh_tokens
                WHERE expires_at < NOW() - INTERVAL '7 days'
                RETURNING id
            )
            SELECT COUNT(*) FROM deleted
            """
        )
        logger.info(f"[SCHEDULER] Job 4 — {deleted} refresh tokens purged")

    except Exception as e:
        logger.error(f"[SCHEDULER] Job 4 error: {e}")
    finally:
        if db:
            await db.close()


# ─────────────────────────────────────────────
# CONFIGURATION DES JOBS
# ─────────────────────────────────────────────
def setup_scheduler():
    """Configure et retourne le scheduler avec tous les jobs."""

    # Job 1 — toutes les 6 heures
    scheduler.add_job(
        job_flag_missing_alerts,
        trigger=IntervalTrigger(hours=6),
        id="flag_missing_alerts",
        name="Flag missing alerts on transactions",
        replace_existing=True,
        misfire_grace_time=300,
    )

    # Job 2 — tous les jours à 02:00 UTC
    scheduler.add_job(
        job_aml_rescreening,
        trigger=CronTrigger(hour=2, minute=0, timezone="UTC"),
        id="aml_rescreening",
        name="Daily AML re-screening",
        replace_existing=True,
        misfire_grace_time=600,
    )

    # Job 3 — tous les jours à 06:00 UTC
    scheduler.add_job(
        job_cass15_check,
        trigger=CronTrigger(hour=6, minute=0, timezone="UTC"),
        id="cass15_check",
        name="Daily CASS 15 reconciliation check",
        replace_existing=True,
        misfire_grace_time=600,
    )

    # Job 4 — tous les jours à 03:00 UTC
    scheduler.add_job(
        job_purge_refresh_tokens,
        trigger=CronTrigger(hour=3, minute=0, timezone="UTC"),
        id="purge_refresh_tokens",
        name="Daily refresh token purge",
        replace_existing=True,
        misfire_grace_time=300,
    )

    logger.info("[SCHEDULER] 4 jobs configured")
    return scheduler
