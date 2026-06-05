"""
ComplianceOS — Transaction Monitor
Moteur de règles AML pour la surveillance continue des transactions financières.

Règles implémentées :
  - structuring      : montant 8 000–9 999 GBP       → +35 pts
  - velocity         : >5 tx / 60 min même business  → +30 pts
  - high_risk_country: pays FATF liste noire          → +40 pts
  - unusual_hours    : 01h–05h UTC                    → +15 pts
  - round_amount     : montant rond > 5 000 GBP       → +10 pts
  - behavior_change  : >3× moyenne 30 jours           → +25 pts

Si risk_score > 60 → alerte AML créée
Si risk_score > 80 → SAR draft + notification MLRO
"""

import asyncpg
import uuid
import json
import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────
# Pays FATF liste noire + grise + sanctionnés
# ─────────────────────────────────────────────
HIGH_RISK_COUNTRIES = {
    "NG",  # Nigeria
    "IR",  # Iran
    "KP",  # Corée du Nord
    "SY",  # Syrie
    "YE",  # Yémen
    "MM",  # Myanmar
    "LY",  # Libye
    "RU",  # Russie (sanctions EU/UK)
    "BY",  # Biélorussie
    "CU",  # Cuba
    "SD",  # Soudan
    "SO",  # Somalie
    "VE",  # Venezuela
    "AF",  # Afghanistan
    "HT",  # Haïti
    "PK",  # Pakistan (FATF grey)
    "UA",  # certaines régions (Donbas)
}

RULE_SCORES = {
    "structuring":       35,
    "velocity":          30,
    "high_risk_country": 40,
    "unusual_hours":     15,
    "round_amount":      10,
    "behavior_change":   25,
}


class TransactionMonitor:
    """
    Évalue une transaction contre l'ensemble des règles AML actives
    et retourne un risk_score + la liste des règles déclenchées.
    """

    def __init__(self):
        self._rules_cache: dict = {}  # tenant_id → rules config

    # ─────────────────────────────────────────────
    # POINT D'ENTRÉE PRINCIPAL
    # ─────────────────────────────────────────────
    async def evaluate(
        self,
        tx: dict,
        db: asyncpg.Connection,
        tenant_id: str,
    ) -> dict:
        """
        Évalue la transaction et retourne :
        {
            "risk_score": int (0-100),
            "flagged": bool,
            "flagged_rules": list[str],
            "alert_id": str | None
        }
        """
        flagged_rules = []
        score = 0

        # Charger les règles actives pour ce tenant
        rules = await self._load_rules(db, tenant_id)

        # ── Évaluer chaque règle ──
        if rules.get("structuring", {}).get("enabled", True):
            if await self._check_structuring(tx, rules.get("structuring", {})):
                flagged_rules.append("structuring")
                score += RULE_SCORES["structuring"]

        if rules.get("velocity", {}).get("enabled", True):
            if await self._check_velocity(tx, db, rules.get("velocity", {})):
                flagged_rules.append("velocity")
                score += RULE_SCORES["velocity"]

        if rules.get("high_risk_country", {}).get("enabled", True):
            if self._check_high_risk_country(tx):
                flagged_rules.append("high_risk_country")
                score += RULE_SCORES["high_risk_country"]

        if rules.get("unusual_hours", {}).get("enabled", True):
            if self._check_unusual_hours(tx):
                flagged_rules.append("unusual_hours")
                score += RULE_SCORES["unusual_hours"]

        if rules.get("round_amount", {}).get("enabled", True):
            if self._check_round_amount(tx, rules.get("round_amount", {})):
                flagged_rules.append("round_amount")
                score += RULE_SCORES["round_amount"]

        if rules.get("behavior_change", {}).get("enabled", True):
            if await self._check_behavior_change(tx, db, rules.get("behavior_change", {})):
                flagged_rules.append("behavior_change")
                score += RULE_SCORES["behavior_change"]

        # Cap à 100
        risk_score = min(score, 100)
        flagged = len(flagged_rules) > 0

        # ── Créer alerte si score > 60 ──
        alert_id = None
        if risk_score > 60 and flagged:
            alert_id = await self._create_alert(
                db, tenant_id, tx, risk_score, flagged_rules
            )

        # ── Audit log ──
        await self._write_audit(db, tenant_id, tx, risk_score, flagged_rules)

        return {
            "risk_score": risk_score,
            "flagged": flagged,
            "flagged_rules": flagged_rules,
            "alert_id": alert_id,
        }

    # ─────────────────────────────────────────────
    # RÈGLE 1 — STRUCTURING (smurfing)
    # ─────────────────────────────────────────────
    async def _check_structuring(self, tx: dict, rule_config: dict) -> bool:
        """
        Montant entre 8 000 et 9 999 GBP — juste sous le seuil de déclaration
        de 10 000 (POCA 2002, JMLSG Guidance).
        """
        amount = float(tx.get("amount", 0))
        currency = tx.get("currency", "GBP").upper()
        threshold = float(rule_config.get("threshold", 9999))

        return currency == "GBP" and 8000 <= amount <= threshold

    # ─────────────────────────────────────────────
    # RÈGLE 2 — VELOCITY (rafale de transactions)
    # ─────────────────────────────────────────────
    async def _check_velocity(
        self, tx: dict, db: asyncpg.Connection, rule_config: dict
    ) -> bool:
        """
        Plus de 5 transactions en 60 minutes pour le même business.
        """
        business_id = tx.get("business_id")
        if not business_id:
            return False

        max_count = int(rule_config.get("threshold", 5))
        window_min = int(rule_config.get("window_minutes", 60))

        count = await db.fetchval(
            """
            SELECT COUNT(*) FROM transactions
            WHERE business_id = $1
              AND created_at >= NOW() - ($2::int * INTERVAL '1 minute')
            """,
            business_id,
            window_min,
        )
        return (count or 0) >= max_count

    # ─────────────────────────────────────────────
    # RÈGLE 3 — HIGH-RISK COUNTRY
    # ─────────────────────────────────────────────
    def _check_high_risk_country(self, tx: dict) -> bool:
        """
        Pays bénéficiaire sur liste FATF noire/grise ou sanctionné.
        """
        country = (tx.get("beneficiary_country") or "").upper()
        return country in HIGH_RISK_COUNTRIES

    # ─────────────────────────────────────────────
    # RÈGLE 4 — UNUSUAL HOURS (01:00–05:00 UTC)
    # ─────────────────────────────────────────────
    def _check_unusual_hours(self, tx: dict) -> bool:
        """
        Transaction entre 01:00 et 05:00 UTC — activité anormale.
        """
        now_utc = datetime.now(timezone.utc)
        return 1 <= now_utc.hour < 5

    # ─────────────────────────────────────────────
    # RÈGLE 5 — ROUND AMOUNT
    # ─────────────────────────────────────────────
    def _check_round_amount(self, tx: dict, rule_config: dict) -> bool:
        """
        Montant parfaitement rond (pas de pence) > 5 000 GBP.
        Ex: 10 000, 50 000, 100 000 → suspect.
        """
        amount = float(tx.get("amount", 0))
        threshold = float(rule_config.get("threshold", 5000))
        return amount > threshold and amount == int(amount) and int(amount) % 1000 == 0

    # ─────────────────────────────────────────────
    # RÈGLE 6 — BEHAVIOR CHANGE (anomalie statistique)
    # ─────────────────────────────────────────────
    async def _check_behavior_change(
        self, tx: dict, db: asyncpg.Connection, rule_config: dict
    ) -> bool:
        """
        Montant > 3× la moyenne des 30 derniers jours pour ce business.
        """
        business_id = tx.get("business_id")
        if not business_id:
            return False

        multiplier = float(rule_config.get("threshold", 3))

        avg = await db.fetchval(
            """
            SELECT AVG(amount) FROM transactions
            WHERE business_id = $1
              AND created_at >= NOW() - INTERVAL '30 days'
            """,
            business_id,
        )
        if not avg or float(avg) == 0:
            return False

        return float(tx.get("amount", 0)) > float(avg) * multiplier

    # ─────────────────────────────────────────────
    # HELPERS
    # ─────────────────────────────────────────────
    async def _load_rules(self, db: asyncpg.Connection, tenant_id: str) -> dict:
        """Charge les règles actives depuis la DB (avec fallback sur défauts)."""
        rows = await db.fetch(
            "SELECT rule_name, rule_type, threshold, window_minutes, enabled "
            "FROM transaction_rules WHERE tenant_id = $1",
            tenant_id,
        )
        rules = {}
        for row in rows:
            rules[row["rule_name"]] = {
                "rule_type": row["rule_type"],
                "threshold": float(row["threshold"]) if row["threshold"] else None,
                "window_minutes": row["window_minutes"],
                "enabled": row["enabled"],
            }

        # Fallback : activer toutes les règles si aucune config en DB
        if not rules:
            for name in RULE_SCORES:
                rules[name] = {"enabled": True, "threshold": None, "window_minutes": None}

        return rules

    async def _create_alert(
        self,
        db: asyncpg.Connection,
        tenant_id: str,
        tx: dict,
        risk_score: int,
        flagged_rules: list,
    ) -> str:
        """Crée une alerte AML dans la table alerts."""
        alert_id = str(uuid.uuid4())
        severity = "critical" if risk_score > 80 else "high"
        sar_required = risk_score > 80

        rules_str = ", ".join(flagged_rules)
        amount = tx.get("amount", 0)
        currency = tx.get("currency", "GBP")
        beneficiary = tx.get("beneficiary_name", "Unknown")
        country = tx.get("beneficiary_country", "?")

        description = (
            f"Transaction surveillée — score {risk_score}/100. "
            f"Règles déclenchées : {rules_str}. "
            f"Montant : {currency} {amount:,.2f} → {beneficiary} ({country})."
        )

        await db.execute(
            """
            INSERT INTO alerts
              (id, tenant_id, business_id, type, severity, status,
               description, sar_required, notes, created_at)
            VALUES ($1,$2,$3,'sar_required',$4,'open',$5,$6,$7,$8)
            """,
            alert_id,
            tenant_id,
            tx.get("business_id"),
            severity,
            description,
            sar_required,
            json.dumps([{
                "source": "transaction_monitor",
                "tx_id": tx.get("id"),
                "risk_score": risk_score,
                "rules": flagged_rules,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }]),
            datetime.now(timezone.utc),
        )

        logger.warning(
            f"[TXN MONITOR] Alert {alert_id} created — score={risk_score} "
            f"rules={flagged_rules} SAR={sar_required}"
        )

        # SAR draft notification si score > 80
        if sar_required:
            logger.warning(
                f"[TXN MONITOR] SAR DRAFT REQUIRED — alert {alert_id} — "
                f"MLRO should review transaction {tx.get('id')}"
            )

        return alert_id

    async def _write_audit(
        self,
        db: asyncpg.Connection,
        tenant_id: str,
        tx: dict,
        risk_score: int,
        flagged_rules: list,
    ):
        """Écrit l'évaluation dans l'audit log immuable."""
        await db.execute(
            """
            INSERT INTO audit_log
              (tenant_id, action, entity_type, entity_id, after, created_at)
            VALUES ($1,'transaction_evaluated','transaction',$2,$3,$4)
            """,
            tenant_id,
            tx.get("id"),
            json.dumps({
                "risk_score": risk_score,
                "flagged": len(flagged_rules) > 0,
                "flagged_rules": flagged_rules,
                "amount": float(tx.get("amount", 0)),
                "currency": tx.get("currency", "GBP"),
                "beneficiary_country": tx.get("beneficiary_country"),
            }),
            datetime.now(timezone.utc),
        )


# Singleton
transaction_monitor = TransactionMonitor()
