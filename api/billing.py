"""
ComplianceOS — Billing Module
Pay-per-use £1.00/vérification KYB + Abonnement £79/mois (GBP)
Stripe Checkout + Stripe Billing + Webhooks sécurisés

Endpoints :
  POST /api/v1/billing/kyb-checkout  — Checkout £1.00 PAYG
  POST /api/v1/billing/subscribe     — Checkout £79/mois
  POST /api/v1/billing/switch-mode   — Bascule PAYG ↔ Subscription
  GET  /api/v1/billing/usage         — Usage + recommandation
  GET  /api/v1/billing/portal        — Stripe Customer Portal
  POST /webhooks/stripe              — Webhook (signature vérifiée)
"""

from fastapi import APIRouter, HTTPException, Depends, Request
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timezone
import asyncpg
import uuid
import os
import json
import logging

from auth import get_current_user, CurrentUser, get_db

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Billing"])

# ── Stripe init (lazy — valide même si clé manquante au boot) ──
_stripe = None

def get_stripe():
    global _stripe
    if _stripe is None:
        import stripe as _s
        _s.api_key = os.environ.get("STRIPE_SECRET_KEY", "")
        _stripe = _s
    return _stripe


APP_URL        = os.environ.get("APP_URL", "https://regtech-production-fae7.up.railway.app")
PRICE_PAYG     = os.environ.get("STRIPE_PRICE_PAYG", "")
PRICE_STARTER  = os.environ.get("STRIPE_PRICE_STARTER", "")
PRICE_USAGE    = os.environ.get("STRIPE_PRICE_USAGE", "")
WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")


# ─────────────────────────────────────────────
# SCHEMAS
# ─────────────────────────────────────────────
class SwitchModeRequest(BaseModel):
    mode: str  # 'payg' | 'subscription'

class KYBCheckoutRequest(BaseModel):
    company_number: str


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────
def _check_stripe_configured():
    """Lève une erreur claire si Stripe n'est pas configuré."""
    key = os.environ.get("STRIPE_SECRET_KEY", "")
    if not key or key in ("sk_test_...", "sk_live_...", ""):
        raise HTTPException(
            status_code=503,
            detail={
                "error": "stripe_not_configured",
                "message": "Stripe n'est pas encore configuré. Ajoutez STRIPE_SECRET_KEY dans Railway Variables.",
                "docs": "https://dashboard.stripe.com/apikeys",
            }
        )


async def get_or_create_stripe_customer(
    tenant_id: str, email: str, company: str, db: asyncpg.Connection
) -> str:
    """Récupère ou crée un customer Stripe pour le tenant."""
    row = await db.fetchrow(
        "SELECT stripe_customer_id FROM tenants WHERE id = $1", tenant_id
    )
    if row and row["stripe_customer_id"]:
        return row["stripe_customer_id"]

    stripe = get_stripe()
    customer = stripe.Customer.create(
        email=email,
        name=company,
        metadata={"tenant_id": tenant_id, "platform": "ComplianceOS"},
    )
    await db.execute(
        "UPDATE tenants SET stripe_customer_id = $1 WHERE id = $2",
        customer.id, tenant_id,
    )
    return customer.id


async def write_audit(
    db: asyncpg.Connection, tenant_id: str, action: str, entity_id: str, data: dict
):
    # entity_id doit être un UUID valide (32-36 chars)
    # Les Stripe IDs (cs_test_..., sub_...) sont stockés dans le champ after->stripe_id
    try:
        import uuid as _uuid
        _uuid.UUID(entity_id)   # valide si c'est déjà un UUID
        valid_entity_id = entity_id
    except (ValueError, AttributeError):
        # Ce n'est pas un UUID → on génère un nouveau et on stocke le stripe_id dans after
        valid_entity_id = str(uuid.uuid4())
        data = {**data, "stripe_id": entity_id}

    await db.execute(
        """INSERT INTO audit_log
             (tenant_id, action, entity_type, entity_id, after, created_at)
           VALUES ($1,$2,'billing',$3,$4,$5)""",
        tenant_id, action, valid_entity_id,
        json.dumps(data), datetime.now(timezone.utc),
    )


# ─────────────────────────────────────────────
# ENDPOINT 1 — KYB Checkout PAYG £1.00
# ─────────────────────────────────────────────
@router.post("/api/v1/billing/kyb-checkout")
async def create_kyb_checkout(
    body: KYBCheckoutRequest,
    current_user: CurrentUser = Depends(get_current_user),
    db: asyncpg.Connection = Depends(get_db),
):
    """
    Crée une Stripe Checkout Session à £1.00 pour une vérification KYB.
    Retourne l'URL de paiement.
    Après paiement → webhook → pipeline KYB automatique.
    """
    _check_stripe_configured()
    stripe = get_stripe()

    tenant = await db.fetchrow(
        "SELECT billing_mode, kyb_credits, stripe_customer_id, name FROM tenants WHERE id = $1",
        current_user.tenant_id,
    )

    # Abonnement actif → pas de paiement requis
    if tenant["billing_mode"] == "subscription":
        raise HTTPException(
            status_code=400,
            detail={
                "error": "subscription_active",
                "message": "Abonnement actif — les vérifications KYB sont incluses.",
                "action": "Utilisez directement POST /api/v1/kyb",
            }
        )

    # Crédits prépayés disponibles → décrémenter
    if (tenant["kyb_credits"] or 0) > 0:
        await db.execute(
            "UPDATE tenants SET kyb_credits = kyb_credits - 1 WHERE id = $1",
            current_user.tenant_id,
        )
        remaining = (tenant["kyb_credits"] or 0) - 1
        await write_audit(db, current_user.tenant_id, "kyb_credit_used",
                          current_user.tenant_id, {"company_number": body.company_number, "credits_remaining": remaining})
        return {
            "mode": "credit",
            "credits_remaining": remaining,
            "message": "Crédit utilisé. Lancez POST /api/v1/kyb directement.",
        }

    # Aucun crédit → Stripe Checkout £1.00
    if not PRICE_PAYG:
        raise HTTPException(
            status_code=503,
            detail="STRIPE_PRICE_PAYG non configuré — exécutez scripts/setup_stripe.py"
        )

    customer_id = await get_or_create_stripe_customer(
        current_user.tenant_id, current_user.email, tenant["name"], db
    )

    session = stripe.checkout.Session.create(
        customer=customer_id,
        payment_method_types=["card"],
        line_items=[{"price": PRICE_PAYG, "quantity": 1}],
        mode="payment",
        metadata={
            "tenant_id": current_user.tenant_id,
            "company_number": body.company_number,
            "type": "payg_kyb",
        },
        success_url=f"{APP_URL}/kyb/success?session_id={{CHECKOUT_SESSION_ID}}&company={body.company_number}",
        cancel_url=f"{APP_URL}/kyb/cancel",
    )

    await write_audit(db, current_user.tenant_id, "kyb_checkout_created",
                      session.id, {"company_number": body.company_number, "amount_gbp": 1.00})

    return {
        "mode":         "payg",
        "checkout_url": session.url,
        "session_id":   session.id,
        "amount":       "£1.00",
        "currency":     "GBP",
        "company_number": body.company_number,
        "expires_at":   session.expires_at,
    }


# ─────────────────────────────────────────────
# ENDPOINT 2 — Abonnement £79/mois
# ─────────────────────────────────────────────
@router.post("/api/v1/billing/subscribe")
async def create_subscription(
    current_user: CurrentUser = Depends(get_current_user),
    db: asyncpg.Connection = Depends(get_db),
):
    """
    Crée un abonnement Stripe Billing Starter à £79/mois.
    Retourne l'URL Stripe Checkout pour confirmation.
    """
    _check_stripe_configured()
    stripe = get_stripe()

    tenant = await db.fetchrow(
        "SELECT stripe_customer_id, billing_mode, stripe_sub_id, name FROM tenants WHERE id = $1",
        current_user.tenant_id,
    )

    if tenant["billing_mode"] == "subscription" and tenant["stripe_sub_id"]:
        raise HTTPException(status_code=400, detail={
            "error": "already_subscribed",
            "message": "Abonnement déjà actif.",
            "stripe_sub_id": tenant["stripe_sub_id"],
        })

    if not PRICE_STARTER:
        raise HTTPException(
            status_code=503,
            detail="STRIPE_PRICE_STARTER non configuré — exécutez scripts/setup_stripe.py"
        )

    customer_id = await get_or_create_stripe_customer(
        current_user.tenant_id, current_user.email, tenant["name"], db
    )

    session = stripe.checkout.Session.create(
        customer=customer_id,
        payment_method_types=["card"],
        line_items=[{"price": PRICE_STARTER, "quantity": 1}],
        mode="subscription",
        metadata={"tenant_id": current_user.tenant_id, "type": "subscription"},
        success_url=f"{APP_URL}/billing/success?session_id={{CHECKOUT_SESSION_ID}}",
        cancel_url=f"{APP_URL}/billing/cancel",
    )

    await write_audit(db, current_user.tenant_id, "subscription_checkout_created",
                      session.id, {"plan": "starter", "amount_gbp": 79.00})

    return {
        "checkout_url": session.url,
        "plan":         "starter",
        "amount":       "£79.00/mois",
        "currency":     "GBP",
        "includes":     [
            "KYB illimité (Companies House + AML)",
            "Surveillance transactions 24/7",
            "CASS 15 reporting automatique",
            "Audit log immuable FCA-compliant",
        ],
    }


# ─────────────────────────────────────────────
# ENDPOINT 3 — Switch PAYG ↔ Subscription
# ─────────────────────────────────────────────
@router.post("/api/v1/billing/switch-mode")
async def switch_billing_mode(
    body: SwitchModeRequest,
    current_user: CurrentUser = Depends(get_current_user),
    db: asyncpg.Connection = Depends(get_db),
):
    """
    Bascule entre pay-per-use et abonnement.
    PAYG → Subscription : redirige vers le checkout.
    Subscription → PAYG : annule l'abonnement en fin de période.
    """
    if body.mode not in ("payg", "subscription"):
        raise HTTPException(
            status_code=400,
            detail="Mode invalide. Valeurs acceptées : 'payg' | 'subscription'"
        )

    tenant = await db.fetchrow(
        "SELECT billing_mode, stripe_sub_id FROM tenants WHERE id = $1",
        current_user.tenant_id,
    )

    if tenant["billing_mode"] == body.mode:
        raise HTTPException(
            status_code=400,
            detail=f"Déjà en mode '{body.mode}'."
        )

    # Subscription → PAYG : annulation en fin de période
    if body.mode == "payg" and tenant["stripe_sub_id"]:
        _check_stripe_configured()
        stripe = get_stripe()
        stripe.Subscription.modify(
            tenant["stripe_sub_id"],
            cancel_at_period_end=True,
        )
        await db.execute(
            "UPDATE tenants SET billing_mode = 'payg' WHERE id = $1",
            current_user.tenant_id,
        )
        await write_audit(db, current_user.tenant_id, "billing_switch_payg",
                          current_user.tenant_id,
                          {"from": "subscription", "to": "payg", "cancel_at_period_end": True})
        return {
            "status":  "switching",
            "mode":    "payg",
            "message": "Abonnement annulé à la fin de la période en cours. Passage automatique en pay-per-use.",
        }

    # PAYG → Subscription : checkout
    if body.mode == "subscription":
        return await create_subscription(current_user, db)

    return {"status": "updated", "mode": body.mode}


# ─────────────────────────────────────────────
# ENDPOINT 4 — Usage + Recommandation
# ─────────────────────────────────────────────
@router.get("/api/v1/billing/usage")
async def get_billing_usage(
    current_user: CurrentUser = Depends(get_current_user),
    db: asyncpg.Connection = Depends(get_db),
):
    """
    Retourne l'usage du mois en cours et la recommandation PAYG vs Subscription.
    Seuil de bascule : 79 vérifications/mois (£79 PAYG = £79 abonnement).
    """
    tenant = await db.fetchrow(
        """SELECT billing_mode, kyb_credits, current_period_kyb_count,
                  stripe_sub_id, name
           FROM tenants WHERE id = $1""",
        current_user.tenant_id,
    )

    # Vérifications KYB du mois en cours
    kyb_this_month = await db.fetchval(
        """SELECT COUNT(*) FROM businesses
           WHERE tenant_id = $1
             AND last_verified_at >= date_trunc('month', CURRENT_TIMESTAMP)""",
        current_user.tenant_id,
    ) or 0

    # Paiements PAYG complétés ce mois
    payg_count = await db.fetchval(
        """SELECT COUNT(*) FROM payments
           WHERE tenant_id = $1 AND type = 'payg_kyb' AND status = 'completed'
             AND created_at >= date_trunc('month', CURRENT_TIMESTAMP)""",
        current_user.tenant_id,
    ) or 0

    payg_cost = float(payg_count) * 1.0        # £1.00/vérif
    sub_cost  = 79.0                           # £79/mois
    would_save = round(max(0.0, payg_cost - sub_cost), 2)
    recommend_sub = payg_count >= 79

    if recommend_sub:
        recommendation_msg = (
            f"Vous avez effectue {int(payg_count)} verifications ce mois "
            f"(cout PAYG: GBP {payg_cost:.0f}). "
            f"L'abonnement a GBP 79/mois vous ferait economiser GBP {would_save:.0f}."
        )
    else:
        remaining_before_sub = max(0, 79 - int(payg_count))
        recommendation_msg = (
            f"Pay-per-use optimal ({int(payg_count)} verifications ce mois). "
            f"L'abonnement devient rentable a partir de 79 verifications "
            f"({remaining_before_sub} de plus ce mois)."
        )

    return {
        "billing_mode":  tenant["billing_mode"],
        "current_period": {
            "kyb_verifications":  int(kyb_this_month),
            "payg_payments":      int(payg_count),
            "payg_cost_gbp":      round(payg_cost, 2),
            "month":              datetime.now(timezone.utc).strftime("%Y-%m"),
        },
        "subscription": {
            "monthly_cost_gbp": sub_cost,
            "active":           tenant["billing_mode"] == "subscription",
            "stripe_sub_id":    tenant["stripe_sub_id"],
        },
        "recommendation": {
            "switch_to_subscription": recommend_sub,
            "would_save_gbp":         would_save,
            "breakeven_verifications": 79,
            "message":                recommendation_msg,
        },
        "credits_remaining": tenant["kyb_credits"] or 0,
    }


# ─────────────────────────────────────────────
# ENDPOINT 5 — Stripe Customer Portal
# ─────────────────────────────────────────────
@router.get("/api/v1/billing/portal")
async def get_customer_portal(
    current_user: CurrentUser = Depends(get_current_user),
    db: asyncpg.Connection = Depends(get_db),
):
    """
    Stripe Customer Portal — gestion carte, factures, abonnement par le client.
    """
    _check_stripe_configured()
    stripe = get_stripe()

    tenant = await db.fetchrow(
        "SELECT stripe_customer_id FROM tenants WHERE id = $1",
        current_user.tenant_id,
    )
    if not tenant or not tenant["stripe_customer_id"]:
        raise HTTPException(
            status_code=404,
            detail="Aucun compte Stripe associé. Effectuez d'abord un paiement ou un abonnement."
        )

    session = stripe.billing_portal.Session.create(
        customer=tenant["stripe_customer_id"],
        return_url=f"{APP_URL}/settings/billing",
    )
    return {"portal_url": session.url}


# ─────────────────────────────────────────────
# ENDPOINT 6 — Webhook Stripe (sécurisé)
# ─────────────────────────────────────────────
@router.post("/webhooks/stripe")
async def stripe_webhook(
    request: Request,
    db: asyncpg.Connection = Depends(get_db),
):
    """
    Reçoit et traite les événements Stripe en temps réel.
    Signature vérifiée via STRIPE_WEBHOOK_SECRET.
    """
    stripe = get_stripe()
    payload = await request.body()
    sig     = request.headers.get("stripe-signature", "")

    # Vérification de signature (rejette les requêtes non-Stripe)
    if WEBHOOK_SECRET and WEBHOOK_SECRET not in ("whsec_...", ""):
        try:
            event = stripe.Webhook.construct_event(payload, sig, WEBHOOK_SECRET)
        except stripe.error.SignatureVerificationError:
            logger.warning("[Stripe Webhook] Signature invalide — requête rejetée")
            raise HTTPException(status_code=400, detail="Invalid Stripe webhook signature")
    else:
        # Mode dev : accepter sans vérification de signature
        import json as _json
        event = _json.loads(payload)
        logger.warning("[Stripe Webhook] WEBHOOK_SECRET non configuré — signature non vérifiée (dev mode)")

    event_type = event["type"]
    data       = event["data"]["object"]
    logger.info(f"[Stripe Webhook] Received: {event_type}")

    # ── checkout.session.completed → paiement PAYG ou subscription ──
    if event_type == "checkout.session.completed":
        meta = data.get("metadata", {})
        tx_type = meta.get("type")

        if tx_type == "payg_kyb":
            tenant_id      = meta.get("tenant_id")
            company_number = meta.get("company_number")
            if tenant_id and company_number:
                # Enregistrer le paiement
                await db.execute(
                    """INSERT INTO payments
                         (tenant_id, stripe_payment_id, amount, currency, type, status, metadata)
                       VALUES ($1,$2,$3,'gbp','payg_kyb','completed',$4)
                       ON CONFLICT (stripe_payment_id) DO NOTHING""",
                    tenant_id,
                    data.get("payment_intent"),
                    float(data.get("amount_total", 100)) / 100,
                    json.dumps(meta),
                )
                # Lancer le pipeline KYB en arrière-plan
                try:
                    from kyb_pipeline import run_kyb_pipeline
                    import asyncio
                    asyncio.create_task(
                        run_kyb_pipeline(tenant_id, company_number, triggered_by="stripe_payg")
                    )
                    logger.info(f"[KYB] Pipeline lancé pour {company_number} via Stripe PAYG")
                except Exception as e:
                    logger.error(f"[KYB] Erreur lancement pipeline: {e}")

    # ── customer.subscription.created → activer Starter ──
    elif event_type == "customer.subscription.created":
        customer_id = data.get("customer")
        sub_id      = data.get("id")
        if customer_id:
            await db.execute(
                """UPDATE tenants
                   SET billing_mode = 'subscription', stripe_sub_id = $1
                   WHERE stripe_customer_id = $2""",
                sub_id, customer_id,
            )
            tenant = await db.fetchrow(
                "SELECT id FROM tenants WHERE stripe_customer_id = $1", customer_id
            )
            if tenant:
                await write_audit(db, str(tenant["id"]), "subscription_activated",
                                  sub_id, {"plan": "starter", "amount_gbp": 79.00})
            logger.info(f"[Billing] Abonnement activé: {sub_id}")

    # ── customer.subscription.deleted → retour PAYG ──
    elif event_type == "customer.subscription.deleted":
        customer_id = data.get("customer")
        if customer_id:
            await db.execute(
                """UPDATE tenants
                   SET billing_mode = 'payg', stripe_sub_id = NULL
                   WHERE stripe_customer_id = $1""",
                customer_id,
            )
            tenant = await db.fetchrow(
                "SELECT id FROM tenants WHERE stripe_customer_id = $1", customer_id
            )
            if tenant:
                await write_audit(db, str(tenant["id"]), "subscription_cancelled",
                                  str(tenant["id"]), {"reason": "subscription_deleted"})
            logger.info(f"[Billing] Abonnement annulé — tenant retour en PAYG")

    # ── invoice.payment_failed → alerte dans le dashboard ──
    elif event_type == "invoice.payment_failed":
        customer_id = data.get("customer")
        if customer_id:
            tenant = await db.fetchrow(
                "SELECT id FROM tenants WHERE stripe_customer_id = $1", customer_id
            )
            if tenant:
                alert_id = str(uuid.uuid4())
                await db.execute(
                    """INSERT INTO alerts
                         (id, tenant_id, type, severity, status, description, sar_required, created_at)
                       VALUES ($1,$2,'kyb_expired','high','open',$3,FALSE,$4)""",
                    alert_id, str(tenant["id"]),
                    "Echec de paiement Stripe — abonnement ComplianceOS suspendu. "
                    "Mettre a jour la carte de paiement dans Settings > Billing.",
                    datetime.now(timezone.utc),
                )
                logger.warning(f"[Billing] Paiement echoue — alerte cree pour tenant {tenant['id']}")

    return {"status": "ok", "event": event_type}
