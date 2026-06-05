"""
ComplianceOS — Stripe Product Setup (GBP)
Crée les produits et prix Stripe pour ComplianceOS.
Exécuter UNE SEULE FOIS : railway run python scripts/setup_stripe.py

Prérequis : STRIPE_SECRET_KEY doit être configuré dans .env ou Railway
"""
import stripe
import os
import sys

# Charger .env si présent (dev local)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

stripe.api_key = os.environ.get("STRIPE_SECRET_KEY", "")

if not stripe.api_key or stripe.api_key.startswith("sk_test_..."):
    print("❌ STRIPE_SECRET_KEY non configuré. Ajouter dans Railway ou .env")
    sys.exit(1)

print(f"🔑 Stripe mode: {'LIVE' if stripe.api_key.startswith('sk_live') else 'TEST'}")
print("Création des produits et prix GBP...\n")

# ── 1. Produit KYB Pay-per-use £1.00 ──
prod_payg = stripe.Product.create(
    name="KYB Verification",
    description="Single KYB verification — Companies House + AML screening (ComplianceOS)",
)
price_payg = stripe.Price.create(
    product=prod_payg.id,
    unit_amount=100,        # £1.00 en pence GBP
    currency="gbp",
    nickname="payg_kyb_1gbp",
)
print(f"✅ PAYG Product : {prod_payg.id}")
print(f"   PAYG Price   : {price_payg.id}  (£1.00 / vérification)\n")

# ── 2. Abonnement Starter £79/mois ──
prod_starter = stripe.Product.create(
    name="ComplianceOS Starter",
    description="KYB illimité + AML + Monitoring continu 24/7 — £79/mois",
)
price_starter = stripe.Price.create(
    product=prod_starter.id,
    unit_amount=7900,       # £79.00 en pence GBP
    currency="gbp",
    recurring={"interval": "month"},
    nickname="starter_79_gbp",
)
print(f"✅ Starter Product : {prod_starter.id}")
print(f"   Starter Price   : {price_starter.id}  (£79.00 / mois)\n")

# ── 3. Usage metered — dépassement £0.80/vérif ──
prod_usage = stripe.Product.create(
    name="KYB Extra Verifications",
    description="Vérifications supplémentaires (dépassement plan) — ComplianceOS",
)
price_usage = stripe.Price.create(
    product=prod_usage.id,
    unit_amount=80,         # £0.80/vérif en pence GBP
    currency="gbp",
    recurring={
        "interval": "month",
        "usage_type": "metered",
        "aggregate_usage": "sum",
    },
    nickname="kyb_metered_overage_gbp",
)
print(f"✅ Metered Product : {prod_usage.id}")
print(f"   Metered Price   : {price_usage.id}  (£0.80 / vérif dépassement)\n")

# ── Résumé ──
print("=" * 55)
print("AJOUTER dans Railway (railway variables set) :")
print("=" * 55)
print(f"STRIPE_PRICE_PAYG={price_payg.id}")
print(f"STRIPE_PRICE_STARTER={price_starter.id}")
print(f"STRIPE_PRICE_USAGE={price_usage.id}")
print("=" * 55)
