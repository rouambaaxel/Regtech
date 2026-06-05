"""
ComplianceOS — Companies House API Client
Vérification KYB officielle UK : entreprise, dirigeants, UBOs
Doc officielle : https://developer.company-information.service.gov.uk/
API Key gratuite : https://developer.company-information.service.gov.uk/get-started
"""

import httpx
import asyncio
from dataclasses import dataclass, field
from typing import Optional
from datetime import date
import logging

logger = logging.getLogger(__name__)

BASE_URL = "https://api.company-information.service.gov.uk"


@dataclass
class CompanyProfile:
    company_number: str
    company_name: str
    status: str                     # active | dissolved | liquidation | ...
    company_type: str               # ltd | plc | llp | ...
    incorporation_date: Optional[date]
    registered_address: dict
    sic_codes: list[str]
    last_accounts: Optional[dict]
    confirmation_statement: Optional[dict]
    raw: dict = field(default_factory=dict, repr=False)


@dataclass
class Officer:
    name: str
    role: str                       # director | secretary | ...
    appointed_on: Optional[date]
    resigned_on: Optional[date]
    nationality: Optional[str]
    country_of_residence: Optional[str]
    date_of_birth: Optional[dict]   # month + year only (CH doesn't give full DOB)
    address: dict


@dataclass
class PSC:
    """Person with Significant Control — proxy for UBO in UK law"""
    name: str
    kind: str                       # individual-person-with-significant-control | corporate-entity-...
    nationality: Optional[str]
    country_of_residence: Optional[str]
    date_of_birth: Optional[dict]
    natures_of_control: list[str]   # ownership-of-shares-75-to-100-percent | ...
    notified_on: Optional[date]
    ceased_on: Optional[date]
    address: dict


class CompaniesHouseClient:
    """
    Client async pour l'API Companies House UK.
    Utilise httpx.AsyncClient avec authentification Basic (api_key:).
    """

    def __init__(self, api_key: str):
        self.api_key = api_key
        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self):
        self._client = httpx.AsyncClient(
            base_url=BASE_URL,
            auth=(self.api_key, ""),         # CH utilise Basic auth avec clé comme username
            headers={"Accept": "application/json"},
            timeout=15.0,
        )
        return self

    async def __aexit__(self, *args):
        await self._client.aclose()

    # ─────────────────────────────────────────────
    # 1. PROFIL ENTREPRISE
    # ─────────────────────────────────────────────
    async def get_company(self, company_number: str) -> CompanyProfile:
        """
        Récupère le profil complet d'une entreprise UK.
        company_number : ex "12345678" (toujours 8 caractères, padder avec des 0)
        """
        cn = company_number.upper().zfill(8)
        resp = await self._client.get(f"/company/{cn}")
        resp.raise_for_status()
        data = resp.json()

        inc_date = None
        if d := data.get("date_of_creation"):
            inc_date = date.fromisoformat(d)

        return CompanyProfile(
            company_number=data["company_number"],
            company_name=data["company_name"],
            status=data.get("company_status", "unknown"),
            company_type=data.get("type", "unknown"),
            incorporation_date=inc_date,
            registered_address=data.get("registered_office_address", {}),
            sic_codes=data.get("sic_codes", []),
            last_accounts=data.get("accounts"),
            confirmation_statement=data.get("confirmation_statement"),
            raw=data,
        )

    # ─────────────────────────────────────────────
    # 2. DIRIGEANTS (OFFICERS)
    # ─────────────────────────────────────────────
    async def get_officers(self, company_number: str) -> list[Officer]:
        """
        Retourne tous les dirigeants actifs et anciens.
        Filtrer sur resigned_on is None pour les actifs uniquement.
        """
        cn = company_number.upper().zfill(8)
        resp = await self._client.get(
            f"/company/{cn}/officers",
            params={"items_per_page": 100},
        )
        resp.raise_for_status()
        items = resp.json().get("items", [])

        officers = []
        for item in items:
            resigned = None
            if r := item.get("resigned_on"):
                resigned = date.fromisoformat(r)

            appointed = None
            if a := item.get("appointed_on"):
                appointed = date.fromisoformat(a)

            officers.append(Officer(
                name=item.get("name", ""),
                role=item.get("officer_role", ""),
                appointed_on=appointed,
                resigned_on=resigned,
                nationality=item.get("nationality"),
                country_of_residence=item.get("country_of_residence"),
                date_of_birth=item.get("date_of_birth"),   # {"month": 3, "year": 1985}
                address=item.get("address", {}),
            ))

        return officers

    # ─────────────────────────────────────────────
    # 3. PERSONNES À CONTRÔLE SIGNIFICATIF (UBOs)
    # ─────────────────────────────────────────────
    async def get_pscs(self, company_number: str) -> list[PSC]:
        """
        Personnes avec contrôle significatif = proxy UBO selon MLR 2017.
        Inclut les personnes physiques ET les entités corporate (imbrication).
        """
        cn = company_number.upper().zfill(8)
        resp = await self._client.get(
            f"/company/{cn}/persons-with-significant-control",
            params={"items_per_page": 100},
        )
        resp.raise_for_status()
        items = resp.json().get("items", [])

        pscs = []
        for item in items:
            notified = None
            if n := item.get("notified_on"):
                notified = date.fromisoformat(n)

            ceased = None
            if c := item.get("ceased_on"):
                ceased = date.fromisoformat(c)

            pscs.append(PSC(
                name=item.get("name", ""),
                kind=item.get("kind", ""),
                nationality=item.get("nationality"),
                country_of_residence=item.get("country_of_residence"),
                date_of_birth=item.get("date_of_birth"),
                natures_of_control=item.get("natures_of_control", []),
                notified_on=notified,
                ceased_on=ceased,
                address=item.get("address", {}),
            ))

        return pscs

    # ─────────────────────────────────────────────
    # 4. RECHERCHE PAR NOM
    # ─────────────────────────────────────────────
    async def search_companies(self, query: str, items: int = 5) -> list[dict]:
        """Recherche par nom — pour trouver le company_number à partir d'un nom."""
        resp = await self._client.get(
            "/search/companies",
            params={"q": query, "items_per_page": items},
        )
        resp.raise_for_status()
        return resp.json().get("items", [])

    # ─────────────────────────────────────────────
    # 5. FULL KYB — Tout en un
    # ─────────────────────────────────────────────
    async def full_kyb(self, company_number: str) -> dict:
        """
        Lance les 3 appels en parallèle et retourne un dict complet.
        C'est ce que tu persistes dans businesses + ubos + audit_log.
        """
        profile, officers, pscs = await asyncio.gather(
            self.get_company(company_number),
            self.get_officers(company_number),
            self.get_pscs(company_number),
        )

        active_officers = [o for o in officers if o.resigned_on is None]
        active_pscs = [p for p in pscs if p.ceased_on is None]

        # Calcul risk flags basiques
        risk_flags = []
        if profile.status != "active":
            risk_flags.append(f"company_status:{profile.status}")
        if not active_pscs:
            risk_flags.append("no_psc_registered")
        if any(
            "25-to-50-percent" in n
            for p in active_pscs
            for n in p.natures_of_control
        ):
            risk_flags.append("psc_25_50_ownership")
        for psc in active_pscs:
            if psc.kind != "individual-person-with-significant-control":
                risk_flags.append(f"corporate_psc:{psc.name}")

        return {
            "company_number": profile.company_number,
            "company_name": profile.company_name,
            "status": profile.status,
            "incorporation_date": profile.incorporation_date.isoformat() if profile.incorporation_date else None,
            "registered_address": profile.registered_address,
            "sic_codes": profile.sic_codes,
            "active_officers": [
                {
                    "name": o.name,
                    "role": o.role,
                    "nationality": o.nationality,
                    "country_of_residence": o.country_of_residence,
                    "dob": o.date_of_birth,
                    "appointed_on": o.appointed_on.isoformat() if o.appointed_on else None,
                }
                for o in active_officers
            ],
            "pscs": [
                {
                    "name": p.name,
                    "kind": p.kind,
                    "nationality": p.nationality,
                    "country_of_residence": p.country_of_residence,
                    "natures_of_control": p.natures_of_control,
                    "notified_on": p.notified_on.isoformat() if p.notified_on else None,
                }
                for p in active_pscs
            ],
            "risk_flags": risk_flags,
            "risk_score_base": min(len(risk_flags) * 20, 80),  # 0–80, sanctions bump via screening
        }


# ─────────────────────────────────────────────
# USAGE EXAMPLE
# ─────────────────────────────────────────────
async def example():
    import os
    api_key = os.environ["CH_API_KEY"]  # Gratuit sur developer.company-information.service.gov.uk

    async with CompaniesHouseClient(api_key) as client:
        # Exemple : Revolut Ltd
        result = await client.full_kyb("08804411")
        print(f"Company: {result['company_name']} ({result['status']})")
        print(f"PSCs: {len(result['pscs'])}")
        print(f"Risk flags: {result['risk_flags']}")
        print(f"Base risk score: {result['risk_score_base']}/100")


if __name__ == "__main__":
    asyncio.run(example())
