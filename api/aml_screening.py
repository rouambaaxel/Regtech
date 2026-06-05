"""
ComplianceOS — AML Screening Client
Sanctions (OFAC, UK HMT, ONU, EU), PEP, Adverse Media
Providers : NameScan (namescan.io) + Dilisense (dilisense.com)
Les deux ont une API REST bien documentée et des free tiers utilisables.
"""

import httpx
import asyncio
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum
import logging
import os

logger = logging.getLogger(__name__)


class ScreeningProvider(str, Enum):
    NAMESCAN = "namescan"
    DILISENSE = "dilisense"


class SubjectType(str, Enum):
    PERSON = "person"
    COMPANY = "company"


@dataclass
class ScreeningHit:
    list_name: str              # "UK HMT Financial Sanctions" | "OFAC SDN" | "UN Security Council"
    entity_name: str
    match_score: float          # 0.0 – 1.0
    match_type: str             # "exact" | "fuzzy" | "alias"
    entity_type: str            # "individual" | "entity" | "vessel"
    details: dict               # aliases, dob, nationalities, etc.
    is_false_positive: bool = False


@dataclass
class ScreeningResult:
    subject_name: str
    subject_type: SubjectType
    provider: str
    status: str                 # "clear" | "hit" | "error"
    hits: list[ScreeningHit] = field(default_factory=list)
    total_hits: int = 0
    is_pep: bool = False
    pep_details: Optional[dict] = None
    adverse_media_count: int = 0
    raw_response: dict = field(default_factory=dict, repr=False)

    @property
    def requires_review(self) -> bool:
        return self.total_hits > 0 or self.is_pep


class NameScanClient:
    """
    NameScan API — Sanctions, PEP, Adverse Media
    https://namescan.io/API.aspx
    Free: checks via web UI. API à partir de ~£50/mois
    """
    BASE_URL = "https://api.namescan.io/v3"

    def __init__(self, api_key: str):
        self.api_key = api_key

    async def screen_person(
        self,
        first_name: str,
        last_name: str,
        dob_year: Optional[int] = None,
        nationality: Optional[str] = None,
    ) -> ScreeningResult:
        payload = {
            "firstName": first_name,
            "lastName": last_name,
            "scanType": "full",  # sanctions + pep + adverse media
        }
        if dob_year:
            payload["dobYear"] = dob_year
        if nationality:
            payload["nationality"] = nationality

        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.post(
                f"{self.BASE_URL}/person-scans/full",
                json=payload,
                headers={
                    "api-key": self.api_key,
                    "Content-Type": "application/json",
                },
            )
            resp.raise_for_status()
            data = resp.json()

        hits = []
        for match in data.get("sanctionsMatches", []):
            hits.append(ScreeningHit(
                list_name=match.get("listName", ""),
                entity_name=match.get("name", ""),
                match_score=match.get("score", 0.0),
                match_type=match.get("matchType", "fuzzy"),
                entity_type="individual",
                details=match,
            ))

        is_pep = len(data.get("pepMatches", [])) > 0
        pep_details = data.get("pepMatches", [{}])[0] if is_pep else None

        return ScreeningResult(
            subject_name=f"{first_name} {last_name}",
            subject_type=SubjectType.PERSON,
            provider=ScreeningProvider.NAMESCAN,
            status="hit" if hits or is_pep else "clear",
            hits=hits,
            total_hits=len(hits),
            is_pep=is_pep,
            pep_details=pep_details,
            adverse_media_count=len(data.get("adverseMediaMatches", [])),
            raw_response=data,
        )

    async def screen_company(self, company_name: str) -> ScreeningResult:
        payload = {
            "name": company_name,
            "scanType": "full",
        }

        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.post(
                f"{self.BASE_URL}/entity-scans/full",
                json=payload,
                headers={"api-key": self.api_key, "Content-Type": "application/json"},
            )
            resp.raise_for_status()
            data = resp.json()

        hits = [
            ScreeningHit(
                list_name=m.get("listName", ""),
                entity_name=m.get("name", ""),
                match_score=m.get("score", 0.0),
                match_type=m.get("matchType", "fuzzy"),
                entity_type="entity",
                details=m,
            )
            for m in data.get("sanctionsMatches", [])
        ]

        return ScreeningResult(
            subject_name=company_name,
            subject_type=SubjectType.COMPANY,
            provider=ScreeningProvider.NAMESCAN,
            status="hit" if hits else "clear",
            hits=hits,
            total_hits=len(hits),
            raw_response=data,
        )


class DilisenseClient:
    """
    Dilisense API — Sanctions + PEP + Criminal + Adverse Media
    https://dilisense.com — API REST, free tier disponible
    Couvre 8 000+ sources : OFAC, EU, UN, UK HMT, SECO, World Bank, etc.
    """
    BASE_URL = "https://api.dilisense.com/v1"

    def __init__(self, api_key: str):
        self.api_key = api_key

    async def screen(
        self,
        name: str,
        subject_type: SubjectType = SubjectType.PERSON,
        dob: Optional[str] = None,          # "YYYY-MM-DD"
        country: Optional[str] = None,
    ) -> ScreeningResult:
        payload: dict = {"name": name, "types": ["sanctions", "pep", "adverse_media"]}
        if dob:
            payload["dateOfBirth"] = dob
        if country:
            payload["country"] = country

        endpoint = "/check/individual" if subject_type == SubjectType.PERSON else "/check/entity"

        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.post(
                f"{self.BASE_URL}{endpoint}",
                json=payload,
                headers={
                    "X-API-Key": self.api_key,
                    "Content-Type": "application/json",
                },
            )
            resp.raise_for_status()
            data = resp.json()

        hits = []
        for result in data.get("results", []):
            for sanction in result.get("sanctions", []):
                hits.append(ScreeningHit(
                    list_name=sanction.get("listName", ""),
                    entity_name=result.get("name", ""),
                    match_score=result.get("matchScore", 0.0),
                    match_type="exact" if result.get("matchScore", 0) > 0.95 else "fuzzy",
                    entity_type=subject_type.value,
                    details={**sanction, "aliases": result.get("aliases", [])},
                ))

        is_pep = any(r.get("isPep", False) for r in data.get("results", []))

        return ScreeningResult(
            subject_name=name,
            subject_type=subject_type,
            provider=ScreeningProvider.DILISENSE,
            status="hit" if hits or is_pep else "clear",
            hits=hits,
            total_hits=len(hits),
            is_pep=is_pep,
            adverse_media_count=sum(len(r.get("adverseMedia", [])) for r in data.get("results", [])),
            raw_response=data,
        )


# ─────────────────────────────────────────────
# ORCHESTRATEUR — Screen toute une entreprise
# ─────────────────────────────────────────────
class AMLScreeningOrchestrator:
    """
    Lance le screening complet d'une entreprise :
    1. Screen la société elle-même
    2. Screen tous les dirigeants actifs
    3. Screen tous les UBOs (PSCs)
    Retourne un rapport consolidé.
    """

    def __init__(self, namescan_key: str):
        self.client = NameScanClient(namescan_key)

    async def screen_business_full(
        self,
        company_name: str,
        officers: list[dict],       # [{name, nationality, dob}, ...]
        pscs: list[dict],           # [{name, nationality, dob}, ...]
    ) -> dict:
        """Screening parallèle de l'entreprise + tous ses individus associés."""

        tasks = [self.client.screen_company(company_name)]

        for person in officers + pscs:
            parts = person["name"].split(" ", 1)
            first = parts[0] if len(parts) > 1 else ""
            last = parts[-1]
            dob_year = None
            if dob := person.get("date_of_birth"):
                dob_year = dob.get("year")

            tasks.append(self.client.screen_person(
                first_name=first,
                last_name=last,
                dob_year=dob_year,
                nationality=person.get("nationality"),
            ))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        company_result = results[0] if not isinstance(results[0], Exception) else None
        person_results = [r for r in results[1:] if not isinstance(r, Exception)]

        total_hits = sum(r.total_hits for r in person_results if r)
        if company_result:
            total_hits += company_result.total_hits

        any_pep = any(r.is_pep for r in person_results if r)
        any_sanctions = total_hits > 0

        # Score AML : base 0, +30 par hit sanctions, +20 si PEP, +10 adverse media
        aml_risk_bump = (
            min(total_hits * 30, 60)
            + (20 if any_pep else 0)
            + (10 if any(r.adverse_media_count > 0 for r in person_results if r) else 0)
        )

        return {
            "company_screening": {
                "status": company_result.status if company_result else "error",
                "hits": company_result.total_hits if company_result else 0,
            },
            "persons_screened": len(person_results),
            "total_hits": total_hits,
            "any_pep": any_pep,
            "any_sanctions": any_sanctions,
            "requires_edd": any_sanctions or any_pep,
            "aml_risk_bump": aml_risk_bump,      # Ajouter au risk_score_base du KYB
            "person_results": [
                {
                    "name": r.subject_name,
                    "status": r.status,
                    "is_pep": r.is_pep,
                    "hits": r.total_hits,
                    "adverse_media": r.adverse_media_count,
                    "requires_review": r.requires_review,
                }
                for r in person_results if r
            ],
        }


# ─────────────────────────────────────────────
# USAGE EXAMPLE
# ─────────────────────────────────────────────
async def example():
    orchestrator = AMLScreeningOrchestrator(
        namescan_key=os.environ["NAMESCAN_API_KEY"],
    )

    # Après avoir récupéré les données Companies House :
    screening = await orchestrator.screen_business_full(
        company_name="Example Fintech Ltd",
        officers=[
            {"name": "John Smith", "nationality": "British", "date_of_birth": {"year": 1980}},
        ],
        pscs=[
            {"name": "Jane Doe", "nationality": "American"},
        ],
    )

    print(f"Total hits: {screening['total_hits']}")
    print(f"PEP detected: {screening['any_pep']}")
    print(f"Requires EDD: {screening['requires_edd']}")
    print(f"AML risk bump: +{screening['aml_risk_bump']} points")


if __name__ == "__main__":
    asyncio.run(example())
