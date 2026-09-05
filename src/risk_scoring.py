"""Deterministic, auditable scoring from specification v1.1 section 7."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


CATEGORIES = ("phishing", "fraudulent_ec", "suspected_counterfeit")

RULE_POINTS = {
    "R-FEED": 30,
    "R-IMPERSONATION": 30,
    "R-SIMILARITY": 25,
    "R-AGE": 5,
    "R-NAME": 5,
}

GROUP_CAPS = {
    "external": 30,
    "observed_behavior": 30,
    "similarity": 25,
    "metadata": 15,
}


@dataclass(frozen=True)
class RiskAssessment:
    category: str
    score: int
    priority: str
    priority_label: str
    completeness: str
    completeness_label: str
    applied_rules: tuple[str, ...]
    missing_evidence: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "score": self.score,
            "priority": self.priority,
            "priority_label": self.priority_label,
            "completeness": self.completeness,
            "completeness_label": self.completeness_label,
            "applied_rules": list(self.applied_rules),
            "missing_evidence": list(self.missing_evidence),
        }


def classify_priority(score: int) -> tuple[str, str]:
    if score >= 80:
        return "urgent", "緊急"
    if score >= 60:
        return "high", "高"
    if score >= 30:
        return "review", "要確認"
    return "normal", "通常"


def _has_page_evidence(scan_result: dict) -> bool:
    return bool(
        scan_result.get("scan_url")
        or scan_result.get("screenshot_url")
        or scan_result.get("dom_text")
        or scan_result.get("page_signals")
    )


def assess_risk(
    domain_info: dict,
    scan_result: dict | None,
    analysis: object | None = None,
) -> RiskAssessment:
    """Score only rules explicitly defined by the specification.

    Category-specific rule applicability is unresolved in v1.1. Therefore the
    deterministic rules are evaluated uniformly and the output is a review
    priority, never a legal or safety conclusion.
    """
    scan_result = scan_result or {}
    groups: dict[str, int] = {name: 0 for name in GROUP_CAPS}
    applied: list[str] = []
    missing: list[str] = []

    if domain_info.get("known_phishing") is True:
        groups["external"] += RULE_POINTS["R-FEED"]
        applied.append("R-FEED")
    else:
        missing.append("feed_match")

    impersonation = (
        str(domain_info.get("candidate_kind", "")) == "brand_impersonation"
        and bool(domain_info.get("brand"))
        and (
            bool((scan_result.get("page_signals") or {}).get("credential"))
            or bool(getattr(analysis, "brand_domain_mismatch", False))
        )
    )
    if impersonation:
        groups["observed_behavior"] += RULE_POINTS["R-IMPERSONATION"]
        applied.append("R-IMPERSONATION")
    elif not _has_page_evidence(scan_result):
        missing.append("page_evidence")

    if domain_info.get("similarity_confirmed") is True:
        groups["similarity"] += RULE_POINTS["R-SIMILARITY"]
        applied.append("R-SIMILARITY")
    else:
        missing.append("similarity_disabled_or_missing")

    domain_age_days = domain_info.get("domain_age_days")
    if isinstance(domain_age_days, (int, float)) and 0 <= domain_age_days <= 30:
        groups["metadata"] += RULE_POINTS["R-AGE"]
        applied.append("R-AGE")
    elif domain_age_days is None:
        missing.append("domain_age")

    if int(domain_info.get("score", 0) or 0) >= 5:
        groups["metadata"] += RULE_POINTS["R-NAME"]
        applied.append("R-NAME")

    score = sum(min(value, GROUP_CAPS[group]) for group, value in groups.items())
    score = min(score, 95)
    priority, priority_label = classify_priority(score)
    missing = list(dict.fromkeys(missing))
    if not missing:
        completeness, completeness_label = "complete", "十分"
    elif _has_page_evidence(scan_result):
        completeness, completeness_label = "partial", "一部不足"
    else:
        completeness, completeness_label = "insufficient", "情報不足"

    kind_to_category = {
        "brand_impersonation": "phishing",
        "known_phishing": "phishing",
        "suspicious_shop": "fraudulent_ec",
        "counterfeit_goods": "suspected_counterfeit",
        "suspected_illegal_goods": "fraudulent_ec",
    }
    category = kind_to_category.get(str(domain_info.get("candidate_kind", "")), "phishing")
    return RiskAssessment(
        category=category,
        score=score,
        priority=priority,
        priority_label=priority_label,
        completeness=completeness,
        completeness_label=completeness_label,
        applied_rules=tuple(applied),
        missing_evidence=tuple(missing),
    )
