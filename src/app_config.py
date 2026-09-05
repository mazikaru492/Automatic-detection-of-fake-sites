"""Canonical defaults and environment parsing for specification v1.1.

Keep operational defaults in this module. GUI and CLI code must import these
values instead of maintaining independent copies.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


SPEC_VERSION = "1.1"


@dataclass(frozen=True)
class FeatureFlags:
    urlscan_submission_enabled: bool = False
    ct_enabled: bool = False
    phishing_feed_enabled: bool = True
    similarity_enabled: bool = False
    llm_enabled: bool = False
    automatic_reporting_enabled: bool = False
    automatic_learning_enabled: bool = True


@dataclass(frozen=True)
class Limits:
    generated_domains_per_brand_per_day: int = 500
    related_search_max_depth: int = 2
    related_candidates_per_seed_per_day: int = 100
    direct_fetch_candidates_per_day: int = 500
    connections_per_host: int = 1
    min_request_interval_seconds: int = 5
    pages_per_candidate: int = 3
    page_timeout_seconds: int = 30
    page_total_transfer_bytes: int = 20_000_000
    max_redirects: int = 5
    allowed_ports: tuple[int, ...] = (80, 443)
    max_retries_after_initial_attempt: int = 5
    queue_size: int = 500
    max_scan_count: int = 50
    scan_workers: int = 4
    learning_minimum_per_class: int = 20
    learning_max_examples: int = 5000


DEFAULT_FEATURES = FeatureFlags()
DEFAULT_LIMITS = Limits()
DEFAULT_TEMPLATE_PATH = "テンプレート/CYCOTサイパト実施結果（京都テック、氏名欄あり）_.xlsx"
DEFAULT_REPORT_OUTPUT_DIR = "検出結果"


def env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    normalized = value.strip().casefold()
    if normalized in {"1", "true", "yes", "on", "enabled"}:
        return True
    if normalized in {"0", "false", "no", "off", "disabled"}:
        return False
    raise ValueError(f"{name} は true/false で指定してください")


def env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} は整数で指定してください") from exc
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} は {minimum}～{maximum} の範囲で指定してください")
    return value


def load_feature_flags() -> FeatureFlags:
    """Load flags while preserving the specification's safe defaults."""
    return FeatureFlags(
        urlscan_submission_enabled=env_bool(
            "URLSCAN_SUBMISSION_ENABLED", DEFAULT_FEATURES.urlscan_submission_enabled
        ),
        ct_enabled=env_bool("CT_ENABLED", DEFAULT_FEATURES.ct_enabled),
        phishing_feed_enabled=env_bool(
            "PHISHING_FEED_ENABLED", DEFAULT_FEATURES.phishing_feed_enabled
        ),
        similarity_enabled=env_bool(
            "SIMILARITY_ENABLED", DEFAULT_FEATURES.similarity_enabled
        ),
        llm_enabled=env_bool("LLM_ENABLED", DEFAULT_FEATURES.llm_enabled),
        automatic_reporting_enabled=env_bool(
            "AUTOMATIC_REPORTING_ENABLED",
            DEFAULT_FEATURES.automatic_reporting_enabled,
        ),
        automatic_learning_enabled=env_bool(
            "AUTOMATIC_LEARNING_ENABLED",
            DEFAULT_FEATURES.automatic_learning_enabled,
        ),
    )


def load_operational_limits() -> Limits:
    return Limits(
        queue_size=env_int("QUEUE_SIZE", DEFAULT_LIMITS.queue_size, 10, 100_000),
        max_scan_count=env_int(
            "MAX_SCAN_COUNT", DEFAULT_LIMITS.max_scan_count, 1, 100_000
        ),
        scan_workers=env_int("SCAN_WORKERS", DEFAULT_LIMITS.scan_workers, 1, 8),
        learning_minimum_per_class=env_int(
            "LEARNING_MINIMUM_PER_CLASS",
            DEFAULT_LIMITS.learning_minimum_per_class,
            5,
            10_000,
        ),
        learning_max_examples=env_int(
            "LEARNING_MAX_EXAMPLES",
            DEFAULT_LIMITS.learning_max_examples,
            100,
            100_000,
        ),
    )
