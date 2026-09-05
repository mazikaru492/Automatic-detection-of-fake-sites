"""Load the administrator-managed shared Supabase connection settings.

The project URL and publishable key identify the shared backend but do not
authenticate a person.  They are therefore distributed with the application,
while each operator still signs in with an individually provisioned account.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from supabase_repository import (
    SupabaseConfigurationError,
    _jwt_role,
    _validate_project_url,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SHARED_BACKEND_PATH = PROJECT_ROOT / "config" / "shared_backend.json"


class SharedBackendConfigurationError(ValueError):
    """Raised when the administrator has not configured the shared backend."""


@dataclass(frozen=True)
class SharedBackendConfig:
    project_url: str
    publishable_key: str
    display_name: str = "CYCOT 共通データベース"
    allowed_custom_host: str = ""


def _required_text(data: dict[str, Any], name: str) -> str:
    value = data.get(name)
    if not isinstance(value, str) or not value.strip():
        raise SharedBackendConfigurationError(
            f"共有Supabase設定の {name} が未設定です"
        )
    normalized = value.strip()
    if any(marker in normalized.upper() for marker in ("YOUR_", "SET_BY_", "REPLACE_")):
        raise SharedBackendConfigurationError(
            "共有Supabaseは管理者による初期設定がまだ完了していません"
        )
    return normalized


def load_shared_backend_config(
    path: str | Path = DEFAULT_SHARED_BACKEND_PATH,
) -> SharedBackendConfig:
    """Read and validate the single backend configuration shipped by an admin."""
    config_path = Path(path)
    try:
        raw = json.loads(config_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SharedBackendConfigurationError(
            f"共有Supabase設定ファイルが見つかりません: {config_path}"
        ) from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise SharedBackendConfigurationError(
            f"共有Supabase設定ファイルを読み取れません: {config_path}"
        ) from exc
    if not isinstance(raw, dict):
        raise SharedBackendConfigurationError(
            "共有Supabase設定はJSONオブジェクトで記載してください"
        )

    project_url = _required_text(raw, "project_url")
    publishable_key = _required_text(raw, "publishable_key")
    display_name = str(raw.get("display_name") or "CYCOT 共通データベース").strip()
    allowed_custom_host = str(raw.get("allowed_custom_host") or "").strip()
    try:
        project_url = _validate_project_url(project_url, allowed_custom_host)
    except SupabaseConfigurationError as exc:
        raise SharedBackendConfigurationError(str(exc)) from exc
    if publishable_key.startswith("sb_secret_") or _jwt_role(publishable_key) == "service_role":
        raise SharedBackendConfigurationError(
            "共有設定にはSecret keyやservice_roleキーを使用できません"
        )
    if not (
        publishable_key.startswith("sb_publishable_")
        or publishable_key.count(".") == 2
    ):
        raise SharedBackendConfigurationError(
            "共有設定にはSupabaseのPublishable keyを指定してください"
        )
    return SharedBackendConfig(
        project_url=project_url,
        publishable_key=publishable_key,
        display_name=display_name[:80],
        allowed_custom_host=allowed_custom_host,
    )
