"""Secure Supabase persistence for detection candidates.

The desktop client authenticates as a normal Supabase user.  A service-role
key is deliberately rejected because it bypasses Row Level Security (RLS).
Only the narrowly scoped RPC functions from the bundled migration are used.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import re
import random
import time
from dataclasses import dataclass
from typing import Any, Optional
from urllib.parse import urlparse, urlunparse

import requests
from url_normalization import normalize_url

logger = logging.getLogger(__name__)

_DOMAIN_RE = re.compile(r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


class SupabaseConfigurationError(ValueError):
    """Raised when Supabase settings would be unsafe or cannot work."""


class SupabaseConnectionError(RuntimeError):
    """Raised when authentication or an RPC request fails."""


@dataclass(frozen=True)
class CandidateClaim:
    candidate_id: str
    domain: str


def _jwt_role(token: str) -> str:
    """Read a JWT role only to reject unsafe keys; this is not authentication."""
    try:
        payload = token.split('.')[1]
        payload += '=' * (-len(payload) % 4)
        return str(json.loads(base64.urlsafe_b64decode(payload)).get('role', ''))
    except (IndexError, ValueError, TypeError, json.JSONDecodeError):
        return ''


def _validate_project_url(project_url: str, allowed_custom_host: str = '') -> str:
    parsed = urlparse(project_url.strip())
    hostname = (parsed.hostname or '').lower().rstrip('.')
    allowed_custom_host = allowed_custom_host.lower().rstrip('.')
    if parsed.scheme != 'https' or not hostname or parsed.username or parsed.password:
        raise SupabaseConfigurationError('Supabase URL は認証情報を含まない https URL にしてください')
    if not (hostname.endswith('.supabase.co') or (allowed_custom_host and hostname == allowed_custom_host)):
        raise SupabaseConfigurationError(
            'Supabase URL のホストが不正です。カスタムドメインは共有設定で明示してください'
        )
    if parsed.port not in (None, 443) or parsed.path not in ('', '/') or parsed.query or parsed.fragment:
        raise SupabaseConfigurationError('Supabase URL はプロジェクトのルートURLだけを指定してください')
    return f'https://{hostname}'


def _safe_domain(domain: str) -> str:
    value = domain.strip().lower().removeprefix('*.').rstrip('.')
    try:
        value = value.encode('idna').decode('ascii')
    except UnicodeError as exc:
        raise ValueError('ドメイン名を正規化できません') from exc
    if not _DOMAIN_RE.fullmatch(value):
        raise ValueError('不正なドメイン名です')
    return value


def _safe_url(url: str, expected_domain: str) -> str:
    """Remove paths and query tokens before persistence."""
    parsed = urlparse(url.strip())
    if parsed.username or parsed.password:
        raise ValueError('認証情報を含む候補URLは保存できません')
    hostname = _safe_domain(parsed.hostname or '')
    if parsed.scheme not in ('http', 'https') or hostname != expected_domain:
        raise ValueError('候補URLとドメインが一致しません')
    try:
        parsed_port = parsed.port
    except ValueError as exc:
        raise ValueError('候補URLのポート番号が不正です') from exc
    if parsed_port not in (None, 80, 443):
        raise ValueError('候補URLの非標準ポートは許可されていません')
    port = f':{parsed_port}' if parsed_port in (80, 443) else ''
    return urlunparse((parsed.scheme, hostname + port, '/', '', '', ''))


class SupabaseRepository:
    def __init__(
        self,
        project_url: str,
        publishable_key: str,
        email: str,
        password: str,
        *,
        allowed_custom_host: str = '',
        timeout_seconds: float = 6.0,
        session: Optional[requests.Session] = None,
    ) -> None:
        self._base_url = _validate_project_url(project_url, allowed_custom_host)
        self._publishable_key = publishable_key.strip()
        self._email = email.strip()
        self._password = password
        self._timeout = max(2.0, min(float(timeout_seconds), 15.0))
        self._session = session or requests.Session()
        self._access_token = ''
        self._expires_at = 0.0
        if not self._publishable_key or not self._email or not self._password:
            raise SupabaseConfigurationError('共有Supabase設定・メール・パスワードはすべて必須です')
        if self._publishable_key.startswith('sb_secret_') or _jwt_role(self._publishable_key) == 'service_role':
            raise SupabaseConfigurationError('service_role/secret キーはデスクトップアプリへ設定できません')
        if len(self._email) > 254 or '@' not in self._email:
            raise SupabaseConfigurationError('Supabaseログインメールアドレスが不正です')

    def connect(self) -> None:
        self._authenticate()
        if self._rpc('app_health', {}) is not True:
            raise SupabaseConnectionError(
                'この利用者は共通Supabaseの許可一覧にありません。'
                '管理者へ事前登録を依頼するか、最新マイグレーションを確認してください'
            )

    def close(self) -> None:
        self._access_token = ''
        self._password = ''
        self._session.close()

    def _authenticate(self) -> None:
        try:
            response = self._session.post(
                f'{self._base_url}/auth/v1/token',
                params={'grant_type': 'password'},
                headers={'apikey': self._publishable_key, 'Content-Type': 'application/json'},
                json={'email': self._email, 'password': self._password},
                timeout=self._timeout,
            )
        except requests.RequestException as exc:
            raise SupabaseConnectionError('Supabase認証サーバーへ接続できません') from exc
        if response.status_code != 200:
            try:
                data = response.json()
                error_code = str(data.get('error_code') or data.get('code') or '').lower()
                message = str(data.get('msg') or data.get('message') or '').lower()
            except (ValueError, TypeError, AttributeError):
                error_code = ''
                message = ''
            if error_code == 'email_not_confirmed' or 'email not confirmed' in message:
                reason = 'メールアドレスが未確認です。SupabaseのAuthenticationで確認済みにしてください'
            elif error_code in ('invalid_credentials', 'invalid_grant') or 'invalid login credentials' in message:
                reason = 'メールアドレスまたはパスワードが一致しません'
            elif response.status_code in (401, 403):
                reason = 'Publishable keyがこのSupabaseプロジェクトのものではありません'
            elif response.status_code == 400:
                reason = 'ログイン情報が無効です。利用者のメール確認状態とパスワードを確認してください'
            else:
                reason = 'Supabase認証サービスが要求を受け付けませんでした'
            raise SupabaseConnectionError(f'{reason} (HTTP {response.status_code})')
        try:
            data = response.json()
            self._access_token = str(data['access_token'])
            expires_in = int(data.get('expires_in', 3600))
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise SupabaseConnectionError('Supabase認証レスポンスが不正です') from exc
        self._expires_at = time.monotonic() + max(30, expires_in - 60)

    def _rpc(self, function: str, payload: dict[str, Any]) -> Any:
        if not self._access_token or time.monotonic() >= self._expires_at:
            self._authenticate()
        url = f'{self._base_url}/rest/v1/rpc/{function}'
        for attempt in range(6):
            try:
                response = self._session.post(
                    url,
                    headers={
                        'apikey': self._publishable_key,
                        'Authorization': f'Bearer {self._access_token}',
                        'Content-Type': 'application/json',
                    },
                    json=payload,
                    timeout=self._timeout,
                )
            except requests.RequestException as exc:
                if attempt == 5:
                    raise SupabaseConnectionError('Supabaseへの保存に失敗しました') from exc
                time.sleep(min(4.0, 0.25 * (2 ** attempt)) + random.uniform(0, 0.2))
                continue
            if response.status_code == 401 and attempt == 0:
                self._authenticate()
                continue
            if response.status_code in (429, 500, 502, 503, 504) and attempt < 5:
                time.sleep(min(4.0, 0.25 * (2 ** attempt)) + random.uniform(0, 0.2))
                continue
            if response.status_code not in (200, 201, 204):
                request_id = response.headers.get('x-request-id', '')
                suffix = f' request_id={request_id}' if request_id else ''
                raise SupabaseConnectionError(
                    f'Supabase RPC {function} が失敗しました (HTTP {response.status_code}){suffix}'
                )
            if response.status_code == 204 or not response.content:
                return None
            try:
                return response.json()
            except json.JSONDecodeError as exc:
                raise SupabaseConnectionError(f'Supabase RPC {function} の応答が不正です') from exc
        raise SupabaseConnectionError('Supabase RPCに失敗しました')

    def claim_candidate(self, candidate: dict, dedup_hours: int = 336) -> Optional[CandidateClaim]:
        domain = _safe_domain(str(candidate.get('domain', '')))
        safe_url = _safe_url(str(candidate.get('url', '')), domain)
        # Despite the legacy column name, this is the F-06 canonical URL key.
        # It keeps path case and query order/value distinct while dropping only
        # the fragment, so unrelated observations are never merged by domain.
        url_key = normalize_url(str(candidate.get('url', ''))).search_key
        domain_hash = hashlib.sha256(url_key.encode('utf-8')).hexdigest()
        result = self._rpc('claim_candidate', {
            'p_domain': domain,
            'p_domain_hash': domain_hash,
            'p_safe_url': safe_url,
            'p_source': str(candidate.get('source', 'unknown'))[:64],
            'p_candidate_kind': str(candidate.get('candidate_kind', 'unknown'))[:64],
            'p_brand': str(candidate.get('brand', ''))[:128],
            'p_score': max(0, min(int(candidate.get('score', 0) or 0), 100)),
            'p_reason': str(candidate.get('reason', ''))[:1000],
            'p_dedup_hours': max(1, min(int(dedup_hours), 24 * 365)),
        })
        candidate_id = str(result or '').strip()
        if not candidate_id:
            return None
        return CandidateClaim(candidate_id=candidate_id, domain=domain)

    def record_scan(self, candidate_id: str, scan_result: Optional[dict], error: str = '') -> None:
        scan_result = scan_result or {}
        evidence = {
            'scan_url': str(scan_result.get('scan_url', ''))[:500],
            'page_domain': str(scan_result.get('page_domain', ''))[:253],
            'ip_address': str(scan_result.get('ip_address', ''))[:64],
            'urlscan_malicious': scan_result.get('urlscan_malicious') is True,
            'urlscan_score': int(scan_result.get('urlscan_score', 0) or 0),
            'page_signals': scan_result.get('page_signals') or {},
            'vocabulary_score': max(0, min(int(scan_result.get('vocabulary_score', 0) or 0), 100)),
            'vocabulary_tier': str(scan_result.get('vocabulary_tier', 'low'))[:16],
            'vocabulary_categories': list(scan_result.get('vocabulary_categories') or [])[:6],
            'scan_reused': scan_result.get('scan_reused') is True,
            'fetch_status': str(scan_result.get('fetch_status', ''))[:32],
            'missing_reason': str(scan_result.get('missing_reason', ''))[:128],
            'dns_status': str(scan_result.get('dns_status', ''))[:32],
            'dns_addresses': list(scan_result.get('dns_addresses') or [])[:20],
            'rdap_status': str(scan_result.get('rdap_status', ''))[:32],
            'domain_age_days': scan_result.get('domain_age_days'),
            'rdap_registrar': str(scan_result.get('rdap_registrar', ''))[:200],
        }
        observed = bool(scan_result) and scan_result.get('fetch_status') != 'not_observed'
        updated = self._rpc('record_candidate_scan', {
            'p_candidate_id': candidate_id,
            'p_success': observed,
            'p_evidence': evidence,
            'p_error': str(error or scan_result.get('missing_reason', ''))[:500],
        })
        if updated is not True:
            raise SupabaseConnectionError('Supabaseのスキャン記録を更新できませんでした')

    def record_decision(self, candidate_id: str, confirmed: bool, category: str, summary: str) -> None:
        updated = self._rpc('record_candidate_decision', {
            'p_candidate_id': candidate_id,
            'p_confirmed': bool(confirmed),
            'p_category': str(category)[:128],
            'p_summary': str(summary)[:2000],
        })
        if updated is not True:
            raise SupabaseConnectionError('Supabaseの判定記録を更新できませんでした')

    def submit_review(
        self,
        candidate_id: str,
        review_status: str,
        reason: str,
        *,
        evidence_refs: Optional[list[str]] = None,
        expected_version: int = 0,
    ) -> int:
        allowed = {
            'investigating', 'no_issue', 'strong_suspicion', 'inconclusive',
            'report_prepared', 'response_verified',
        }
        if review_status not in allowed:
            raise ValueError('不正なレビュー状態です')
        if not reason.strip():
            raise ValueError('レビュー理由は必須です')
        safe_refs = []
        for value in evidence_refs or []:
            text = str(value).strip()
            if text.startswith('https://urlscan.io/'):
                safe_refs.append(text[:500])
        result = self._rpc('submit_candidate_review', {
            'p_candidate_id': candidate_id,
            'p_review_status': review_status,
            'p_reason': reason.strip()[:2000],
            'p_evidence_refs': safe_refs[:20],
            'p_expected_version': max(0, int(expected_version)),
        })
        try:
            return int(result)
        except (TypeError, ValueError) as exc:
            raise SupabaseConnectionError('Supabaseのレビュー更新結果が不正です') from exc

    def record_learning_example(
        self,
        candidate_id: str,
        review_version: int,
        category: str,
        features: dict[str, float],
    ) -> bool:
        if category not in {'phishing', 'fraudulent_ec', 'suspected_counterfeit'}:
            raise ValueError('学習対象の分類が不正です')
        if not isinstance(features, dict) or not features:
            raise ValueError('学習特徴量がありません')
        try:
            version = int(review_version)
        except (TypeError, ValueError) as exc:
            raise ValueError('レビュー版番号が不正です') from exc
        if version < 1:
            raise ValueError('レビュー版番号が不正です')
        result = self._rpc('record_learning_example', {
            'p_candidate_id': candidate_id,
            'p_review_version': version,
            'p_category': str(category),
            'p_features': features,
        })
        return result is True

    def get_learning_examples(self, limit: int = 5000) -> list[dict]:
        result = self._rpc('get_learning_examples', {
            'p_limit': max(100, min(int(limit), 100_000)),
        })
        return result if isinstance(result, list) else []

    def get_active_learning_model(self) -> Optional[dict]:
        result = self._rpc('get_active_learning_model', {})
        return result if isinstance(result, dict) else None

    def publish_learning_model(
        self,
        model: dict,
        metrics: dict,
        *,
        expected_parent_version: str = '',
    ) -> str:
        result = self._rpc('publish_learning_model', {
            'p_model': model,
            'p_metrics': metrics,
            'p_expected_parent_version': str(expected_parent_version)[:128],
        })
        version = str(result or '').strip()
        if not version:
            raise SupabaseConnectionError('学習モデルを公開できませんでした')
        return version

    def rollback_learning_model(self, model_version: str) -> bool:
        return self._rpc('rollback_learning_model', {
            'p_model_version': str(model_version)[:128],
        }) is True
