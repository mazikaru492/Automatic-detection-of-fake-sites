"""Loss-minimising URL search-key normalization from specification F-06."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit


_DOMAIN_RE = re.compile(
    r'(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+'
    r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z'
)


@dataclass(frozen=True)
class NormalizedUrl:
    original: str
    search_key: str
    host: str


def normalize_url(value: str) -> NormalizedUrl:
    """Create a search key without merging paths, queries, HTTP/HTTPS or www."""
    original = str(value)
    parsed = urlsplit(original)
    scheme = parsed.scheme.lower()
    if scheme not in ('http', 'https') or parsed.username or parsed.password:
        raise ValueError('認証情報を含まないHTTP/HTTPS URLが必要です')
    hostname = (parsed.hostname or '').rstrip('.')
    if not hostname:
        raise ValueError('URLにホスト名がありません')
    try:
        host = hostname.encode('idna').decode('ascii').lower()
    except UnicodeError as exc:
        raise ValueError('ホスト名をIDNA正規化できません') from exc
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError('ポート番号が不正です') from exc
    default_port = (scheme == 'http' and port == 80) or (scheme == 'https' and port == 443)
    netloc = host if port is None or default_port else f'{host}:{port}'
    # urlsplit keeps path case and raw query order/value. Fragment is omitted.
    search_key = urlunsplit((scheme, netloc, parsed.path, parsed.query, ''))
    return NormalizedUrl(original=original, search_key=search_key, host=host)


def safe_observation_url(value: str) -> str:
    """Return the URL form safe for urlscan submission and local audit logs.

    Paths are retained to identify the inspected page. Credentials, queries and
    fragments are never returned because they can contain tokens or personal data.
    """
    parsed = urlsplit(str(value).strip())
    scheme = parsed.scheme.lower()
    if scheme not in ('http', 'https') or parsed.username or parsed.password:
        raise ValueError('http/https以外、または認証情報を含むURLです')
    hostname = (parsed.hostname or '').lower().rstrip('.')
    try:
        hostname = hostname.encode('idna').decode('ascii')
    except UnicodeError as exc:
        raise ValueError('ホスト名を正規化できません') from exc
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise ValueError('IPアドレス直接指定は許可されていません')
    if not _DOMAIN_RE.fullmatch(hostname):
        raise ValueError('ホスト名が不正です')
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError('ポート番号が不正です') from exc
    if port not in (None, 80, 443):
        raise ValueError('非標準ポートは許可されていません')
    netloc = hostname + (f':{port}' if port else '')
    return urlunsplit((scheme, netloc, parsed.path or '/', '', ''))
