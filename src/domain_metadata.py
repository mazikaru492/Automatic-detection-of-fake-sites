"""DNS and authoritative RDAP metadata without fetching a candidate website."""

from __future__ import annotations

import datetime as dt
import ipaddress
import socket
import threading
from urllib.parse import quote, urljoin, urlparse

import requests


IANA_RDAP_BOOTSTRAP = 'https://data.iana.org/rdap/dns.json'


class DomainMetadataResolver:
    def __init__(self, timeout_seconds: float = 8.0) -> None:
        self._timeout = max(2.0, min(float(timeout_seconds), 15.0))
        self._local = threading.local()
        self._bootstrap_lock = threading.Lock()
        self._rdap_services: dict[str, str] | None = None

    def _session(self) -> requests.Session:
        session = getattr(self._local, 'session', None)
        if session is None:
            session = requests.Session()
            session.headers['User-Agent'] = 'CYCOT-Suspicious-Site-Collector/1.1'
            self._local.session = session
        return session

    def enrich(self, candidate: dict) -> dict:
        result = dict(candidate)
        domain = str(candidate.get('domain', '')).lower().rstrip('.')
        result.update(self._resolve_dns(domain))
        result.update(self._resolve_rdap(domain))
        return result

    def _resolve_dns(self, domain: str) -> dict:
        try:
            addresses = sorted({
                item[4][0]
                for item in socket.getaddrinfo(domain, None, type=socket.SOCK_STREAM)
            })
            return {
                'dns_status': 'resolved',
                'dns_addresses': addresses[:20],
                'dns_contains_non_public_ip': any(
                    not ipaddress.ip_address(address).is_global for address in addresses
                ),
            }
        except (socket.gaierror, OSError, ValueError) as exc:
            return {
                'dns_status': 'unresolved',
                'dns_addresses': [],
                'dns_error': type(exc).__name__,
            }

    def _load_services(self) -> dict[str, str]:
        with self._bootstrap_lock:
            if self._rdap_services is not None:
                return self._rdap_services
            response = self._session().get(IANA_RDAP_BOOTSTRAP, timeout=self._timeout)
            response.raise_for_status()
            data = response.json()
            services: dict[str, str] = {}
            for entry in data.get('services', []):
                if not isinstance(entry, list) or len(entry) != 2:
                    continue
                tlds, urls = entry
                https_urls = [str(url) for url in urls if str(url).startswith('https://')]
                if not https_urls:
                    continue
                for tld in tlds:
                    services[str(tld).casefold()] = https_urls[0]
            self._rdap_services = services
            return services

    def _resolve_rdap(self, domain: str) -> dict:
        tld = domain.rsplit('.', 1)[-1].casefold() if '.' in domain else ''
        try:
            base_url = self._load_services().get(tld)
            if not base_url:
                return {'rdap_status': 'unsupported', 'domain_age_days': None}
            endpoint = urljoin(base_url.rstrip('/') + '/', 'domain/' + quote(domain, safe='.-'))
            parsed = urlparse(endpoint)
            if parsed.scheme != 'https' or not parsed.hostname:
                return {'rdap_status': 'unsafe_endpoint', 'domain_age_days': None}
            response = self._session().get(endpoint, timeout=self._timeout)
            if urlparse(response.url).scheme != 'https':
                return {'rdap_status': 'unsafe_redirect', 'domain_age_days': None}
            if response.status_code == 404:
                return {'rdap_status': 'not_found', 'domain_age_days': None}
            if response.status_code in (401, 403, 429):
                return {'rdap_status': f'http_{response.status_code}', 'domain_age_days': None}
            response.raise_for_status()
            data = response.json()
            registered_at = self._registration_date(data)
            age_days = None
            if registered_at is not None:
                age_days = max(0, (dt.datetime.now(dt.timezone.utc) - registered_at).days)
            return {
                'rdap_status': 'observed',
                'domain_age_days': age_days,
                'rdap_registrar': self._registrar_name(data),
            }
        except (requests.RequestException, ValueError, TypeError, KeyError):
            return {'rdap_status': 'failed', 'domain_age_days': None}

    @staticmethod
    def _registration_date(data: dict) -> dt.datetime | None:
        for event in data.get('events', []):
            if str(event.get('eventAction', '')).casefold() in {
                'registration', 'registered',
            }:
                value = str(event.get('eventDate', ''))
                try:
                    parsed = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
                    return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)
                except ValueError:
                    return None
        return None

    @staticmethod
    def _registrar_name(data: dict) -> str:
        for entity in data.get('entities', []):
            if 'registrar' not in entity.get('roles', []):
                continue
            for row in entity.get('vcardArray', [None, []])[1]:
                if isinstance(row, list) and row and row[0] == 'fn' and len(row) > 3:
                    return str(row[3])[:200]
        return ''
