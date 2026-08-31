import base64
import datetime
import logging
import threading
import queue
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional
import requests
import tldextract
from cryptography import x509

logger = logging.getLogger(__name__)
CHROME_LOG_LIST_URL = 'https://www.gstatic.com/ct/log_list/v3/log_list.json'
CT_REQUEST_TIMEOUT_SEC = 20
CT_BATCH_SIZE = 1024
CT_INITIAL_LOOKBACK = 256
CT_POLL_INTERVAL_SEC = 2
TARGET_BRANDS: list[str] = ['sagawa', 'aeon', 'kuroneko', 'yamato', 'amazon', 'mercari', 'rakuten', 'yahoo', 'nttdocomo', 'docomo', 'softbank', 'smbc', 'mizuho', 'mitsubishiufj', 'japanpost', 'yuubin', 'paypal', 'line', 'naver', 'zozotown']
SUSPICIOUS_TLDS: list[str] = ['.top', '.xyz', '.shop', '.club', '.vip', '.cn', '.buzz', '.icu', '.fit', '.surf', '.space', '.gdn', '.win', '.loan', '.date', '.accountant']
SAFE_DOMAINS: set[str] = {'amazon.co.jp', 'amazon.com', 'mercari.com', 'aeon.co.jp', 'rakuten.co.jp', 'yahoo.co.jp', 'docomo.ne.jp', 'softbank.jp', 'smbc.co.jp', 'mizuhobank.co.jp'}
TLD_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())

def is_suspicious(domain: str) -> tuple[bool, str]:
    if not domain:
        return (False, '')
    domain_lower = domain.lower()
    ext = TLD_EXTRACT(domain_lower)
    registered_domain = ext.registered_domain
    if registered_domain in SAFE_DOMAINS:
        return (False, '')
    matched_brand: Optional[str] = None
    for brand in TARGET_BRANDS:
        if brand in domain_lower:
            matched_brand = brand
            break
    has_suspicious_tld = any((domain_lower.endswith(tld) for tld in SUSPICIOUS_TLDS))
    if matched_brand and has_suspicious_tld:
        return (True, f"brand='{matched_brand}', suspicious_tld=True")
    elif matched_brand:
        return (True, f"brand='{matched_brand}', suspicious_tld=False")
    return (False, '')

class DomainMonitor:

    def __init__(self, domain_queue: queue.Queue, max_queue_size: int=500):
        self._queue = domain_queue
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._processed_count = 0
        self._accepted_count = 0
        self._session = requests.Session()
        self._seen_domains: set[str] = set()
        self._seen_domain_order: deque[str] = deque(maxlen=100000)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            logger.warning('DomainMonitor は既に実行中です')
            return
        self._thread = threading.Thread(target=self._run, name='certstream-monitor', daemon=True)
        self._thread.start()
        logger.info('🔍 certstream 監視スレッドを開始しました')

    def stop(self) -> None:
        self._stop_event.set()
        logger.info('🛑 certstream 監視を停止中...')

    @property
    def stats(self) -> dict:
        return {'processed': self._processed_count, 'accepted': self._accepted_count}

    def _run(self) -> None:
        try:
            log_urls = self._load_log_urls()
            cursors: dict[str, int] = {}
            with ThreadPoolExecutor(max_workers=min(8, len(log_urls))) as executor:
                futures = {
                    executor.submit(self._get_tree_size, url): url for url in log_urls
                }
                for future in as_completed(futures):
                    url = futures[future]
                    try:
                        cursors[url] = max(0, future.result() - CT_INITIAL_LOOKBACK)
                    except Exception as e:
                        logger.warning(f'応答しないCTログを除外しました ({url}): {e}')
            log_urls = list(cursors)
            if not log_urls:
                raise RuntimeError('応答するCTログがありません')
            logger.info(f'✅ Certificate Transparency 直接監視を開始しました ({len(log_urls)}ログ)')
        except Exception as e:
            logger.error(f'CTログ一覧の取得に失敗しました: {e}')
            return

        while not self._stop_event.is_set():
            received = 0
            for url in log_urls:
                if self._stop_event.is_set():
                    break
                try:
                    tree_size = self._get_tree_size(url)
                    cursor = cursors[url]
                    while cursor < tree_size and not self._stop_event.is_set():
                        end = min(cursor + CT_BATCH_SIZE - 1, tree_size - 1)
                        entries = self._fetch_entries(url, cursor, end)
                        if not entries:
                            break
                        for entry in entries:
                            try:
                                self._process_domains(self._domains_from_entry(entry))
                            except (KeyError, TypeError, ValueError) as e:
                                logger.debug(f'CT証明書の解析をスキップしました: {e}')
                        cursor += len(entries)
                        cursors[url] = cursor
                        received += len(entries)
                except Exception as e:
                    logger.warning(f'CTログ取得エラー ({url}): {e}')
            if received:
                logger.info(f'📥 CT証明書を {received:,} 件受信しました')
            self._stop_event.wait(CT_POLL_INTERVAL_SEC)

    def _load_log_urls(self) -> list[str]:
        response = self._session.get(CHROME_LOG_LIST_URL, timeout=CT_REQUEST_TIMEOUT_SEC)
        response.raise_for_status()
        now = datetime.datetime.now(datetime.timezone.utc)
        urls: list[str] = []
        for operator in response.json().get('operators', []):
            for log_info in operator.get('logs', []):
                interval = log_info.get('temporal_interval', {})
                try:
                    start = datetime.datetime.fromisoformat(interval['start_inclusive'].replace('Z', '+00:00'))
                    end = datetime.datetime.fromisoformat(interval['end_exclusive'].replace('Z', '+00:00'))
                except (KeyError, ValueError):
                    continue
                state = log_info.get('state', {})
                if start <= now < end and ('usable' in state or 'qualified' in state):
                    urls.append(log_info['url'])
        if not urls:
            raise RuntimeError('現在利用可能なCTログがありません')
        return urls

    def _get_tree_size(self, log_url: str) -> int:
        response = requests.get(
            f'{log_url}ct/v1/get-sth', timeout=CT_REQUEST_TIMEOUT_SEC
        )
        response.raise_for_status()
        return int(response.json()['tree_size'])

    def _fetch_entries(self, log_url: str, start: int, end: int) -> list[dict]:
        response = self._session.get(
            f'{log_url}ct/v1/get-entries',
            params={'start': start, 'end': end},
            timeout=CT_REQUEST_TIMEOUT_SEC,
        )
        response.raise_for_status()
        return response.json().get('entries', [])

    @staticmethod
    def _domains_from_entry(entry: dict) -> list[str]:
        leaf_input = base64.b64decode(entry['leaf_input'])
        entry_type = int.from_bytes(leaf_input[10:12], 'big')
        if entry_type == 0:
            certificate_data = leaf_input
            length_offset = 12
        elif entry_type == 1:
            certificate_data = base64.b64decode(entry['extra_data'])
            length_offset = 0
        else:
            return []
        cert_length = int.from_bytes(
            certificate_data[length_offset:length_offset + 3], 'big'
        )
        cert_start = length_offset + 3
        certificate = x509.load_der_x509_certificate(
            certificate_data[cert_start:cert_start + cert_length]
        )
        try:
            extension = certificate.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )
            return extension.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            return []

    def _process_domains(self, domains: list[str]) -> None:
        self._processed_count += len(domains)
        for raw_domain in domains:
            domain = raw_domain.removeprefix('*.').lower().rstrip('.')
            if not domain or domain in self._seen_domains:
                continue
            if len(self._seen_domain_order) == self._seen_domain_order.maxlen:
                self._seen_domains.discard(self._seen_domain_order[0])
            self._seen_domain_order.append(domain)
            self._seen_domains.add(domain)
            suspicious, reason = is_suspicious(domain)
            if suspicious:
                self._accepted_count += 1
                if self._queue.full():
                    try:
                        self._queue.get_nowait()
                    except queue.Empty:
                        pass
                self._queue.put({
                    'domain': domain,
                    'url': f'https://{domain}',
                    'reason': reason,
                    'detected_at': time.strftime('%Y-%m-%d %H:%M:%S'),
                })
                logger.info(f'🚨 不審ドメイン検出: {domain} (理由: {reason})')
