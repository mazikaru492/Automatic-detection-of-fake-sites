import logging
import threading
import queue
import time
from typing import Optional
import certstream
import tldextract
logger = logging.getLogger(__name__)
TARGET_BRANDS: list[str] = ['sagawa', 'aeon', 'kuroneko', 'yamato', 'amazon', 'mercari', 'rakuten', 'yahoo', 'nttdocomo', 'docomo', 'softbank', 'smbc', 'mizuho', 'mitsubishiufj', 'japanpost', 'yuubin', 'paypal', 'line', 'naver', 'zozotown']
SUSPICIOUS_TLDS: list[str] = ['.top', '.xyz', '.shop', '.club', '.vip', '.cn', '.buzz', '.icu', '.fit', '.surf', '.space', '.gdn', '.win', '.loan', '.date', '.accountant']
SAFE_DOMAINS: set[str] = {'amazon.co.jp', 'amazon.com', 'mercari.com', 'aeon.co.jp', 'rakuten.co.jp', 'yahoo.co.jp', 'docomo.ne.jp', 'softbank.jp', 'smbc.co.jp', 'mizuhobank.co.jp'}

def is_suspicious(domain: str) -> tuple[bool, str]:
    if not domain:
        return (False, '')
    domain_lower = domain.lower()
    ext = tldextract.extract(domain_lower)
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
        while not self._stop_event.is_set():
            try:
                logger.info('🌐 certstream に接続中...')
                certstream.listen(callback=self._on_message, url='wss://certstream.calidog.io/')
            except Exception as e:
                if self._stop_event.is_set():
                    break
                logger.error(f'certstream 接続エラー: {e} — 10秒後に再接続します')
                time.sleep(10)

    def _on_message(self, message: dict, context: object) -> None:
        if self._stop_event.is_set():
            return
        msg_type = message.get('message_type', '')
        if msg_type == 'heartbeat':
            return
        if msg_type != 'certificate_update':
            return
        try:
            leaf_cert = message['data']['leaf_cert']
            domains: list[str] = leaf_cert.get('all_domains', [])
        except (KeyError, TypeError):
            return
        for domain in domains:
            self._processed_count += 1
            suspicious, reason = is_suspicious(domain)
            if suspicious:
                self._accepted_count += 1
                if self._queue.full():
                    try:
                        self._queue.get_nowait()
                    except queue.Empty:
                        pass
                self._queue.put({'domain': domain, 'url': f'https://{domain}', 'reason': reason, 'detected_at': time.strftime('%Y-%m-%d %H:%M:%S')})
                logger.info(f'🚨 不審ドメイン検出: {domain} (理由: {reason})')
