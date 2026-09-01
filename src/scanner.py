import logging
import re
import time
from typing import Callable, Optional
import unicodedata
import requests
logger = logging.getLogger(__name__)
URLSCAN_SUBMIT_URL = 'https://urlscan.io/api/v1/scan/'
URLSCAN_RESULT_URL = 'https://urlscan.io/api/v1/result/{uuid}/'
MAX_POLL_WAIT_SEC = 90
POLL_INTERVAL_SEC = 10
PAGE_SIGNAL_PATTERNS: dict[str, tuple[tuple[str, str], ...]] = {
    'transaction': (
        ('購入', r'購入'), ('注文', r'注文'), ('カート', r'カート'),
        ('今すぐ買う', r'今すぐ買う'), ('決済', r'決済'),
        ('buy now', r'\bbuy\s+now\b'), ('add to cart', r'\badd\s+to\s+cart\b'),
        ('checkout', r'\bcheckout\b'),
    ),
    'commerce': (
        ('購入', r'購入'), ('注文', r'注文'), ('カート', r'カート'),
        ('今すぐ買う', r'今すぐ買う'), ('価格', r'価格'), ('円価格', r'\d[\d,]*\s*円'),
        ('buy now', r'\bbuy\s+now\b'), ('add to cart', r'\badd\s+to\s+cart\b'),
        ('price', r'\bprice\b'),
    ),
    'fraud': (
        ('本日限り', r'本日限り'), ('期間限定', r'期間限定'),
        ('残りわずか', r'残り\s*(?:\d+|わずか)'), ('大幅値引き', r'(?:[5-9]\d|100)\s*%\s*off'),
        ('銀行振込', r'銀行振込'), ('前払い', r'前払い'),
    ),
    'counterfeit': (
        ('スーパーコピー', r'スーパーコピー'),
        ('コピー品', r'コピー品'), ('偽ブランド', r'偽ブランド'),
        ('レプリカ', r'レプリカ'), ('N級品', r'\bn級品\b'),
        ('replica', r'\breplica\b'), ('counterfeit', r'\bcounterfeit\b'),
        ('supercopy', r'\bsuper\s*copy\b'),
    ),
    'illegal_goods': (
        ('覚醒剤', r'覚醒剤'), ('大麻', r'大麻'), ('コカイン', r'コカイン'),
        ('MDMA', r'\bmdma\b'), ('LSD', r'\blsd\b'), ('フェンタニル', r'フェンタニル'),
        ('違法ドラッグ', r'違法ドラッグ'), ('指定薬物', r'指定薬物'),
        ('処方箋不要', r'処方(?:箋|せん)不要'),
        ('未承認医薬品', r'未承認(?:医薬品|薬)'),
        ('fentanyl', r'\bfentanyl\b'), ('cocaine', r'\bcocaine\b'),
    ),
}

def detect_page_signals(text: str) -> dict[str, list[str]]:
    normalized = unicodedata.normalize('NFKC', text or '').casefold()
    return {
        category: [label for label, pattern in patterns if re.search(pattern, normalized)]
        for category, patterns in PAGE_SIGNAL_PATTERNS.items()
    }

class UrlScannerError(Exception):
    pass

class ScanSubmitError(UrlScannerError):
    pass

class ScanResultError(UrlScannerError):
    pass

class UrlScanner:

    def __init__(self, api_key: str):
        self._api_key = api_key
        self._session = requests.Session()
        self._session.headers.update({'API-Key': api_key, 'Content-Type': 'application/json'})
        self._successful_submissions = 0
        self._rate_limit: dict = {}
        self._cooldown_until = 0.0
        self._status_callback: Optional[Callable[[dict], None]] = None

    def set_status_callback(self, callback: Callable[[dict], None]) -> None:
        self._status_callback = callback

    def _notify_status(self) -> None:
        if self._status_callback:
            self._status_callback(self.rate_limit_status)

    @staticmethod
    def _header_int(headers, name: str) -> Optional[int]:
        try:
            value = headers.get(name)
            return int(value) if value is not None else None
        except (TypeError, ValueError):
            return None

    def _capture_rate_limit(self, response) -> None:
        headers = response.headers
        limit = self._header_int(headers, 'X-Rate-Limit-Limit')
        remaining = self._header_int(headers, 'X-Rate-Limit-Remaining')
        reset_after = self._header_int(headers, 'X-Rate-Limit-Reset-After')
        if limit is not None or remaining is not None:
            self._rate_limit = {
                'action': headers.get('X-Rate-Limit-Action', ''),
                'window': headers.get('X-Rate-Limit-Window', ''),
                'limit': limit,
                'remaining': remaining,
                'reset': headers.get('X-Rate-Limit-Reset', ''),
                'reset_at_epoch': time.time() + reset_after if reset_after is not None else 0.0,
            }
        self._notify_status()

    def _wait_for_rate_limit(self, response) -> None:
        wait_time = self._header_int(response.headers, 'X-Rate-Limit-Reset-After') or 60
        self._cooldown_until = time.time() + wait_time
        self._notify_status()
        logger.warning(f'urlscan.io レートリミット到達。{wait_time}秒待機します')
        time.sleep(wait_time)
        self._cooldown_until = 0.0
        self._notify_status()

    def scan(self, url: str) -> Optional[dict]:
        uuid = self._submit_scan(url)
        if not uuid:
            return None
        logger.info(f'⏳ スキャン完了を待機中 (UUID: {uuid})...')
        time.sleep(POLL_INTERVAL_SEC)
        result_data = self._poll_result(uuid)
        if not result_data:
            return None
        return self._extract_evidence(uuid, result_data)

    def _submit_scan(self, url: str) -> Optional[str]:
        payload = {'url': url, 'visibility': 'public', 'country': 'JP', 'tags': ['japan-scam-detection', 'automated']}
        try:
            response = self._session.post(URLSCAN_SUBMIT_URL, json=payload, timeout=30)
            self._capture_rate_limit(response)
            if response.status_code == 400:
                logger.warning(f'スキャン拒否 (既存スキャン or 無効URL): {url}')
                data = response.json()
                existing_uuid = data.get('uuid')
                if existing_uuid:
                    logger.info(f'既存スキャン UUID を使用: {existing_uuid}')
                    return existing_uuid
                return None
            if response.status_code == 429:
                self._wait_for_rate_limit(response)
                return None
            response.raise_for_status()
            self._successful_submissions += 1
            self._notify_status()
            return response.json().get('uuid')
        except requests.exceptions.Timeout:
            logger.error(f'スキャン送信タイムアウト: {url}')
            return None
        except requests.exceptions.RequestException as e:
            logger.error(f'スキャン送信エラー: {e}')
            return None

    def _poll_result(self, uuid: str) -> Optional[dict]:
        result_url = URLSCAN_RESULT_URL.format(uuid=uuid)
        elapsed = 0
        while elapsed < MAX_POLL_WAIT_SEC:
            try:
                response = self._session.get(result_url, timeout=30)
                if response.status_code == 200:
                    logger.info(f'✅ スキャン完了 (UUID: {uuid})')
                    return response.json()
                if response.status_code == 404:
                    logger.debug(f'スキャン処理中... ({elapsed}秒経過)')
                    time.sleep(POLL_INTERVAL_SEC)
                    elapsed += POLL_INTERVAL_SEC
                    continue
                if response.status_code == 429:
                    wait_time = self._header_int(response.headers, 'X-Rate-Limit-Reset-After') or 60
                    self._wait_for_rate_limit(response)
                    elapsed += wait_time
                    continue
                logger.error(f'結果取得エラー HTTP {response.status_code}')
                return None
            except requests.exceptions.RequestException as e:
                logger.error(f'結果ポーリングエラー: {e}')
                return None
        logger.warning(f'スキャン結果タイムアウト (UUID: {uuid})')
        return None

    def _extract_evidence(self, uuid: str, data: dict) -> dict:
        page = data.get('page', {})
        task = data.get('task', {})
        lists = data.get('lists', {})
        verdicts = data.get('verdicts', {})
        urlscan_verdict = verdicts.get('urlscan', {})
        community_verdict = verdicts.get('community', {})
        verdict_score = urlscan_verdict.get('score', 0)
        if not isinstance(verdict_score, (int, float)):
            verdict_score = 0
        categories = [str(value).lower() for value in urlscan_verdict.get('categories', [])]
        brands = [
            str(value.get('name') or value.get('key') or '')
            for value in urlscan_verdict.get('brands', [])
            if isinstance(value, dict)
        ]
        ips: list[str] = lists.get('ips', [])
        ip_address = ips[0] if ips else page.get('ip', '')
        dom_text = self._fetch_dom_text(uuid)
        page_signals = detect_page_signals(dom_text)
        return {
            'uuid': uuid,
            'screenshot_url': f'https://urlscan.io/screenshots/{uuid}.png',
            'dom_text': dom_text,
            'ip_address': ip_address,
            'page_title': page.get('title', ''),
            'page_url': page.get('url', ''),
            'page_domain': page.get('domain', ''),
            'page_apex_domain': page.get('apexDomain', ''),
            'task_domain': task.get('domain', ''),
            'task_apex_domain': task.get('apexDomain', ''),
            'http_status': page.get('status'),
            'redirected': page.get('redirected') is True,
            'country': page.get('country', ''),
            'server': page.get('server', ''),
            'scan_url': f'https://urlscan.io/result/{uuid}/',
            'asn': page.get('asn', ''),
            'urlscan_malicious': urlscan_verdict.get('malicious') is True,
            'urlscan_score': verdict_score,
            'urlscan_categories': categories,
            'urlscan_brands': brands,
            'community_malicious': community_verdict.get('malicious') is True,
            'page_signals': page_signals,
        }

    def _fetch_dom_text(self, uuid: str) -> str:
        dom_url = f'https://urlscan.io/dom/{uuid}/'
        try:
            response = self._session.get(dom_url, timeout=30)
            if response.status_code == 200:
                return response.text[:5000]
            return ''
        except requests.exceptions.RequestException as e:
            logger.debug(f'DOM 取得失敗 (UUID: {uuid}): {e}')
            return ''

    @property
    def rate_limit_status(self) -> dict:
        status = dict(self._rate_limit)
        reset_at = float(status.get('reset_at_epoch') or 0)
        status['reset_after'] = max(0, int(reset_at - time.time())) if reset_at else None
        status['cooldown_seconds'] = max(0, int(self._cooldown_until - time.time()))
        status['cooldown_until'] = self._cooldown_until
        status['successful_submissions'] = self._successful_submissions
        return status
