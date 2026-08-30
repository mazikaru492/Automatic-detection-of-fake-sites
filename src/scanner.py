import logging
import time
from typing import Optional
import requests
logger = logging.getLogger(__name__)
URLSCAN_SUBMIT_URL = 'https://urlscan.io/api/v1/scan/'
URLSCAN_RESULT_URL = 'https://urlscan.io/api/v1/result/{uuid}/'
MAX_POLL_WAIT_SEC = 90
POLL_INTERVAL_SEC = 10

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
            if response.status_code == 400:
                logger.warning(f'スキャン拒否 (既存スキャン or 無効URL): {url}')
                data = response.json()
                existing_uuid = data.get('uuid')
                if existing_uuid:
                    logger.info(f'既存スキャン UUID を使用: {existing_uuid}')
                    return existing_uuid
                return None
            if response.status_code == 429:
                logger.warning('urlscan.io レートリミット到達。60秒待機します')
                time.sleep(60)
                return None
            response.raise_for_status()
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
                    logger.warning('レートリミット到達。60秒待機します')
                    time.sleep(60)
                    elapsed += 60
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
        ips: list[str] = lists.get('ips', [])
        ip_address = ips[0] if ips else page.get('ip', '')
        dom_text = self._fetch_dom_text(uuid)
        return {'uuid': uuid, 'screenshot_url': f'https://urlscan.io/screenshots/{uuid}.png', 'dom_text': dom_text, 'ip_address': ip_address, 'page_title': page.get('title', ''), 'country': page.get('country', ''), 'server': page.get('server', ''), 'scan_url': f'https://urlscan.io/result/{uuid}/', 'asn': page.get('asn', '')}

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
