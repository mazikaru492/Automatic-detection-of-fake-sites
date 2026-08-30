"""
scanner.py — Validation モジュール (安全な証拠保全)

urlscan.io の API 経由でサイトを安全にスキャンし、証拠データを取得する。

重要なセキュリティ原則:
- このモジュールは絶対に不審URLへ直接 HTTP リクエストを送らない。
- すべてのアクセスは urlscan.io サーバーを経由する（プロキシとして機能）。
- これにより、マルウェアのダウンロードや IP 漏洩を防止できる。

API 制限（無料 Community Plan）:
- 5,000 スキャン/日, 5 スキャン/分
- time.sleep(2) で連続リクエストを制御
"""

import logging
import time
from typing import Optional

import requests

logger = logging.getLogger(__name__)

# urlscan.io API エンドポイント
URLSCAN_SUBMIT_URL = "https://urlscan.io/api/v1/scan/"
URLSCAN_RESULT_URL = "https://urlscan.io/api/v1/result/{uuid}/"

# スキャン結果が出るまでの最大待機時間（秒）
MAX_POLL_WAIT_SEC = 90
POLL_INTERVAL_SEC = 10  # 結果ポーリング間隔


class UrlScannerError(Exception):
    """urlscan.io API 関連のエラー基底クラス"""
    pass


class ScanSubmitError(UrlScannerError):
    """スキャン送信失敗"""
    pass


class ScanResultError(UrlScannerError):
    """スキャン結果取得失敗"""
    pass


class UrlScanner:
    """
    urlscan.io API ラッパー。

    なぜクラスにするか:
        API キーや HTTP セッションを状態として保持し、
        接続の再利用（パフォーマンス）とヘッダー管理を一元化するため。
    """

    def __init__(self, api_key: str):
        self._api_key = api_key
        self._session = requests.Session()
        self._session.headers.update({
            "API-Key": api_key,
            "Content-Type": "application/json",
        })

    def scan(self, url: str) -> Optional[dict]:
        """
        指定URLをスキャンし、証拠データを返す。

        スキャンが失敗または結果が取得できない場合は None を返す。

        Args:
            url: スキャン対象の URL（直接アクセスせず urlscan.io 経由）

        Returns:
            {
                "uuid": str,
                "screenshot_url": str,
                "dom_text": str,
                "ip_address": str,
                "page_title": str,
                "scan_url": str,  # urlscan.io 上のレポートURL
            }
            または None（失敗時）
        """
        # STEP 1: スキャンを送信して UUID を取得
        uuid = self._submit_scan(url)
        if not uuid:
            return None

        # urlscan.io 側でスキャンが完了するまで待機
        # なぜ wait が必要か: 送信後すぐには結果が出ないため（通常20-60秒）
        logger.info(f"⏳ スキャン完了を待機中 (UUID: {uuid})...")
        time.sleep(POLL_INTERVAL_SEC)

        # STEP 2: 結果をポーリングで取得
        result_data = self._poll_result(uuid)
        if not result_data:
            return None

        # STEP 3: 必要な証拠データを抽出して返す
        return self._extract_evidence(uuid, result_data)

    def _submit_scan(self, url: str) -> Optional[str]:
        """
        スキャンを送信し、UUID を返す。

        visibility を "public" にしている理由:
        - Community Plan では public のみ許可されているため。
        - 警察提出用レポートとして、公開されたスキャン結果を
          証拠 URL として参照できることは利点でもある。
        """
        payload = {
            "url": url,
            "visibility": "public",
            "country": "JP",  # 日本のスキャンノードを優先
            "tags": ["japan-scam-detection", "automated"],
        }

        try:
            response = self._session.post(
                URLSCAN_SUBMIT_URL,
                json=payload,
                timeout=30,
            )

            if response.status_code == 400:
                logger.warning(f"スキャン拒否 (既存スキャン or 無効URL): {url}")
                # 既存スキャンの場合はレスポンスに UUID が含まれることがある
                data = response.json()
                existing_uuid = data.get("uuid")
                if existing_uuid:
                    logger.info(f"既存スキャン UUID を使用: {existing_uuid}")
                    return existing_uuid
                return None

            if response.status_code == 429:
                logger.warning("urlscan.io レートリミット到達。60秒待機します")
                time.sleep(60)
                return None

            response.raise_for_status()
            return response.json().get("uuid")

        except requests.exceptions.Timeout:
            logger.error(f"スキャン送信タイムアウト: {url}")
            return None
        except requests.exceptions.RequestException as e:
            logger.error(f"スキャン送信エラー: {e}")
            return None

    def _poll_result(self, uuid: str) -> Optional[dict]:
        """
        スキャン結果が完成するまでポーリングする。

        なぜポーリングか:
        - urlscan.io は非同期でスキャンを実行するため、
          結果取得は別途 API コールが必要。
        - Webhook はコミュニティプランでは利用不可。
        """
        result_url = URLSCAN_RESULT_URL.format(uuid=uuid)
        elapsed = 0

        while elapsed < MAX_POLL_WAIT_SEC:
            try:
                response = self._session.get(result_url, timeout=30)

                if response.status_code == 200:
                    logger.info(f"✅ スキャン完了 (UUID: {uuid})")
                    return response.json()

                if response.status_code == 404:
                    # まだスキャン中（結果未完成）
                    logger.debug(f"スキャン処理中... ({elapsed}秒経過)")
                    time.sleep(POLL_INTERVAL_SEC)
                    elapsed += POLL_INTERVAL_SEC
                    continue

                if response.status_code == 429:
                    logger.warning("レートリミット到達。60秒待機します")
                    time.sleep(60)
                    elapsed += 60
                    continue

                logger.error(f"結果取得エラー HTTP {response.status_code}")
                return None

            except requests.exceptions.RequestException as e:
                logger.error(f"結果ポーリングエラー: {e}")
                return None

        logger.warning(f"スキャン結果タイムアウト (UUID: {uuid})")
        return None

    def _extract_evidence(self, uuid: str, data: dict) -> dict:
        """
        urlscan.io のレスポンスから必要な証拠データを抽出する。

        フィールドが存在しない場合は空文字列でフォールバックし、
        KeyError を防ぐ（堅牢性確保）。
        """
        page = data.get("page", {})
        task = data.get("task", {})
        lists = data.get("lists", {})

        # IP アドレスの取得（複数の場合は最初の1件）
        ips: list[str] = lists.get("ips", [])
        ip_address = ips[0] if ips else page.get("ip", "")

        # DOM テキストは直接 API では返らないため、
        # screenshot と page 情報から利用可能なものを集約する。
        # 実際の DOM は /dom/ エンドポイントから取得できる。
        dom_text = self._fetch_dom_text(uuid)

        return {
            "uuid": uuid,
            "screenshot_url": f"https://urlscan.io/screenshots/{uuid}.png",
            "dom_text": dom_text,
            "ip_address": ip_address,
            "page_title": page.get("title", ""),
            "country": page.get("country", ""),
            "server": page.get("server", ""),
            "scan_url": f"https://urlscan.io/result/{uuid}/",
            "asn": page.get("asn", ""),
        }

    def _fetch_dom_text(self, uuid: str) -> str:
        """
        urlscan.io の DOM エンドポイントから HTML テキストを取得する。

        なぜ DOM テキストが必要か:
        - Gemini マルチモーダル分析でテキストコンテンツも評価することで、
          スクリーンショットだけでは判断できない偽ページの特徴（偽日本語等）
          を検出できるため。
        """
        dom_url = f"https://urlscan.io/dom/{uuid}/"
        try:
            response = self._session.get(dom_url, timeout=30)
            if response.status_code == 200:
                # HTML が長い場合は最初の 5000 文字のみ使用（Gemini のトークン節約）
                return response.text[:5000]
            return ""
        except requests.exceptions.RequestException as e:
            logger.debug(f"DOM 取得失敗 (UUID: {uuid}): {e}")
            return ""
