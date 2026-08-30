"""
monitor.py — Input モジュール (ドメイン監視)

certstream WebSocket を購読し、SSL証明書発行ログからリアルタイムに
不審ドメインを抽出してキューに積む。

設計上の選択:
- certstream は内部で websocket-client を使用するブロッキング処理のため、
  スレッド分離して main スレッドがキューを消費できるようにしている。
- is_suspicious() を独立関数にして、ユニットテストを容易にしている。
"""

import logging
import threading
import queue
import time
from typing import Optional

import certstream
import tldextract

logger = logging.getLogger(__name__)

# -----------------------------------------------------------------------
# フィルタリング設定
# -----------------------------------------------------------------------

# 日本の主要ブランドキーワード（小文字で比較）
TARGET_BRANDS: list[str] = [
    "sagawa",           # 佐川急便
    "aeon",             # イオン
    "kuroneko",         # ヤマト運輸（クロネコヤマト）
    "yamato",           # ヤマト運輸
    "amazon",           # Amazon Japan
    "mercari",          # メルカリ
    "rakuten",          # 楽天
    "yahoo",            # Yahoo! Japan
    "nttdocomo",        # NTTドコモ
    "docomo",           # ドコモ
    "softbank",         # ソフトバンク
    "smbc",             # 三井住友銀行
    "mizuho",           # みずほ銀行
    "mitsubishiufj",    # 三菱UFJ銀行
    "japanpost",        # 日本郵便
    "yuubin",           # 郵便
    "paypal",           # PayPal
    "line",             # LINE
    "naver",            # NAVER
    "zozotown",         # ZOZO
]

# 詐欺サイトで多用される不審な TLD
SUSPICIOUS_TLDS: list[str] = [
    ".top",
    ".xyz",
    ".shop",
    ".club",
    ".vip",
    ".cn",
    ".buzz",
    ".icu",
    ".fit",
    ".surf",
    ".space",
    ".gdn",
    ".win",
    ".loan",
    ".date",
    ".accountant",
]

# 既知の安全なドメイン（誤検知軽減用）
SAFE_DOMAINS: set[str] = {
    "amazon.co.jp",
    "amazon.com",
    "mercari.com",
    "aeon.co.jp",
    "rakuten.co.jp",
    "yahoo.co.jp",
    "docomo.ne.jp",
    "softbank.jp",
    "smbc.co.jp",
    "mizuhobank.co.jp",
}


def is_suspicious(domain: str) -> tuple[bool, str]:
    """
    ドメインが不審かどうかを判定する。

    Returns:
        (True, 理由文字列) または (False, "")

    なぜ tuple を返すか:
        ログ出力時に理由が分かると運用上のデバッグが楽になるため。
    """
    if not domain:
        return False, ""

    domain_lower = domain.lower()

    # 既知の正規ドメインはスキップ（誤検知防止）
    ext = tldextract.extract(domain_lower)
    registered_domain = ext.registered_domain  # e.g. "amazon.co.jp"

    if registered_domain in SAFE_DOMAINS:
        return False, ""

    # ブランドキーワードを含むか確認
    matched_brand: Optional[str] = None
    for brand in TARGET_BRANDS:
        if brand in domain_lower:
            matched_brand = brand
            break

    # 不審 TLD を持つか確認
    has_suspicious_tld = any(
        domain_lower.endswith(tld) for tld in SUSPICIOUS_TLDS
    )

    if matched_brand and has_suspicious_tld:
        # 最も高リスク: ブランド名 + 怪しいTLDの組み合わせ
        return True, f"brand='{matched_brand}', suspicious_tld=True"
    elif matched_brand:
        # ブランド名を含むが正規ドメインでない
        return True, f"brand='{matched_brand}', suspicious_tld=False"
    # 不審TLDのみ（ブランド名なし）は対象外とする（urlscan.io無料枠節約）

    return False, ""


class DomainMonitor:
    """
    certstream WebSocket を購読し、不審ドメインを抽出するクラス。

    使い方:
        monitor = DomainMonitor(domain_queue)
        monitor.start()   # バックグラウンドスレッドで購読開始
        ...
        monitor.stop()
    """

    def __init__(self, domain_queue: queue.Queue, max_queue_size: int = 500):
        self._queue = domain_queue
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._processed_count = 0
        self._accepted_count = 0

    # ------------------------------------------------------------------
    # 公開 API
    # ------------------------------------------------------------------

    def start(self) -> None:
        """バックグラウンドスレッドで certstream 購読を開始する。"""
        if self._thread and self._thread.is_alive():
            logger.warning("DomainMonitor は既に実行中です")
            return

        self._thread = threading.Thread(
            target=self._run,
            name="certstream-monitor",
            daemon=True,   # メインスレッド終了時に自動的に終了
        )
        self._thread.start()
        logger.info("🔍 certstream 監視スレッドを開始しました")

    def stop(self) -> None:
        """監視を停止する。"""
        self._stop_event.set()
        logger.info("🛑 certstream 監視を停止中...")

    @property
    def stats(self) -> dict:
        return {
            "processed": self._processed_count,
            "accepted": self._accepted_count,
        }

    # ------------------------------------------------------------------
    # 内部処理
    # ------------------------------------------------------------------

    def _run(self) -> None:
        """
        certstream を購読するメインループ。
        接続断の場合は自動的に再接続を試みる。
        """
        while not self._stop_event.is_set():
            try:
                logger.info("🌐 certstream に接続中...")
                certstream.listen(
                    callback=self._on_message,
                    url="wss://certstream.calidog.io/",
                )
            except Exception as e:
                if self._stop_event.is_set():
                    break
                logger.error(f"certstream 接続エラー: {e} — 10秒後に再接続します")
                time.sleep(10)

    def _on_message(self, message: dict, context: object) -> None:
        """
        certstream から受信した各メッセージのコールバック。

        メッセージタイプが 'certificate_update' の場合のみ処理する。
        """
        if self._stop_event.is_set():
            return

        msg_type = message.get("message_type", "")
        if msg_type == "heartbeat":
            return

        if msg_type != "certificate_update":
            return

        # 証明書に含まれる全ドメイン（SAN含む）を取得
        try:
            leaf_cert = message["data"]["leaf_cert"]
            domains: list[str] = leaf_cert.get("all_domains", [])
        except (KeyError, TypeError):
            return

        for domain in domains:
            self._processed_count += 1
            suspicious, reason = is_suspicious(domain)

            if suspicious:
                self._accepted_count += 1
                # キューが満杯の場合は古いアイテムを破棄（backpressure対策）
                if self._queue.full():
                    try:
                        self._queue.get_nowait()
                    except queue.Empty:
                        pass

                self._queue.put({
                    "domain": domain,
                    "url": f"https://{domain}",
                    "reason": reason,
                    "detected_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                })
                logger.info(
                    f"🚨 不審ドメイン検出: {domain} (理由: {reason})"
                )
