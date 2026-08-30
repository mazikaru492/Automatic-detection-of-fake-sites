"""
worker.py — PyQt6 バックグラウンドワーカー

パイプライン（monitor → scanner → analyzer → reporter）を
QThread 上で実行し、Qt シグナルで UI スレッドにリアルタイム通知する。

なぜ QThread か:
- GUI スレッドをブロックしないため（フリーズ防止）。
- Qt のシグナル/スロット機構でスレッドセーフに UI 更新できるため。
"""

import logging
import os
import queue
import sys
import time
from pathlib import Path
from typing import Optional

from PyQt6.QtCore import QThread, pyqtSignal

sys.path.insert(0, str(Path(__file__).parent))


class WorkerLogHandler(logging.Handler):
    """
    Python logging → Qt シグナル への橋渡しハンドラ。

    パイプライン内の logger.info() 等の呼び出しを捕捉して
    GUI のログビューアに転送する。
    """

    def __init__(self, signal):
        super().__init__()
        self._signal = signal
        self.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(message)s",
                              datefmt="%H:%M:%S")
        )

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
            self._signal.emit(record.levelname, msg)
        except Exception:
            pass  # ロギング自体のエラーで UI クラッシュを防止


class PipelineWorker(QThread):
    """
    パイプラインを実行する QThread ワーカー。

    シグナル一覧:
        log_emitted(level, message)  — ログメッセージを UI に転送
        scam_detected(data)          — 詐欺判定データを結果テーブルに転送
        stats_updated(data)          — 統計情報を定期更新
        finished_with_result(path)   — 完了時に Excel 保存先を通知
        error_occurred(message)      — 致命的エラーを通知
    """

    log_emitted = pyqtSignal(str, str)       # (level, message)
    scam_detected = pyqtSignal(dict)         # 詐欺判定1件分のデータ
    stats_updated = pyqtSignal(dict)         # 統計情報辞書
    finished_with_result = pyqtSignal(str)  # Excel 保存パス
    error_occurred = pyqtSignal(str)        # エラーメッセージ

    def __init__(
        self,
        urlscan_api_key: str,
        gemini_api_key: str,
        excel_template_path: str,
        max_scan_count: int,
        parent=None,
    ):
        super().__init__(parent)
        self._urlscan_api_key = urlscan_api_key
        self._gemini_api_key = gemini_api_key
        self._excel_template_path = excel_template_path
        self._max_scan_count = max_scan_count
        self._stop_requested = False

    def request_stop(self) -> None:
        """外部から安全な停止をリクエストする"""
        self._stop_requested = True

    def run(self) -> None:
        """
        QThread のエントリーポイント。
        パイプライン全体をここで実行する。
        """
        # ログハンドラをセットアップ（全モジュールの logger を捕捉）
        log_handler = WorkerLogHandler(self.log_emitted)
        root_logger = logging.getLogger()
        root_logger.addHandler(log_handler)
        root_logger.setLevel(logging.INFO)

        try:
            self._run_pipeline()
        except Exception as e:
            self.error_occurred.emit(f"パイプライン実行エラー: {e}")
        finally:
            root_logger.removeHandler(log_handler)

    def _run_pipeline(self) -> None:
        """実際のパイプライン処理"""
        from monitor import DomainMonitor
        from scanner import UrlScanner
        from analyzer import ScamAnalyzer
        from reporter import ExcelReporter

        domain_queue: queue.Queue = queue.Queue(maxsize=500)
        monitor = DomainMonitor(domain_queue)
        scanner = UrlScanner(self._urlscan_api_key)
        analyzer = ScamAnalyzer(self._gemini_api_key)
        reporter = ExcelReporter(self._excel_template_path)

        scan_count = 0
        scam_count = 0

        self.log_emitted.emit("INFO", "🔍 certstream 監視を開始します...")
        monitor.start()
        time.sleep(3)

        while not self._stop_requested:
            if scan_count >= self._max_scan_count:
                self.log_emitted.emit(
                    "INFO",
                    f"✅ 最大スキャン数 ({self._max_scan_count}) に達しました"
                )
                break

            try:
                domain_info = domain_queue.get(timeout=5)
            except queue.Empty:
                self._emit_stats(monitor, scan_count, scam_count, analyzer)
                continue

            url = domain_info["url"]
            domain = domain_info["domain"]
            detected_at = domain_info["detected_at"]

            # urlscan.io スキャン
            self.log_emitted.emit("INFO", f"📡 スキャン開始: {domain}")
            scan_result = scanner.scan(url)
            if not scan_result:
                self.log_emitted.emit("WARNING", f"⚠️ スキャン失敗: {domain}")
                continue

            time.sleep(2)
            scan_count += 1

            # Gemini AI 分析
            self.log_emitted.emit("INFO", f"🤖 AI 分析中: {domain}")
            analysis = analyzer.analyze(
                screenshot_url=scan_result["screenshot_url"],
                dom_text=scan_result["dom_text"],
            )
            if not analysis:
                self.log_emitted.emit("WARNING", f"⚠️ AI 分析失敗: {domain}")
                continue

            # 統計更新シグナル
            self._emit_stats(monitor, scan_count, scam_count, analyzer)

            if analysis.is_scam:
                scam_count += 1
                reporter.append_record(
                    url=url,
                    target_brand=analysis.target_brand or domain,
                    features=analysis.features,
                    detected_at=detected_at,
                )
                # 詐欺サイト検出シグナル
                self.scam_detected.emit({
                    "detected_at": detected_at,
                    "domain": domain,
                    "url": url,
                    "target_brand": analysis.target_brand or domain,
                    "features": analysis.features,
                    "scan_url": scan_result.get("scan_url", ""),
                    "ip_address": scan_result.get("ip_address", ""),
                })
                self.log_emitted.emit(
                    "WARNING",
                    f"🚨 詐欺サイト検出: {domain} (ブランド: {analysis.target_brand})"
                )
            else:
                self.log_emitted.emit("INFO", f"✅ 正常サイト: {domain}")

        monitor.stop()

        # Excel 保存
        if reporter.appended_count > 0:
            saved_path = reporter.save()
            self.finished_with_result.emit(saved_path)
        else:
            self.finished_with_result.emit("")

        self._emit_stats(monitor, scan_count, scam_count, analyzer)

    def _emit_stats(self, monitor, scan_count: int, scam_count: int, analyzer) -> None:
        """統計情報シグナルを発行する"""
        m_stats = monitor.stats
        self.stats_updated.emit({
            "processed": m_stats["processed"],
            "accepted": m_stats["accepted"],
            "scanned": scan_count,
            "scams": scam_count,
            "api_requests": analyzer.request_count,
        })
