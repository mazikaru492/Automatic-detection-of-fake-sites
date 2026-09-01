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

    def __init__(self, signal):
        super().__init__()
        self._signal = signal
        self.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S'))

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
            self._signal.emit(record.levelname, msg)
        except Exception:
            pass

class PipelineWorker(QThread):
    log_emitted = pyqtSignal(str, str)
    scam_detected = pyqtSignal(dict)
    stats_updated = pyqtSignal(dict)
    finished_with_result = pyqtSignal(str)
    error_occurred = pyqtSignal(str)

    def __init__(self, urlscan_api_key: str, gemini_api_key: str, excel_template_path: str, max_scan_count: int, reporter_name: str = '', parent=None):
        super().__init__(parent)
        self._urlscan_api_key = urlscan_api_key
        self._gemini_api_key = gemini_api_key
        self._excel_template_path = excel_template_path
        self._max_scan_count = max_scan_count
        self._reporter_name = reporter_name
        self._stop_requested = False

    def request_stop(self) -> None:
        self._stop_requested = True

    def run(self) -> None:
        log_handler = WorkerLogHandler(self.log_emitted)
        root_logger = logging.getLogger()
        root_logger.addHandler(log_handler)
        root_logger.setLevel(logging.INFO)
        try:
            self._run_pipeline()
        except Exception as e:
            self.error_occurred.emit(f'パイプライン実行エラー: {e}')
        finally:
            root_logger.removeHandler(log_handler)

    def _run_pipeline(self) -> None:
        from monitor import DomainMonitor
        from scanner import UrlScanner
        from analyzer import ScamAnalyzer
        from reporter import ExcelReporter
        from verification import decide_report
        domain_queue: queue.Queue = queue.Queue(maxsize=500)
        monitor = DomainMonitor(domain_queue)
        scanner = UrlScanner(self._urlscan_api_key)
        analyzer = ScamAnalyzer(self._gemini_api_key)
        scanner.set_status_callback(
            lambda status: self.stats_updated.emit({'urlscan': status})
        )
        analyzer.set_status_callback(
            lambda status: self.stats_updated.emit({'gemini': status})
        )
        reporter = ExcelReporter(self._excel_template_path, self._reporter_name)
        scan_count = 0
        scam_count = 0
        self.log_emitted.emit('INFO', '🔍 certstream 監視を開始します...')
        monitor.start()
        time.sleep(3)
        while not self._stop_requested:
            if scan_count >= self._max_scan_count:
                self.log_emitted.emit('INFO', f'✅ 最大スキャン数 ({self._max_scan_count}) に達しました')
                break
            try:
                domain_info = domain_queue.get(timeout=5)
            except queue.Empty:
                self._emit_stats(monitor, scan_count, scam_count, scanner, analyzer)
                continue
            url = domain_info['url']
            domain = domain_info['domain']
            detected_at = domain_info['detected_at']
            self.log_emitted.emit('INFO', f'📡 スキャン開始: {domain}')
            scan_count += 1
            scan_result = scanner.scan(url)
            if not scan_result:
                self.log_emitted.emit('WARNING', f'⚠️ スキャン失敗: {domain}')
                self._emit_stats(monitor, scan_count, scam_count, scanner, analyzer)
                continue
            time.sleep(2)
            self.log_emitted.emit('INFO', f'🤖 AI 分析中: {domain}')
            analysis = analyzer.analyze(
                screenshot_url=scan_result['screenshot_url'],
                dom_text=scan_result['dom_text'],
                page_url=url,
                detection_context=(
                    f"{domain_info.get('reason', '')}; "
                    f"candidate_kind={domain_info.get('candidate_kind', '')}; "
                    f"page_signals={scan_result.get('page_signals', {})}"
                ),
            )
            if not analysis:
                self.log_emitted.emit('WARNING', f'⚠️ AI 分析失敗: {domain}')
                continue
            self._emit_stats(monitor, scan_count, scam_count, scanner, analyzer)
            decision = decide_report(domain_info, scan_result, analysis)
            if decision.confirmed:
                scam_count += 1
                reporter.append_record(url=url, target_brand=analysis.target_brand, features=decision.evidence_summary, detected_at=detected_at, category=decision.report_category)
                self.scam_detected.emit({'detected_at': detected_at, 'domain': domain, 'url': url, 'target_brand': analysis.target_brand, 'category': decision.report_category, 'features': decision.evidence_summary, 'scan_url': scan_result.get('scan_url', ''), 'ip_address': scan_result.get('ip_address', '')})
                self.log_emitted.emit('WARNING', f'🚨 複数根拠で確認済み: {domain} (ブランド: {analysis.target_brand})')
            else:
                self.log_emitted.emit('INFO', f'⏭️ 報告対象外: {domain} — {decision.reason}')
        monitor.stop()
        if reporter.appended_count > 0:
            saved_path = reporter.save()
            self.finished_with_result.emit(saved_path)
        else:
            self.finished_with_result.emit('')
        self._emit_stats(monitor, scan_count, scam_count, scanner, analyzer)

    def _emit_stats(self, monitor, scan_count: int, scam_count: int, scanner, analyzer) -> None:
        m_stats = monitor.stats
        self.stats_updated.emit({
            'processed': m_stats['processed'],
            'accepted': m_stats['accepted'],
            'scanned': scan_count,
            'scams': scam_count,
            'urlscan': scanner.rate_limit_status,
            'gemini': analyzer.usage_status,
        })
