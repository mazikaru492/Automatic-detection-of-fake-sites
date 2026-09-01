import logging
import os
import queue
import signal
import sys
import time
from pathlib import Path
from dotenv import load_dotenv
sys.path.insert(0, str(Path(__file__).parent))
from monitor import DomainMonitor
from scanner import UrlScanner
from analyzer import ScamAnalyzer
from reporter import ExcelReporter
from verification import decide_report
from key_manager import get_api_key, URLSCAN_KEY_NAME, GEMINI_KEY_NAME

def setup_logging() -> None:
    log_format = '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
    log_date_format = '%Y-%m-%d %H:%M:%S'
    log_dir = Path('logs')
    log_dir.mkdir(exist_ok=True)
    log_filename = log_dir / f"scan_{time.strftime('%Y%m%d_%H%M%S')}.log"
    logging.basicConfig(level=logging.INFO, format=log_format, datefmt=log_date_format, handlers=[logging.StreamHandler(sys.stdout), logging.FileHandler(str(log_filename), encoding='utf-8')])
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('websocket').setLevel(logging.WARNING)
    logging.getLogger('certstream').setLevel(logging.WARNING)
logger = logging.getLogger(__name__)

def load_config() -> dict:
    load_dotenv()
    urlscan_key = get_api_key(URLSCAN_KEY_NAME) or os.getenv('URLSCAN_API_KEY', '')
    gemini_key = get_api_key(GEMINI_KEY_NAME) or os.getenv('GEMINI_API_KEY', '')
    config = {
        'urlscan_api_key': urlscan_key,
        'gemini_api_key': gemini_key,
        'excel_template_path': os.getenv('EXCEL_TEMPLATE_PATH', 'テンプレート/CYCOTサイパト実施結果（京都テック、氏名欄あり）_.xlsx'),
        'report_output_dir': os.getenv('REPORT_OUTPUT_DIR', '検出結果'),
        'reporter_name': os.getenv('REPORTER_NAME', ''),
        'max_scan_count': int(os.getenv('MAX_SCAN_COUNT', '50')),
        'queue_size': int(os.getenv('QUEUE_SIZE', '500'))
    }
    missing = []
    if not config['urlscan_api_key']:
        missing.append('URLSCAN_API_KEY')
    if not config['gemini_api_key']:
        missing.append('GEMINI_API_KEY')
    if missing:
        logger.error(f"❌ 必須の環境変数が設定されていません: {', '.join(missing)}\n   .env ファイルを確認するか、GUIからキーを保存してください")
        sys.exit(1)
    return config


class Pipeline:

    def __init__(self, config: dict):
        self._config = config
        self._domain_queue: queue.Queue = queue.Queue(maxsize=config['queue_size'])
        self._monitor: DomainMonitor = DomainMonitor(self._domain_queue)
        self._scanner: UrlScanner = UrlScanner(config['urlscan_api_key'])
        self._analyzer: ScamAnalyzer = ScamAnalyzer(config['gemini_api_key'])
        self._reporter: ExcelReporter = ExcelReporter(
            config['excel_template_path'],
            config.get('reporter_name', ''),
            config.get('report_output_dir', '検出結果'),
        )
        self._running = True
        self._scan_count = 0
        self._scam_count = 0
        self._max_scan_count = config['max_scan_count']

    def run(self) -> None:
        logger.info('=' * 60)
        logger.info('🛡️  日本向け詐欺サイト自動検知システム 起動')
        logger.info('=' * 60)
        logger.info(f'最大スキャン数: {self._max_scan_count}')
        logger.info('Ctrl+C で安全に停止し、Excel に結果を保存します')
        logger.info('=' * 60)
        self._monitor.start()
        time.sleep(3)
        try:
            self._process_loop()
        except KeyboardInterrupt:
            logger.info('\n⏹️  停止シグナルを受信しました')
        finally:
            self._shutdown()

    def _process_loop(self) -> None:
        while self._running:
            if self._scan_count >= self._max_scan_count:
                logger.info(f'✅ 最大スキャン数 ({self._max_scan_count}) に達しました。終了します。')
                break
            try:
                domain_info = self._domain_queue.get(timeout=5)
            except queue.Empty:
                stats = self._monitor.stats
                logger.debug(f"キュー待機中... (監視済: {stats['processed']}, 検出: {stats['accepted']})")
                continue
            self._process_domain(domain_info)

    def _process_domain(self, domain_info: dict) -> None:
        url = domain_info['url']
        domain = domain_info['domain']
        detected_at = domain_info['detected_at']
        logger.info(f"\n{'─' * 50}")
        logger.info(f'🔬 処理開始 [{self._scan_count + 1}/{self._max_scan_count}]: {domain}')
        logger.info(f'  📡 [1/3] urlscan.io スキャン送信中...')
        scan_result = self._scanner.scan(url)
        if scan_result is None:
            logger.warning(f'  ⚠️  スキャン失敗。このドメインをスキップします: {domain}')
            return
        logger.info(f"  ✅ スキャン完了 — IP: {scan_result.get('ip_address', 'N/A')}, レポート: {scan_result.get('scan_url', 'N/A')}")
        time.sleep(2)
        self._scan_count += 1
        logger.info(f'  🤖 [2/3] Gemini AI 分析中...')
        analysis = self._analyzer.analyze(
            screenshot_url=scan_result['screenshot_url'],
            dom_text=scan_result['dom_text'],
            page_url=url,
            detection_context=(
                f"{domain_info.get('reason', '')}; "
                f"candidate_kind={domain_info.get('candidate_kind', '')}; "
                f"page_signals={scan_result.get('page_signals', {})}"
            ),
        )
        if analysis is None:
            logger.warning(f'  ⚠️  AI 分析失敗。このドメインをスキップします: {domain}')
            return
        verdict = f'{analysis.verdict} ({analysis.confidence}%)'
        logger.info(f"  {verdict} — ブランド: {analysis.target_brand or 'N/A'}")
        logger.info(f'  特徴: {analysis.features[:100]}...' if len(analysis.features) > 100 else f'  特徴: {analysis.features}')
        decision = decide_report(domain_info, scan_result, analysis)
        if decision.confirmed:
            logger.info(f'  📝 [3/3] Excel に追記中...')
            self._reporter.append_record(url=url, target_brand=analysis.target_brand, features=decision.evidence_summary, detected_at=detected_at, category=decision.report_category)
            self._scam_count += 1
            logger.info(f'  ✅ 追記完了（累計詐欺件数: {self._scam_count}）')
        else:
            logger.info(f'  ⏭️  [3/3] 報告対象外: {decision.reason}')

    def _shutdown(self) -> None:
        self._running = False
        self._monitor.stop()
        logger.info('\n' + '=' * 60)
        logger.info('📊 実行結果サマリー')
        logger.info('=' * 60)
        logger.info(f'  スキャン実行数: {self._scan_count}')
        logger.info(f'  詐欺判定数:     {self._scam_count}')
        logger.info(f'  Gemini リクエスト数: {self._analyzer.request_count}')
        if self._reporter.appended_count > 0:
            saved_path = self._reporter.save()
            logger.info(f'  📄 Excel 保存先: {saved_path}')
        else:
            logger.info('  ℹ️  追記データがないため Excel は保存しませんでした')
        logger.info('=' * 60)
        logger.info('🏁 システムを正常終了しました')

def main() -> None:
    setup_logging()
    config = load_config()
    pipeline = Pipeline(config)
    pipeline.run()
if __name__ == '__main__':
    main()
