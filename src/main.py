import logging
import os
import queue
import sys
import time
from pathlib import Path
from dotenv import load_dotenv
sys.path.insert(0, str(Path(__file__).parent))
from monitor import DomainMonitor
from scanner import UrlScanner
from analyzer import ScamAnalyzer
from verification import decide_report, should_analyze
from risk_scoring import assess_risk
from app_config import (
    load_feature_flags,
    load_operational_limits,
)
from domain_metadata import DomainMetadataResolver
from online_learning import LearningModel, build_feature_vector
from url_audit_log import UrlAuditLog
from supabase_repository import SupabaseRepository
from key_manager import (
    GEMINI_KEY_NAME,
    SUPABASE_ANON_KEY_NAME,
    SUPABASE_PASSWORD_NAME,
    URLSCAN_KEY_NAME,
    get_api_key,
)

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
    features = load_feature_flags()
    limits = load_operational_limits()
    if features.automatic_reporting_enabled:
        raise ValueError('AUTOMATIC_REPORTING_ENABLED=true は安全上許可されていません')
    urlscan_key = get_api_key(URLSCAN_KEY_NAME) or os.getenv('URLSCAN_API_KEY', '')
    gemini_key = get_api_key(GEMINI_KEY_NAME) or os.getenv('GEMINI_API_KEY', '')
    supabase_anon_key = get_api_key(SUPABASE_ANON_KEY_NAME) or os.getenv('SUPABASE_ANON_KEY', '')
    supabase_password = get_api_key(SUPABASE_PASSWORD_NAME) or os.getenv('SUPABASE_PASSWORD', '')
    config = {
        'urlscan_api_key': urlscan_key,
        'gemini_api_key': gemini_key,
        'max_scan_count': limits.max_scan_count,
        'queue_size': limits.queue_size,
        'features': features,
        'supabase_url': os.getenv('SUPABASE_URL', ''),
        'supabase_anon_key': supabase_anon_key,
        'supabase_email': os.getenv('SUPABASE_EMAIL', ''),
        'supabase_password': supabase_password,
    }
    missing = []
    if not config['urlscan_api_key']:
        missing.append('URLSCAN_API_KEY')
    if features.llm_enabled and not config['gemini_api_key']:
        missing.append('GEMINI_API_KEY')
    for key in ('supabase_url', 'supabase_anon_key', 'supabase_email', 'supabase_password'):
        if not config[key]:
            missing.append(key.upper())
    if missing:
        logger.error(f"❌ 必須の環境変数が設定されていません: {', '.join(missing)}\n   .env ファイルを確認するか、GUIからキーを保存してください")
        sys.exit(1)
    return config


class Pipeline:

    def __init__(self, config: dict):
        self._config = config
        self._domain_queue: queue.Queue = queue.Queue(maxsize=config['queue_size'])
        features = config['features']
        self._audit_log = UrlAuditLog()
        self._monitor: DomainMonitor = DomainMonitor(
            self._domain_queue,
            ct_enabled=features.ct_enabled,
            phishing_feed_enabled=features.phishing_feed_enabled,
            audit_log=self._audit_log,
        )
        self._scanner: UrlScanner = UrlScanner(
            config['urlscan_api_key'],
            submission_enabled=features.urlscan_submission_enabled,
        )
        self._analyzer = ScamAnalyzer(config['gemini_api_key']) if features.llm_enabled else None
        self._metadata_resolver = DomainMetadataResolver()
        self._repository = SupabaseRepository(
            config['supabase_url'], config['supabase_anon_key'],
            config['supabase_email'], config['supabase_password'],
            allowed_custom_host=os.getenv('SUPABASE_ALLOWED_HOST', ''),
        )
        config['supabase_password'] = ''
        config['supabase_anon_key'] = ''
        self._running = True
        self._scan_count = 0
        self._scam_count = 0
        self._max_scan_count = config['max_scan_count']
        self._learning_model = None

    def run(self) -> None:
        logger.info('=' * 60)
        logger.info('🛡️  日本向け詐欺サイト自動検知システム 起動')
        logger.info('=' * 60)
        logger.info(f'最大スキャン数: {self._max_scan_count}')
        logger.info('自動出力は無効です。人手レビューはGUIから実施してください')
        logger.info(
            'URL履歴: %s / %s',
            self._audit_log.filter_passed_path,
            self._audit_log.scanned_path,
        )
        logger.info('=' * 60)
        self._repository.connect()
        logger.info('🔐 Supabase Auth・RLS接続を確認しました')
        if self._config['features'].automatic_learning_enabled:
            try:
                model_payload = self._repository.get_active_learning_model()
                self._learning_model = LearningModel.from_dict(model_payload)
                if self._learning_model:
                    logger.info(
                        '自動学習モデルを読み込みました: %s',
                        self._learning_model.model_version,
                    )
                elif model_payload:
                    logger.warning(
                        '学習モデルの形式が不正なため、ルール判定で継続します'
                    )
                else:
                    logger.info('自動学習: 現在は教師データ収集中です')
            except Exception as exc:
                logger.warning('自動学習は利用できませんが、通常判定を継続します: %s', exc)
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
        claim = self._repository.claim_candidate(domain_info)
        if claim is None:
            logger.info(f'  ♻️ Supabase重複除外: {domain}')
            return
        logger.info(f"\n{'─' * 50}")
        logger.info(f'🔬 処理開始 [{self._scan_count + 1}/{self._max_scan_count}]: {domain}')
        logger.info(f'  📡 [1/3] urlscan.io スキャン送信中...')
        self._audit_log.record_scanned(
            url,
            domain=domain,
            source=domain_info.get('source', ''),
            candidate_kind=domain_info.get('candidate_kind', ''),
        )
        scan_result = self._scanner.scan(url)
        if scan_result is None:
            self._repository.record_scan(claim.candidate_id, None, 'scan_failed')
            logger.warning(f'  ⚠️  スキャン失敗。このドメインをスキップします: {domain}')
            return
        domain_info = self._metadata_resolver.enrich(domain_info)
        scan_result.update({
            'dns_status': domain_info.get('dns_status', ''),
            'dns_addresses': domain_info.get('dns_addresses', []),
            'rdap_status': domain_info.get('rdap_status', ''),
            'domain_age_days': domain_info.get('domain_age_days'),
            'rdap_registrar': domain_info.get('rdap_registrar', ''),
        })
        self._repository.record_scan(claim.candidate_id, scan_result)
        logger.info(f"  ✅ スキャン完了 — IP: {scan_result.get('ip_address', 'N/A')}, レポート: {scan_result.get('scan_url', 'N/A')}")
        self._scan_count += 1
        assessment = assess_risk(domain_info, scan_result)
        learning_features = build_feature_vector(domain_info, scan_result, assessment)
        if self._learning_model:
            learning_probability = self._learning_model.predict_for_category(
                assessment.category, learning_features
            )
            if learning_probability is not None:
                logger.info(
                    '  学習モデルの要レビュー予測: %.1f%%',
                    learning_probability * 100,
                )
        precheck = should_analyze(domain_info, scan_result)
        if self._analyzer is None or not precheck.proceed:
            reason = 'LLM補助分析は無効' if self._analyzer is None else precheck.reason
            self._repository.record_decision(
                claim.candidate_id, False, assessment.category,
                f'{reason}; score={assessment.score}; completeness={assessment.completeness}',
            )
            logger.info(
                '  レビュー優先度=%s (%s点)、情報充足度=%s: %s',
                assessment.priority_label, assessment.score,
                assessment.completeness_label, reason,
            )
            return
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
        assessment = assess_risk(domain_info, scan_result, analysis)
        learning_features = build_feature_vector(
            domain_info, scan_result, assessment, analysis
        )
        if self._learning_model:
            learning_probability = self._learning_model.predict_for_category(
                assessment.category, learning_features
            )
            if learning_probability is not None:
                logger.info(
                    '  AI証拠反映後の学習予測: %.1f%%',
                    learning_probability * 100,
                )
        verdict = f'{analysis.verdict} ({analysis.confidence}%)'
        logger.info(f"  {verdict} — ブランド: {analysis.target_brand or 'N/A'}")
        logger.info(f'  特徴: {analysis.features[:100]}...' if len(analysis.features) > 100 else f'  特徴: {analysis.features}')
        decision = decide_report(domain_info, scan_result, analysis)
        self._repository.record_decision(
            claim.candidate_id, decision.confirmed,
            decision.report_category if decision.confirmed else 'not_reportable',
            decision.evidence_summary if decision.confirmed else decision.reason,
        )
        if decision.confirmed:
            self._scam_count += 1
            logger.info('  要レビュー候補として保存しました。自動報告・自動出力はしません')
        else:
            logger.info(f'  ⏭️  [3/3] 報告対象外: {decision.reason}')

    def _shutdown(self) -> None:
        self._running = False
        self._monitor.stop()
        self._repository.close()
        logger.info('\n' + '=' * 60)
        logger.info('📊 実行結果サマリー')
        logger.info('=' * 60)
        logger.info(f'  スキャン実行数: {self._scan_count}')
        logger.info(f'  詐欺判定数:     {self._scam_count}')
        logger.info(f'  Gemini リクエスト数: {self._analyzer.request_count if self._analyzer else 0}')
        logger.info('  Excel出力: 人手レビュー前のため未実施')
        logger.info('=' * 60)
        logger.info('🏁 システムを正常終了しました')

def main() -> None:
    setup_logging()
    config = load_config()
    pipeline = Pipeline(config)
    pipeline.run()
if __name__ == '__main__':
    main()
