import logging
import os
import queue
import sys
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from pathlib import Path
from PyQt6.QtCore import QThread, pyqtSignal
sys.path.insert(0, str(Path(__file__).parent))
from app_config import DEFAULT_LIMITS

logger = logging.getLogger(__name__)

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

    def __init__(
        self,
        urlscan_api_key: str,
        gemini_api_key: str,
        max_scan_count: int,
        supabase_url: str = '',
        supabase_anon_key: str = '',
        supabase_email: str = '',
        supabase_password: str = '',
        scan_workers: int = 4,
        urlscan_submission_enabled: bool = False,
        ct_enabled: bool = False,
        phishing_feed_enabled: bool = True,
        llm_enabled: bool = False,
        automatic_learning_enabled: bool = True,
        parent=None,
    ):
        super().__init__(parent)
        self._urlscan_api_key = urlscan_api_key
        self._gemini_api_key = gemini_api_key
        self._max_scan_count = max_scan_count
        self._supabase_url = supabase_url
        self._supabase_anon_key = supabase_anon_key
        self._supabase_email = supabase_email
        self._supabase_password = supabase_password
        self._scan_workers = max(1, min(int(scan_workers), 8))
        self._urlscan_submission_enabled = bool(urlscan_submission_enabled)
        self._ct_enabled = bool(ct_enabled)
        self._phishing_feed_enabled = bool(phishing_feed_enabled)
        self._llm_enabled = bool(llm_enabled)
        self._automatic_learning_enabled = bool(automatic_learning_enabled)
        self._learning_model = None
        self._learning_status = '無効'
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
        from risk_scoring import assess_risk
        from domain_metadata import DomainMetadataResolver
        from supabase_repository import SupabaseRepository
        from verification import decide_report, should_analyze
        from online_learning import LearningModel, PREDICTION_THRESHOLD, build_feature_vector
        from url_audit_log import UrlAuditLog
        audit_log = UrlAuditLog()
        domain_queue: queue.Queue = queue.Queue(maxsize=DEFAULT_LIMITS.queue_size)
        monitor = DomainMonitor(
            domain_queue,
            ct_enabled=self._ct_enabled,
            phishing_feed_enabled=self._phishing_feed_enabled,
            audit_log=audit_log,
        )
        scanner = UrlScanner(
            self._urlscan_api_key,
            submission_enabled=self._urlscan_submission_enabled,
        )
        metadata_resolver = DomainMetadataResolver()
        analyzer = ScamAnalyzer(self._gemini_api_key) if self._llm_enabled else None
        repository = SupabaseRepository(
            self._supabase_url,
            self._supabase_anon_key,
            self._supabase_email,
            self._supabase_password,
            allowed_custom_host=os.getenv('SUPABASE_ALLOWED_HOST', ''),
        )
        self._supabase_password = ''
        self._supabase_anon_key = ''
        repository.connect()
        self.log_emitted.emit('INFO', '🔐 Supabase Auth・RLS接続を確認しました')
        self.log_emitted.emit(
            'INFO',
            f'📝 URL履歴を自動保存: {audit_log.filter_passed_path} / '
            f'{audit_log.scanned_path}',
        )
        if self._automatic_learning_enabled:
            try:
                model_payload = repository.get_active_learning_model()
                self._learning_model = LearningModel.from_dict(model_payload)
                if self._learning_model:
                    self._learning_status = f'稼働中 {self._learning_model.model_version[:8]}'
                    self.log_emitted.emit('INFO', f'🧠 学習モデルを読込: {self._learning_model.model_version[:8]}')
                elif model_payload:
                    self._learning_status = 'モデル破損・ルール継続'
                    self.log_emitted.emit(
                        'WARNING',
                        '学習モデルの形式が不正なため、安全なルール判定で継続します',
                    )
                else:
                    self._learning_status = '教師データ収集中'
            except Exception as exc:
                self._learning_model = None
                self._learning_status = 'DB更新待ち'
                self.log_emitted.emit('WARNING', f'自動学習モデルを利用できません: {exc}')
        scanner.set_status_callback(
            lambda status: self.stats_updated.emit({'urlscan': status})
        )
        if analyzer is not None:
            analyzer.set_status_callback(
                lambda status: self.stats_updated.emit({'gemini': status})
            )
        scan_count = 0
        scam_count = 0
        self.log_emitted.emit('INFO', '🔍 certstream 監視を開始します...')
        monitor.start()
        pending: dict[Future, tuple[dict, str]] = {}
        executor = ThreadPoolExecutor(max_workers=self._scan_workers, thread_name_prefix='urlscan')
        self.log_emitted.emit('INFO', f'⚡ 高速スキャンレーンを開始しました ({self._scan_workers}並列)')
        try:
            while not self._stop_requested and (scan_count < self._max_scan_count or pending):
                while not self._stop_requested and scan_count < self._max_scan_count and len(pending) < self._scan_workers:
                    try:
                        domain_info = domain_queue.get(timeout=0.25)
                    except queue.Empty:
                        break
                    claim = repository.claim_candidate(domain_info)
                    if claim is None:
                        self.log_emitted.emit('INFO', f"♻️ Supabase重複除外: {domain_info['domain']}")
                        continue
                    future = executor.submit(
                        self._collect_candidate,
                        scanner,
                        metadata_resolver,
                        audit_log,
                        domain_info,
                    )
                    pending[future] = (domain_info, claim.candidate_id)
                    scan_count += 1
                    self.log_emitted.emit('INFO', f"📡 スキャン開始 [{len(pending)}/{self._scan_workers}]: {domain_info['domain']}")

                if not pending:
                    self._emit_stats(monitor, scan_count, scam_count, scanner, analyzer)
                    continue
                done, _ = wait(tuple(pending), timeout=0.25, return_when=FIRST_COMPLETED)
                for future in done:
                    domain_info, candidate_id = pending.pop(future)
                    try:
                        scan_result, domain_info = future.result()
                    except Exception as exc:
                        scan_result = None
                        logger.exception('並列スキャン処理に失敗しました')
                        repository.record_scan(candidate_id, None, type(exc).__name__)
                    else:
                        repository.record_scan(candidate_id, scan_result, '' if scan_result else 'scan_failed')
                    if not scan_result:
                        self.log_emitted.emit('WARNING', f"⚠️ スキャン失敗: {domain_info['domain']}")
                        self._emit_stats(monitor, scan_count, scam_count, scanner, analyzer)
                        continue

                    assessment = assess_risk(domain_info, scan_result)
                    learning_features = build_feature_vector(domain_info, scan_result, assessment)
                    learning_probability = (
                        self._learning_model.predict_for_category(
                            assessment.category, learning_features
                        )
                        if self._learning_model else None
                    )
                    precheck = should_analyze(domain_info, scan_result)
                    if not self._llm_enabled or not precheck.proceed:
                        reason = (
                            'LLM補助分析は設定により無効'
                            if not self._llm_enabled else precheck.reason
                        )
                        repository.record_decision(
                            candidate_id, False, assessment.category,
                            f'{reason}; rules={",".join(assessment.applied_rules)}; '
                            f'completeness={assessment.completeness}',
                        )
                        if assessment.score >= 30 or (
                            learning_probability is not None
                            and learning_probability >= PREDICTION_THRESHOLD
                        ):
                            scam_count += 1
                            self._emit_review_candidate(
                                domain_info, scan_result, assessment, reason,
                                candidate_id=candidate_id,
                                learning_features=learning_features,
                                learning_probability=learning_probability,
                            )
                        self.log_emitted.emit('INFO', f"⚡ AI分析を省略: {domain_info['domain']} — {reason}")
                        self._emit_stats(monitor, scan_count, scam_count, scanner, analyzer)
                        continue

                    self.log_emitted.emit('INFO', f"🤖 AI 分析中: {domain_info['domain']}")
                    analysis = analyzer.analyze(
                        screenshot_url=scan_result['screenshot_url'],
                        dom_text=scan_result['dom_text'],
                        page_url=domain_info['url'],
                        detection_context=(
                            f"{domain_info.get('reason', '')}; "
                            f"candidate_kind={domain_info.get('candidate_kind', '')}; "
                            f"page_signals={scan_result.get('page_signals', {})}; "
                            f"vocabulary_score={scan_result.get('vocabulary_score', 0)}; "
                            f"vocabulary_evidence={scan_result.get('vocabulary_evidence', [])}"
                        ),
                    )
                    if not analysis:
                        repository.record_decision(
                            candidate_id,
                            False,
                            assessment.category,
                            '自動判定保留: AI補助分析失敗',
                        )
                        if assessment.score >= 30 or (
                            learning_probability is not None
                            and learning_probability >= PREDICTION_THRESHOLD
                        ):
                            scam_count += 1
                            self._emit_review_candidate(
                                domain_info,
                                scan_result,
                                assessment,
                                'AI補助分析に失敗。ルールと取得済み証拠で要レビュー',
                                candidate_id=candidate_id,
                                learning_features=learning_features,
                                learning_probability=learning_probability,
                            )
                        self.log_emitted.emit('WARNING', f"⚠️ AI 分析失敗: {domain_info['domain']}")
                        self._emit_stats(monitor, scan_count, scam_count, scanner, analyzer)
                        continue
                    assessment = assess_risk(domain_info, scan_result, analysis)
                    learning_features = build_feature_vector(
                        domain_info, scan_result, assessment, analysis
                    )
                    learning_probability = (
                        self._learning_model.predict_for_category(
                            assessment.category, learning_features
                        )
                        if self._learning_model else None
                    )
                    decision = decide_report(domain_info, scan_result, analysis)
                    repository.record_decision(
                        candidate_id, decision.confirmed,
                        decision.report_category if decision.confirmed else 'not_reportable',
                        decision.evidence_summary if decision.confirmed else decision.reason,
                    )
                    if decision.confirmed:
                        scam_count += 1
                        scan_url = scan_result.get('scan_url', '')
                        report_evidence = decision.evidence_summary
                        if scan_url:
                            report_evidence = f'{report_evidence}; urlscan証拠={scan_url}'
                        self._emit_review_candidate(
                            domain_info, scan_result, assessment, report_evidence,
                            target_brand=analysis.target_brand,
                            candidate_id=candidate_id,
                            learning_features=learning_features,
                            learning_probability=learning_probability,
                        )
                        self.log_emitted.emit('WARNING', f"🚨 要レビュー候補: {domain_info['domain']} (ブランド: {analysis.target_brand})")
                    else:
                        if (
                            learning_probability is not None
                            and learning_probability >= PREDICTION_THRESHOLD
                        ):
                            scam_count += 1
                            self._emit_review_candidate(
                                domain_info, scan_result, assessment,
                                f'学習モデルが要レビュー候補として抽出; {decision.reason}',
                                target_brand=analysis.target_brand,
                                candidate_id=candidate_id,
                                learning_features=learning_features,
                                learning_probability=learning_probability,
                            )
                        self.log_emitted.emit('INFO', f"⏭️ 報告対象外: {domain_info['domain']} — {decision.reason}")
                    self._emit_stats(monitor, scan_count, scam_count, scanner, analyzer)
            if scan_count >= self._max_scan_count:
                self.log_emitted.emit('INFO', f'✅ 最大スキャン数 ({self._max_scan_count}) に達しました')
        finally:
            monitor.stop()
            for future in pending:
                future.cancel()
            executor.shutdown(wait=True, cancel_futures=True)
            repository.close()
        self.finished_with_result.emit('')
        self._emit_stats(monitor, scan_count, scam_count, scanner, analyzer)

    def _emit_review_candidate(self, domain_info, scan_result, assessment, features, target_brand='', candidate_id='', learning_features=None, learning_probability=None) -> None:
        self.scam_detected.emit({
            'candidate_id': candidate_id,
            'review_version': 0,
            'detected_at': domain_info.get('detected_at', ''),
            'first_seen_at': domain_info.get('detected_at', ''),
            'last_observed_at': (
                domain_info.get('detected_at', '')
                if scan_result.get('fetch_status') == 'observed' else ''
            ),
            'source': domain_info.get('source', ''),
            'domain': domain_info.get('domain', ''),
            'url': domain_info.get('url', ''),
            'target_brand': target_brand or domain_info.get('brand', ''),
            'category': assessment.category,
            'priority': assessment.priority,
            'priority_label': assessment.priority_label,
            'risk_score': assessment.score,
            'learning_probability': learning_probability,
            'learning_model_version': (
                self._learning_model.model_version if self._learning_model else ''
            ),
            'learning_features': learning_features or {},
            'completeness': assessment.completeness,
            'completeness_label': assessment.completeness_label,
            'review_status': 'unreviewed',
            'review_status_label': '未レビュー',
            'features': features,
            'rules': ', '.join(assessment.applied_rules),
            'missing_evidence': ', '.join(assessment.missing_evidence),
            'dns_status': domain_info.get('dns_status', ''),
            'dns_addresses': ', '.join(domain_info.get('dns_addresses', [])),
            'rdap_status': domain_info.get('rdap_status', ''),
            'domain_age_days': domain_info.get('domain_age_days'),
            'scan_url': scan_result.get('scan_url', ''),
            'screenshot_url': scan_result.get('screenshot_url', ''),
            'ip_address': scan_result.get('ip_address', ''),
        })

    @staticmethod
    def _collect_candidate(scanner, metadata_resolver, audit_log, domain_info):
        audit_log.record_scanned(
            domain_info['url'],
            domain=domain_info.get('domain', ''),
            source=domain_info.get('source', ''),
            candidate_kind=domain_info.get('candidate_kind', ''),
        )
        scan_result = scanner.scan(domain_info['url'])
        enriched = metadata_resolver.enrich(domain_info)
        if scan_result is not None:
            scan_result = dict(scan_result)
            scan_result['dns_status'] = enriched.get('dns_status', '')
            scan_result['dns_addresses'] = enriched.get('dns_addresses', [])
            scan_result['rdap_status'] = enriched.get('rdap_status', '')
            scan_result['domain_age_days'] = enriched.get('domain_age_days')
            scan_result['rdap_registrar'] = enriched.get('rdap_registrar', '')
        return scan_result, enriched

    def _emit_stats(self, monitor, scan_count: int, scam_count: int, scanner, analyzer) -> None:
        m_stats = monitor.stats
        self.stats_updated.emit({
            'processed': m_stats['processed'],
            'accepted': m_stats['accepted'],
            'duplicates': m_stats.get('duplicates', 0),
            'source_counts': m_stats.get('source_counts', {}),
            'backlog': getattr(monitor, '_queue', ()).qsize() if hasattr(getattr(monitor, '_queue', None), 'qsize') else 0,
            'scanned': scan_count,
            'scams': scam_count,
            'urlscan': scanner.rate_limit_status,
            'gemini': analyzer.usage_status if analyzer is not None else {
                'requests': 0, 'total_tokens': 0, 'model': '無効'
            },
            'learning': {
                'enabled': self._automatic_learning_enabled,
                'status': self._learning_status,
                'model_version': (
                    self._learning_model.model_version if self._learning_model else ''
                ),
            },
        })
