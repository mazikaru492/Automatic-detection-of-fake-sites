"""Conservative deterministic gate for deciding what may be reported."""

from dataclasses import dataclass
import re
from urllib.parse import urlparse

from monitor import BRAND_ALIASES, SAFE_DOMAINS, TLD_EXTRACT

MIN_AI_CONFIDENCE = 90
MIN_COMMERCE_CONFIDENCE = 95
MIN_URLSCAN_SCORE = 70
MIN_VOCABULARY_REVIEW_SCORE = 45
MALICIOUS_CATEGORIES = {'phishing', 'malware'}


@dataclass(frozen=True)
class ReportDecision:
    confirmed: bool
    reason: str
    evidence_summary: str = ''
    report_category: str = ''


@dataclass(frozen=True)
class AnalysisPrecheck:
    proceed: bool
    reason: str


def _registered_domain(value: str) -> str:
    hostname = (urlparse(value).hostname if '://' in value else value) or ''
    hostname = hostname.lower().removeprefix('*.').rstrip('.')
    extracted = TLD_EXTRACT(hostname)
    return extracted.registered_domain or hostname


def _normalise_brand(value: str) -> str:
    return re.sub(r'[^0-9a-z\u3040-\u30ff\u3400-\u9fff]+', '', value.casefold())


def is_official_domain(value: str) -> bool:
    return _registered_domain(value) in SAFE_DOMAINS


def _has_signal(scan_result: dict, category: str) -> bool:
    return bool((scan_result.get('page_signals') or {}).get(category))


def _analysis_category(analysis) -> str:
    category = str(getattr(analysis, 'site_category', '') or '')
    if category and category != 'unknown':
        return category
    # Compatibility with results generated before multi-category analysis.
    if getattr(analysis, 'credential_or_payment_request', False):
        return 'phishing'
    if getattr(analysis, 'deceptive_commerce', False):
        return 'fraudulent_shop'
    return 'unknown'


def _base_evidence(analysis, details: str) -> str:
    features = str(getattr(analysis, 'features', '') or '')
    return f"確認根拠: AI確信度={analysis.confidence}%; {details}; {features}"[:500]


def should_analyze(domain_info: dict, scan_result: dict) -> AnalysisPrecheck:
    """Skip Gemini when deterministic evidence cannot satisfy the final gate."""
    if scan_result.get('fetch_status') == 'not_observed':
        return AnalysisPrecheck(
            False,
            f"ページ未観測 ({scan_result.get('missing_reason') or 'evidence_missing'})",
        )
    kind = str(domain_info.get('candidate_kind', '') or '')
    signals = scan_result.get('page_signals') or {}
    has_transaction = bool(signals.get('transaction'))
    vocabulary_score = int(scan_result.get('vocabulary_score', 0) or 0)
    vocabulary_categories = set(scan_result.get('vocabulary_categories') or [])
    if kind in ('brand_impersonation', 'known_phishing'):
        if (
            domain_info.get('known_phishing') is True
            or scan_result.get('urlscan_malicious') is True
            or bool(signals.get('credential'))
        ):
            return AnalysisPrecheck(True, 'フィッシング確認に必要な独立シグナルあり')
        return AnalysisPrecheck(False, 'ログイン・認証入力または外部脅威情報がありません')
    if kind == 'suspicious_shop':
        legacy_fraud = len(signals.get('fraud') or []) >= 2
        vocabulary_fraud = (
            vocabulary_score >= MIN_VOCABULARY_REVIEW_SCORE
            and len(vocabulary_categories) >= 2
        )
        if has_transaction and (legacy_fraud or vocabulary_fraud):
            return AnalysisPrecheck(True, '購入導線と複数の詐欺通販シグナルあり')
        return AnalysisPrecheck(False, '購入導線と詐欺通販の赤旗2種類が揃っていません')
    if kind == 'counterfeit_goods':
        if has_transaction and bool(signals.get('counterfeit')):
            return AnalysisPrecheck(True, '購入導線とコピー商品シグナルあり')
        return AnalysisPrecheck(False, '購入導線またはコピー商品の具体的表示がありません')
    if kind == 'suspected_illegal_goods':
        if has_transaction and bool(signals.get('illegal_goods')):
            return AnalysisPrecheck(True, '購入導線と規制商品シグナルあり')
        return AnalysisPrecheck(False, '購入導線または規制商品の具体的表示がありません')
    return AnalysisPrecheck(False, '分析対象カテゴリを確認できません')


def _decide_phishing(domain_info: dict, scan_result: dict, analysis) -> ReportDecision:
    if analysis.confidence < MIN_AI_CONFIDENCE:
        return ReportDecision(False, f'AI確信度不足 ({analysis.confidence}%)')
    if not getattr(analysis, 'brand_domain_mismatch', False):
        return ReportDecision(False, 'ブランドとドメインの不一致を確認できません')
    if not getattr(analysis, 'credential_or_payment_request', False):
        return ReportDecision(False, '認証情報・個人情報・支払い要求の証拠がありません')
    impersonation = str(getattr(analysis, 'impersonation_evidence', '') or '').strip()
    if not impersonation:
        return ReportDecision(False, 'ブランド偽装の具体的証拠がありません')

    candidate_brand = str(domain_info.get('brand', '')).strip()
    if not candidate_brand or candidate_brand not in BRAND_ALIASES:
        return ReportDecision(False, '監視対象ブランドを特定できません')
    if _normalise_brand(candidate_brand) != _normalise_brand(
        str(getattr(analysis, 'target_brand', ''))
    ):
        return ReportDecision(False, 'ドメイン検出と画面分析のブランドが一致しません')

    categories = {str(value).lower() for value in scan_result.get('urlscan_categories', [])}
    urlscan_confirmed = (
        scan_result.get('urlscan_malicious') is True
        and scan_result.get('urlscan_score', 0) >= MIN_URLSCAN_SCORE
        and bool(categories & MALICIOUS_CATEGORIES)
    )
    feed_confirmed = domain_info.get('known_phishing') is True
    domain_page_confirmed = (
        domain_info.get('candidate_kind') == 'brand_impersonation'
        and int(domain_info.get('score', 0) or 0) >= 7
        and _has_signal(scan_result, 'credential')
    )
    if not (urlscan_confirmed or feed_confirmed or domain_page_confirmed):
        return ReportDecision(False, '独立した脅威情報による確認が不足しています')

    sources = []
    if feed_confirmed:
        sources.append('OpenPhish')
    if urlscan_confirmed:
        sources.append(f"urlscan(score={scan_result.get('urlscan_score')})")
    if domain_page_confirmed:
        sources.append('不審ドメイン＋認証入力画面')
    evidence = _base_evidence(
        analysis,
        f"情報源={', '.join(sources)}; 偽装={impersonation}",
    )
    return ReportDecision(True, '複数の独立根拠が一致', evidence, 'フィッシングサイト')


def _decide_commerce(category: str, domain_info: dict, scan_result: dict, analysis) -> ReportDecision:
    if analysis.confidence < MIN_COMMERCE_CONFIDENCE:
        return ReportDecision(False, f'通販系判定のAI確信度不足 ({analysis.confidence}%)')
    if not getattr(analysis, 'transaction_evidence', False):
        return ReportDecision(False, '注文・購入・決済が可能という証拠がありません')
    if not _has_signal(scan_result, 'transaction'):
        return ReportDecision(False, 'ページ本文から購入導線を確認できません')

    candidate_kind = str(domain_info.get('candidate_kind', '') or '')
    candidate_score = int(domain_info.get('score', 0) or 0)

    if category == 'fraudulent_shop':
        if not getattr(analysis, 'deceptive_commerce', False):
            return ReportDecision(False, '架空・欺瞞的な販売の具体的証拠がありません')
        red_flag_count = int(getattr(analysis, 'red_flag_count', 0) or 0)
        fraud_signals = (scan_result.get('page_signals') or {}).get('fraud') or []
        vocabulary_score = int(scan_result.get('vocabulary_score', 0) or 0)
        vocabulary_categories = set(scan_result.get('vocabulary_categories') or [])
        corroborated_vocabulary = (
            vocabulary_score >= MIN_VOCABULARY_REVIEW_SCORE
            and len(vocabulary_categories) >= 2
        )
        if red_flag_count < 2 or not (len(fraud_signals) >= 2 or corroborated_vocabulary):
            return ReportDecision(False, '独立した詐欺通販の赤旗が2種類以上確認できません')
        details = str(getattr(analysis, 'red_flags', '') or '').strip()
        if corroborated_vocabulary:
            evidence = ','.join(str(value) for value in scan_result.get('vocabulary_evidence', [])[:4])
            details = f'{details}; 語彙スコア={vocabulary_score} ({evidence})'
        label = '詐欺通販サイト（要確認）'
        expected_kind = 'suspicious_shop'
    elif category == 'counterfeit_goods':
        details = str(getattr(analysis, 'counterfeit_evidence', '') or '').strip()
        if not details or not _has_signal(scan_result, 'counterfeit'):
            return ReportDecision(False, 'コピー商品販売の具体的な二重証拠がありません')
        label = 'コピー商品販売サイト（要確認）'
        expected_kind = 'counterfeit_goods'
    elif category == 'suspected_illegal_goods':
        details = str(getattr(analysis, 'illegal_goods_evidence', '') or '').strip()
        if not details or not _has_signal(scan_result, 'illegal_goods'):
            return ReportDecision(False, '規制対象商品の販売を示す具体的な二重証拠がありません')
        label = '違法商品販売の疑い（要確認）'
        expected_kind = 'suspected_illegal_goods'
    else:
        return ReportDecision(False, '報告可能な分類ではありません')

    if candidate_kind != expected_kind and candidate_score < 7:
        return ReportDecision(False, '候補抽出とページ分析の分類が一致しません')
    evidence = _base_evidence(
        analysis,
        f"候補={candidate_kind or '汎用'}; ページ証拠={details}",
    )
    return ReportDecision(True, 'AI・ドメイン・ページ本文の根拠が一致', evidence, label)


def decide_report(domain_info: dict, scan_result: dict, analysis) -> ReportDecision:
    """Report only cases supported by category-specific independent evidence."""
    candidate_domain = _registered_domain(domain_info.get('domain', ''))
    final_domain = _registered_domain(
        scan_result.get('page_apex_domain')
        or scan_result.get('page_domain')
        or scan_result.get('page_url', '')
        or candidate_domain
    )
    if not candidate_domain:
        return ReportDecision(False, '候補ドメインを確認できません')
    if is_official_domain(candidate_domain) or is_official_domain(final_domain):
        return ReportDecision(False, '正規ドメインまたは正規ドメインへの遷移を確認')
    if analysis is None:
        return ReportDecision(False, 'AIによる内容確認が完了していません')
    if getattr(analysis, 'verdict', '') not in ('reportable', 'confirmed_scam'):
        return ReportDecision(
            False,
            f"AI判定が報告条件外 ({getattr(analysis, 'verdict', 'unknown')}, "
            f"{getattr(analysis, 'confidence', 0)}%)",
        )

    category = _analysis_category(analysis)
    if category == 'phishing':
        return _decide_phishing(domain_info, scan_result, analysis)
    return _decide_commerce(category, domain_info, scan_result, analysis)
