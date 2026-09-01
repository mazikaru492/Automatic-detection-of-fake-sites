import base64
import datetime
import logging
import threading
import queue
import re
import time
from collections import Counter, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional
from urllib.parse import urlparse
import requests
import tldextract
from cryptography import x509

logger = logging.getLogger(__name__)
CHROME_LOG_LIST_URL = 'https://www.gstatic.com/ct/log_list/v3/log_list.json'
CT_REQUEST_TIMEOUT_SEC = 20
CT_BATCH_SIZE = 1024
CT_INITIAL_LOOKBACK = 256
CT_POLL_INTERVAL_SEC = 2
OPENPHISH_FEED_URL = 'https://openphish.com/feed.txt'
OPENPHISH_REFRESH_SEC = 30 * 60
DIVERSITY_WINDOW_SEC = 10 * 60
MAX_CANDIDATES_PER_GROUP = 8
BRAND_ALIASES: dict[str, tuple[str, ...]] = {
    '佐川急便': ('sagawa',),
    'ヤマト運輸': ('yamato', 'kuroneko'),
    '日本郵便': ('japanpost', 'jppost', 'yuubin', 'yubin'),
    'Amazon': ('amazon',),
    '楽天': ('rakuten', 'rakutencard'),
    'メルカリ': ('mercari',),
    'Yahoo! JAPAN': ('yahoo',),
    'NTTドコモ': ('docomo', 'nttdocomo', 'daccount'),
    'SoftBank': ('softbank',),
    '三井住友銀行': ('smbc',),
    'みずほ銀行': ('mizuho',),
    '三菱UFJ': ('mufg', 'mitsubishiufj'),
    'ゆうちょ銀行': ('yucho', 'jpbank', 'japanpostbank'),
    'PayPay': ('paypay',),
    'PayPal': ('paypal',),
    'LINE': ('line',),
    'イオン': ('aeon', 'aeoncard'),
    'JCB': ('jcb',),
    'セゾンカード': ('saison', 'saisoncard'),
    'エポスカード': ('epos', 'eposcard'),
    'オリコ': ('orico',),
    'dカード': ('dcard',),
    'SBI証券': ('sbisec',),
    '野村證券': ('nomura',),
    '大和証券': ('daiwa',),
    'マネックス証券': ('monex',),
    '松井証券': ('matsui',),
}
PHISHING_KEYWORDS: set[str] = {
    'account', 'auth', 'card', 'confirm', 'id', 'login', 'member', 'official',
    'payment', 'secure', 'security', 'service', 'signin', 'support', 'update',
    'verify', 'wallet', 'japan', 'jp',
}
COMMERCE_KEYWORDS: set[str] = {
    'buy', 'deal', 'deals', 'mall', 'market', 'outlet', 'sale', 'shop',
    'store', 'wholesale',
}
SCAM_SHOP_KEYWORDS: set[str] = {
    'bargain', 'clearance', 'closing', 'discount', 'limited', 'liquidation',
    'officialsale', 'stockout', 'warehouse',
}
COUNTERFEIT_KEYWORDS: set[str] = {
    'clone', 'copybrand', 'counterfeit', 'fakebrand', 'mirrorcopy', 'replica',
    'superclone', 'supercopy',
}
ILLICIT_GOODS_KEYWORDS: set[str] = {
    'anabolic', 'cannabis', 'cocaine', 'designerdrug', 'fentanyl', 'marijuana',
    'mdma', 'researchchemical', 'steroid', 'thc',
}
SUSPICIOUS_TLDS: list[str] = ['.top', '.xyz', '.shop', '.club', '.vip', '.cn', '.buzz', '.icu', '.fit', '.surf', '.space', '.gdn', '.win', '.loan', '.date', '.accountant']
SAFE_DOMAINS: set[str] = {
    'aeon.co.jp', 'aeonbank.co.jp', 'amazon.co.jp', 'amazon.com',
    'd-card.jp', 'docomo.ne.jp', 'eposcard.co.jp', 'jcb.co.jp',
    'japanpost.jp', 'jp-bank.japanpost.jp', 'kuronekoyamato.co.jp',
    'line.biz', 'line.me', 'linecorp.com', 'matsui.co.jp', 'mercari.com',
    'mizuhobank.co.jp', 'monex.co.jp', 'mufg.jp', 'nomura.co.jp',
    'orico.co.jp', 'paypay.ne.jp', 'paypay-card.co.jp', 'paypay-bank.co.jp',
    'rakuten.co.jp', 'sagawa-exp.co.jp', 'paypal.com', 'paypal.jp',
    'paypalobjects.com',
    'saisoncard.co.jp', 'sbisec.co.jp', 'smbc.co.jp', 'softbank.jp',
    'yahoo.co.jp',
}
TLD_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())

def _edit_distance_at_most_one(left: str, right: str) -> bool:
    if abs(len(left) - len(right)) > 1:
        return False
    if len(left) > len(right):
        left, right = right, left
    if len(left) == len(right):
        return sum(a != b for a, b in zip(left, right)) == 1
    index_left = index_right = differences = 0
    while index_left < len(left) and index_right < len(right):
        if left[index_left] == right[index_right]:
            index_left += 1
        else:
            differences += 1
            if differences > 1:
                return False
        index_right += 1
    return True

def classify_domain_candidate(domain: str) -> tuple[int, str, str, str]:
    if not domain:
        return (0, '', '', '')
    domain_lower = domain.lower().removeprefix('*.').rstrip('.')
    ext = TLD_EXTRACT(domain_lower)
    registered_domain = ext.registered_domain
    if registered_domain in SAFE_DOMAINS:
        return (0, '', '', '')
    labels = [part for part in re.split(r'[.\-_]+', domain_lower) if part]
    compact_labels = [part.replace('-', '') for part in domain_lower.split('.')]
    matched_brand = ''
    matched_alias = ''
    brand_score = 0
    for brand, aliases in BRAND_ALIASES.items():
        for alias in aliases:
            if alias in labels:
                score = 5
            elif len(alias) >= 5 and any(
                label.startswith(alias) and len(label) <= len(alias) + 12
                for label in compact_labels
            ):
                score = 4
            elif len(alias) >= 5 and any(
                len(label) == len(alias) and
                _edit_distance_at_most_one(label, alias) for label in labels
            ):
                score = 4
            else:
                continue
            if score > brand_score:
                matched_brand, matched_alias, brand_score = brand, alias, score
    signals: list[str] = []
    candidate_kind = ''
    if matched_brand:
        score = brand_score
        candidate_kind = 'brand_impersonation'
        signals.append(f'brand={matched_brand}({matched_alias})')
    else:
        def keyword_matches(keywords: set[str]) -> list[str]:
            return sorted({
                keyword for keyword in keywords
                if keyword in labels or (
                    len(keyword) >= 5 and any(keyword in label for label in compact_labels)
                )
            })

        commerce_matches = keyword_matches(COMMERCE_KEYWORDS)
        counterfeit_matches = keyword_matches(COUNTERFEIT_KEYWORDS)
        illicit_matches = keyword_matches(ILLICIT_GOODS_KEYWORDS)
        scam_shop_matches = keyword_matches(SCAM_SHOP_KEYWORDS)
        score = 0
        if counterfeit_matches:
            score += 5
            candidate_kind = 'counterfeit_goods'
            signals.append(f"模倣品語={','.join(counterfeit_matches[:3])}")
        elif illicit_matches:
            score += 5
            candidate_kind = 'suspected_illegal_goods'
            signals.append(f"規制商品語={','.join(illicit_matches[:3])}")
        if commerce_matches:
            score += 2
            candidate_kind = candidate_kind or 'suspicious_shop'
            signals.append(f"通販語={','.join(commerce_matches[:3])}")
        if commerce_matches and scam_shop_matches:
            score += 2
            candidate_kind = candidate_kind or 'suspicious_shop'
            signals.append(f"詐欺販売語={','.join(scam_shop_matches[:3])}")
    has_suspicious_tld = any((domain_lower.endswith(tld) for tld in SUSPICIOUS_TLDS))
    if has_suspicious_tld:
        score += 2
        signals.append('危険TLD')
    if matched_brand:
        keyword_matches = sorted({
            keyword
            for keyword in PHISHING_KEYWORDS
            if keyword in labels or (
                len(keyword) >= 4 and any(keyword in label for label in compact_labels)
            )
        })
        if keyword_matches:
            score += 2
            signals.append(f"誘導語={','.join(keyword_matches[:3])}")
    if 'xn--' in domain_lower:
        score += 2
        signals.append('IDN')
    if not candidate_kind or score < 1:
        return (0, '', '', '')
    reason = f"score={score}; candidate={candidate_kind}; " + '; '.join(signals)
    return (score, matched_brand, reason, candidate_kind)

def evaluate_domain(domain: str) -> tuple[int, str, str]:
    score, brand, reason, _ = classify_domain_candidate(domain)
    return (score, brand, reason)

def is_suspicious(domain: str) -> tuple[bool, str]:
    score, _, reason = evaluate_domain(domain)
    return (score >= 5, reason)

class DomainMonitor:

    def __init__(self, domain_queue: queue.Queue, max_queue_size: int=500):
        self._queue = domain_queue
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._processed_count = 0
        self._accepted_count = 0
        self._session = requests.Session()
        self._seen_domains: set[str] = set()
        self._seen_domain_order: deque[str] = deque(maxlen=100000)
        self._candidate_group_history: deque[tuple[float, str]] = deque()
        self._candidate_group_counts: Counter[str] = Counter()

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            logger.warning('DomainMonitor は既に実行中です')
            return
        self._thread = threading.Thread(target=self._run, name='certstream-monitor', daemon=True)
        self._thread.start()
        logger.info('🔍 certstream 監視スレッドを開始しました')

    def stop(self) -> None:
        self._stop_event.set()
        logger.info('🛑 certstream 監視を停止中...')

    @property
    def stats(self) -> dict:
        return {'processed': self._processed_count, 'accepted': self._accepted_count}

    def _run(self) -> None:
        try:
            log_urls = self._load_log_urls()
            cursors: dict[str, int] = {}
            with ThreadPoolExecutor(max_workers=min(8, len(log_urls))) as executor:
                futures = {
                    executor.submit(self._get_tree_size, url): url for url in log_urls
                }
                for future in as_completed(futures):
                    url = futures[future]
                    try:
                        cursors[url] = max(0, future.result() - CT_INITIAL_LOOKBACK)
                    except Exception as e:
                        logger.warning(f'応答しないCTログを除外しました ({url}): {e}')
            log_urls = list(cursors)
            if not log_urls:
                raise RuntimeError('応答するCTログがありません')
            logger.info(f'✅ Certificate Transparency 直接監視を開始しました ({len(log_urls)}ログ)')
        except Exception as e:
            logger.error(f'CTログ一覧の取得に失敗しました: {e}')
            return

        next_feed_refresh = 0.0
        while not self._stop_event.is_set():
            if time.monotonic() >= next_feed_refresh:
                self._load_openphish_candidates()
                next_feed_refresh = time.monotonic() + OPENPHISH_REFRESH_SEC
            received = 0
            for url in log_urls:
                if self._stop_event.is_set():
                    break
                try:
                    tree_size = self._get_tree_size(url)
                    cursor = cursors[url]
                    while cursor < tree_size and not self._stop_event.is_set():
                        end = min(cursor + CT_BATCH_SIZE - 1, tree_size - 1)
                        entries = self._fetch_entries(url, cursor, end)
                        if not entries:
                            break
                        for entry in entries:
                            try:
                                self._process_domains(self._domains_from_entry(entry))
                            except (KeyError, TypeError, ValueError) as e:
                                logger.debug(f'CT証明書の解析をスキップしました: {e}')
                        cursor += len(entries)
                        cursors[url] = cursor
                        received += len(entries)
                except Exception as e:
                    logger.warning(f'CTログ取得エラー ({url}): {e}')
            if received:
                logger.info(f'📥 CT証明書を {received:,} 件受信しました')
            self._stop_event.wait(CT_POLL_INTERVAL_SEC)

    def _load_log_urls(self) -> list[str]:
        response = self._session.get(CHROME_LOG_LIST_URL, timeout=CT_REQUEST_TIMEOUT_SEC)
        response.raise_for_status()
        now = datetime.datetime.now(datetime.timezone.utc)
        urls: list[str] = []
        for operator in response.json().get('operators', []):
            for log_info in operator.get('logs', []):
                interval = log_info.get('temporal_interval', {})
                try:
                    start = datetime.datetime.fromisoformat(interval['start_inclusive'].replace('Z', '+00:00'))
                    end = datetime.datetime.fromisoformat(interval['end_exclusive'].replace('Z', '+00:00'))
                except (KeyError, ValueError):
                    continue
                state = log_info.get('state', {})
                if start <= now < end and ('usable' in state or 'qualified' in state):
                    urls.append(log_info['url'])
        if not urls:
            raise RuntimeError('現在利用可能なCTログがありません')
        return urls

    def _get_tree_size(self, log_url: str) -> int:
        response = requests.get(
            f'{log_url}ct/v1/get-sth', timeout=CT_REQUEST_TIMEOUT_SEC
        )
        response.raise_for_status()
        return int(response.json()['tree_size'])

    def _fetch_entries(self, log_url: str, start: int, end: int) -> list[dict]:
        response = self._session.get(
            f'{log_url}ct/v1/get-entries',
            params={'start': start, 'end': end},
            timeout=CT_REQUEST_TIMEOUT_SEC,
        )
        response.raise_for_status()
        return response.json().get('entries', [])

    @staticmethod
    def _domains_from_entry(entry: dict) -> list[str]:
        leaf_input = base64.b64decode(entry['leaf_input'])
        entry_type = int.from_bytes(leaf_input[10:12], 'big')
        if entry_type == 0:
            certificate_data = leaf_input
            length_offset = 12
        elif entry_type == 1:
            certificate_data = base64.b64decode(entry['extra_data'])
            length_offset = 0
        else:
            return []
        cert_length = int.from_bytes(
            certificate_data[length_offset:length_offset + 3], 'big'
        )
        cert_start = length_offset + 3
        certificate = x509.load_der_x509_certificate(
            certificate_data[cert_start:cert_start + cert_length]
        )
        try:
            extension = certificate.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )
            return extension.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            return []

    def _process_domains(self, domains: list[str]) -> None:
        self._processed_count += len(domains)
        for raw_domain in domains:
            domain = raw_domain.removeprefix('*.').lower().rstrip('.')
            score, brand, reason, candidate_kind = classify_domain_candidate(domain)
            if score >= (5 if brand else 6):
                self._enqueue_candidate(
                    domain=domain,
                    url=f'https://{domain}',
                    brand=brand,
                    score=score,
                    reason=reason,
                    source='CT',
                    candidate_kind=candidate_kind,
                )

    def _load_openphish_candidates(self) -> None:
        try:
            response = self._session.get(OPENPHISH_FEED_URL, timeout=CT_REQUEST_TIMEOUT_SEC)
            response.raise_for_status()
            added = 0
            for url in response.text.splitlines():
                parsed = urlparse(url.strip())
                domain = (parsed.hostname or '').lower().rstrip('.')
                score, brand, reason, candidate_kind = classify_domain_candidate(domain)
                # The feed is global. Generic entries would consume the scan
                # budget without providing a brand-mismatch verification path.
                if not brand:
                    continue
                if self._enqueue_candidate(
                    domain=domain,
                    url=url.strip(),
                    brand=brand,
                    score=max(score + 5, 9),
                    reason=f'OpenPhish登録済み; {reason}',
                    source='OpenPhish',
                    known_phishing=True,
                    candidate_kind=candidate_kind,
                ):
                    added += 1
            logger.info(f'🛡️ OpenPhishから日本ブランド候補を {added} 件追加しました')
        except requests.exceptions.RequestException as e:
            logger.warning(f'OpenPhishフィード取得エラー: {e}')

    def _enqueue_candidate(
        self,
        domain: str,
        url: str,
        brand: str,
        score: int,
        reason: str,
        source: str,
        known_phishing: bool = False,
        candidate_kind: str = 'brand_impersonation',
    ) -> bool:
        if not domain or domain in self._seen_domains:
            return False
        if len(self._seen_domain_order) == self._seen_domain_order.maxlen:
            self._seen_domains.discard(self._seen_domain_order[0])
        self._seen_domain_order.append(domain)
        self._seen_domains.add(domain)
        group = f'brand:{brand}' if brand else f'kind:{candidate_kind}'
        now = time.monotonic()
        while self._candidate_group_history and now - self._candidate_group_history[0][0] >= DIVERSITY_WINDOW_SEC:
            _, expired_group = self._candidate_group_history.popleft()
            self._candidate_group_counts[expired_group] -= 1
            if self._candidate_group_counts[expired_group] <= 0:
                del self._candidate_group_counts[expired_group]
        if self._candidate_group_counts[group] >= MAX_CANDIDATES_PER_GROUP:
            logger.debug(f'候補の偏りを抑制しました: {domain} ({group})')
            return False
        self._candidate_group_history.append((now, group))
        self._candidate_group_counts[group] += 1
        self._accepted_count += 1
        if self._queue.full():
            try:
                self._queue.get_nowait()
            except queue.Empty:
                pass
        self._queue.put({
            'domain': domain,
            'url': url,
            'brand': brand,
            'score': score,
            'reason': reason,
            'source': source,
            'known_phishing': known_phishing,
            'candidate_kind': candidate_kind,
            'detected_at': time.strftime('%Y-%m-%d %H:%M:%S'),
        })
        logger.info(f'🚨 高信頼候補: {domain} ({reason}; source={source})')
        return True
