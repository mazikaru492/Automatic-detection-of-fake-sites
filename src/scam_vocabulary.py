"""Validated, weighted matching for the user-provided Japanese scam vocabulary."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import json
import logging
from pathlib import Path
import unicodedata

logger = logging.getLogger(__name__)

DATASET_PATH = Path(__file__).resolve().parents[1] / 'data' / 'scam_words_dataset_expanded.json'
ALLOWED_CATEGORIES = frozenset({
    'counterfeit', 'payment_anomaly', 'price_anomaly',
    'urgency', 'operator_anomaly', 'language_anomaly',
})

# These entries describe conclusions or visual/structural checks. Treating them as
# literal words would create false positives and would not prove the stated fact.
NON_LITERAL_KEYWORDS = frozenset({
    '〇〇風', '〇〇調', '特商法ページが画像', '返品ポリシーなし',
    '住所が架空', '住所が空き地', '代表者名がアルファベット',
    '国際電話番号', '会社概要なし', '運営会社不明', '代表者名なし',
    '不自然なフォント', '繁体字', '簡体字', '直訳日本語', '入金期限が短い',
})

# Legitimate Japanese shops commonly use these expressions. They remain weak
# supporting evidence but can never become a strong signal by themselves.
AMBIGUOUS_KEYWORDS = frozenset({
    '正規代理店', '並行輸入', '互換品', '代替品', 'カスタム品',
    'ノベルティ（非売品）', 'サンプル品', 'B級アウトレット', '工場直販',
    'ロゴなし', '090-', '080-', '@gmail.com', '@yahoo.co.jp',
    '休業日:年中無休', '営業時間:24時間', 'キャンセル不可', '返品不可',
    '返金不可', '振込手数料はお客様負担', '入金確認後発送', '暗号資産決済',
    '指定銀行', '最安値保証', '期間限定', '数量限定', '今だけ',
    '会員限定セール', 'キャンペーン価格', '限定販売',
})

CATEGORY_WEIGHTS = {
    'counterfeit': 55,
    'payment_anomaly': 35,
    'operator_anomaly': 25,
    'language_anomaly': 20,
    'price_anomaly': 15,
    'urgency': 10,
}


@dataclass(frozen=True)
class VocabularyEntry:
    keyword: str
    normalized_keyword: str
    category: str
    risk_score: float


@dataclass(frozen=True)
class VocabularyAssessment:
    score: int
    tier: str
    matches: dict[str, list[str]]

    @property
    def categories(self) -> tuple[str, ...]:
        return tuple(category for category, words in self.matches.items() if words)

    @property
    def evidence(self) -> tuple[str, ...]:
        return tuple(
            f"{category}={','.join(words[:3])}"
            for category, words in self.matches.items() if words
        )


def _normalize(value: str) -> str:
    return unicodedata.normalize('NFKC', value).casefold()


@lru_cache(maxsize=1)
def load_vocabulary() -> tuple[VocabularyEntry, ...]:
    """Load only bounded classification fields; context_for_ai is never executed."""
    try:
        if DATASET_PATH.stat().st_size > 1_000_000:
            raise ValueError('dataset exceeds 1 MB')
        raw = json.loads(DATASET_PATH.read_text(encoding='utf-8'))
        if not isinstance(raw, list):
            raise ValueError('dataset root must be an array')
        entries: list[VocabularyEntry] = []
        seen: set[tuple[str, str]] = set()
        for item in raw:
            if not isinstance(item, dict):
                continue
            keyword = str(item.get('keyword', '')).strip()
            category = str(item.get('category', '')).strip()
            if (
                not keyword or len(keyword) > 80 or category not in ALLOWED_CATEGORIES
                or keyword in NON_LITERAL_KEYWORDS
            ):
                continue
            try:
                score = float(item.get('risk_score', 0))
            except (TypeError, ValueError):
                continue
            if not 0 <= score <= 1:
                continue
            key = (_normalize(keyword), category)
            if key in seen:
                continue
            seen.add(key)
            entries.append(VocabularyEntry(keyword, key[0], category, score))
        return tuple(entries)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        logger.error('詐欺語彙データを安全に読み込めませんでした: %s', exc)
        return ()


def assess_scam_vocabulary(text: str) -> VocabularyAssessment:
    normalized_text = _normalize(text or '')
    matches: dict[str, list[str]] = {category: [] for category in ALLOWED_CATEGORIES}
    category_strength: dict[str, float] = {}
    for entry in load_vocabulary():
        if entry.normalized_keyword not in normalized_text:
            continue
        matches[entry.category].append(entry.keyword)
        effective_score = min(entry.risk_score, 0.2) if entry.keyword in AMBIGUOUS_KEYWORDS else entry.risk_score
        category_strength[entry.category] = max(
            category_strength.get(entry.category, 0.0), effective_score,
        )

    # Count only the strongest match per category so repeated sales copy cannot
    # inflate a score. Independent categories provide the corroboration.
    score = min(100, round(sum(
        CATEGORY_WEIGHTS[category] * strength
        for category, strength in category_strength.items()
    )))
    tier = 'high' if score >= 70 else 'review' if score >= 45 else 'low'
    return VocabularyAssessment(score=score, tier=tier, matches=matches)
