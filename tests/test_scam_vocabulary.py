import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))

from scam_vocabulary import assess_scam_vocabulary, load_vocabulary
from scanner import detect_page_signals
from verification import should_analyze


class ScamVocabularyTests(unittest.TestCase):
    def test_bundled_dataset_is_loaded_without_instruction_fields(self):
        entries = load_vocabulary()
        self.assertGreaterEqual(len(entries), 190)
        self.assertTrue(all(not hasattr(entry, 'context_for_ai') for entry in entries))

    def test_independent_strong_categories_create_high_risk_score(self):
        assessment = assess_scam_vocabulary(
            'スーパーコピー商品を90%OFFで販売。お支払いは個人口座のみです。'
        )
        self.assertEqual(assessment.tier, 'high')
        self.assertGreaterEqual(assessment.score, 70)
        self.assertIn('counterfeit', assessment.categories)
        self.assertIn('payment_anomaly', assessment.categories)

    def test_common_shop_phrases_stay_low_risk(self):
        assessment = assess_scam_vocabulary(
            '正規代理店による期間限定キャンペーン。並行輸入品も返品可能です。'
        )
        self.assertEqual(assessment.tier, 'low')
        self.assertLess(assessment.score, 45)

    def test_descriptive_non_literal_entry_is_not_matched(self):
        assessment = assess_scam_vocabulary('住所が空き地という注意喚起の記事です。')
        self.assertNotIn('住所が空き地', assessment.matches['operator_anomaly'])

    def test_page_signals_include_dataset_categories(self):
        signals = detect_page_signals('商品を購入できます。個人口座へ送金。こんにちは友人。')
        self.assertIn('個人口座', signals['payment_anomaly'])
        self.assertIn('こんにちは友人', signals['language_anomaly'])

    def test_precheck_accepts_transaction_with_two_weighted_categories(self):
        text = 'カートに追加して購入。個人口座へ送金。こんにちは友人。'
        assessment = assess_scam_vocabulary(text)
        scan = {
            'page_signals': detect_page_signals(text),
            'vocabulary_score': assessment.score,
            'vocabulary_categories': list(assessment.categories),
        }
        result = should_analyze({'candidate_kind': 'suspicious_shop'}, scan)
        self.assertTrue(result.proceed)


if __name__ == '__main__':
    unittest.main()
