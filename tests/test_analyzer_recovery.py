import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))

from analyzer import AnalysisResponseError, ScamAnalyzer


def complete_payload() -> dict:
    return {
        'verdict': 'reportable',
        'site_category': 'phishing',
        'confidence': 95,
        'target_brand': 'LINE',
        'brand_domain_mismatch': True,
        'credential_or_payment_request': True,
        'transaction_evidence': False,
        'deceptive_commerce': False,
        'red_flag_count': 0,
        'red_flags': '',
        'impersonation_evidence': 'LINEのログイン画面',
        'counterfeit_evidence': '',
        'illegal_goods_evidence': '',
        'features': '認証情報を要求',
    }


class AnalyzerRecoveryTests(unittest.TestCase):
    def test_repairs_single_quoted_keys_and_values(self):
        raw = json.dumps(complete_payload(), ensure_ascii=False)
        raw = raw.replace('"verdict"', "'verdict'").replace('"reportable"', "'reportable'")

        result = ScamAnalyzer._parse_response(object.__new__(ScamAnalyzer), raw)

        self.assertIsNotNone(result)
        self.assertEqual(result.verdict, 'reportable')
        self.assertEqual(result.target_brand, 'LINE')

    def test_truncated_json_is_not_accepted_as_evidence(self):
        raw = '{"verdict":"reportable","site_category":"phishing","confidence":95'

        result = ScamAnalyzer._parse_response(object.__new__(ScamAnalyzer), raw)

        self.assertIsNone(result)

    @patch('analyzer.time.sleep', return_value=None)
    def test_invalid_output_switches_model_and_recovers(self, _sleep):
        analyzer = object.__new__(ScamAnalyzer)
        analyzer._models = ('model-a', 'model-b', 'model-c')
        analyzer._parse_retry_count = 0
        analyzer._status_callback = None
        calls = []

        def call(*_args, model=None, **_kwargs):
            calls.append(model)
            if len(calls) == 1:
                raise AnalysisResponseError('JSONが途中で切れています')
            return ScamAnalyzer._result_from_dict(complete_payload())

        analyzer._call_gemini = call
        result = analyzer.analyze('', '', max_retries=3)

        self.assertEqual(calls, ['model-a', 'model-b'])
        self.assertEqual(result.verdict, 'reportable')
        self.assertEqual(analyzer._parse_retry_count, 1)

    @patch('analyzer.time.sleep', return_value=None)
    def test_all_invalid_outputs_fall_back_to_safe_hold(self, _sleep):
        analyzer = object.__new__(ScamAnalyzer)
        analyzer._models = ('model-a', 'model-b', 'model-c')
        analyzer._parse_retry_count = 0
        analyzer._status_callback = None
        analyzer._call_gemini = lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AnalysisResponseError('形式不正')
        )

        result = analyzer.analyze('', '', max_retries=3)

        self.assertEqual(result.verdict, 'suspicious')
        self.assertEqual(result.confidence, 0)
        self.assertFalse(result.is_scam)
        self.assertEqual(analyzer._parse_retry_count, 3)


if __name__ == '__main__':
    unittest.main()
