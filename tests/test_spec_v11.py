import os
import sys
import unittest
import tempfile
import json
import hashlib
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))

from app_config import DEFAULT_FEATURES, load_feature_flags
from risk_scoring import assess_risk, classify_priority
from scanner import UrlScanner
from url_normalization import normalize_url
from verification import should_analyze
from domain_metadata import DomainMetadataResolver


class SafeDefaultTests(unittest.TestCase):
    def test_external_submission_and_optional_features_default_off(self):
        with patch.dict(os.environ, {}, clear=True):
            flags = load_feature_flags()
        self.assertFalse(flags.urlscan_submission_enabled)
        self.assertFalse(flags.ct_enabled)
        self.assertFalse(flags.llm_enabled)
        self.assertFalse(flags.automatic_reporting_enabled)
        self.assertTrue(flags.automatic_learning_enabled)
        self.assertEqual(flags, DEFAULT_FEATURES)

    def test_no_existing_scan_does_not_submit_by_default(self):
        scanner = UrlScanner('test-key')
        scanner._find_recent_scan = lambda _url: None
        scanner._submit_scan = lambda _url: self.fail('must not submit')
        result = scanner.scan('https://example.test/login?token=secret')
        self.assertEqual(result['fetch_status'], 'not_observed')
        self.assertEqual(result['missing_reason'], 'urlscan_submission_disabled')
        precheck = should_analyze({'known_phishing': True}, result)
        self.assertFalse(precheck.proceed)


class RiskScoringTests(unittest.TestCase):
    def test_priority_boundaries(self):
        expected = {
            29: 'normal', 30: 'review', 59: 'review', 60: 'high',
            79: 'high', 80: 'urgent',
        }
        for score, priority in expected.items():
            with self.subTest(score=score):
                self.assertEqual(classify_priority(score)[0], priority)

    def test_rule_points_and_missing_evidence_are_separate(self):
        assessment = assess_risk({
            'known_phishing': True,
            'candidate_kind': 'brand_impersonation',
            'brand': 'Example',
            'score': 7,
        }, {
            'scan_url': 'https://urlscan.io/result/id/',
            'page_signals': {'credential': ['password']},
        })
        self.assertEqual(assessment.score, 65)
        self.assertEqual(assessment.priority, 'high')
        self.assertIn('R-FEED', assessment.applied_rules)
        self.assertIn('R-IMPERSONATION', assessment.applied_rules)
        self.assertEqual(assessment.completeness, 'partial')

    def test_low_score_is_not_labeled_safe(self):
        assessment = assess_risk({
            'candidate_kind': 'suspicious_shop',
            'score': 5,
        }, {'fetch_status': 'not_observed'})
        self.assertEqual(assessment.priority, 'normal')
        self.assertEqual(assessment.completeness, 'insufficient')
        self.assertNotIn('safe', assessment.as_dict().values())


class UrlNormalizationTests(unittest.TestCase):
    def test_only_allowed_components_are_normalized(self):
        normalized = normalize_url(
            'HTTPS://例え.テスト:443/Case/Path?b=2&a=1#screen'
        )
        self.assertEqual(
            normalized.search_key,
            'https://xn--r8jz45g.xn--zckzah/Case/Path?b=2&a=1',
        )
        self.assertEqual(
            normalized.original,
            'HTTPS://例え.テスト:443/Case/Path?b=2&a=1#screen',
        )

    def test_path_case_and_query_order_remain_distinct(self):
        one = normalize_url('https://example.test/A?a=1&b=2').search_key
        two = normalize_url('https://example.test/a?b=2&a=1').search_key
        self.assertNotEqual(one, two)


class DomainMetadataTests(unittest.TestCase):
    def test_registration_date_is_parsed_from_rdap_events(self):
        value = DomainMetadataResolver._registration_date({
            'events': [
                {'eventAction': 'last changed', 'eventDate': '2026-01-02T00:00:00Z'},
                {'eventAction': 'registration', 'eventDate': '2025-12-01T12:30:00Z'},
            ]
        })
        self.assertEqual(value.isoformat(), '2025-12-01T12:30:00+00:00')


class CsvSafetyTests(unittest.TestCase):
    def test_formula_prefix_is_neutralized(self):
        try:
            from gui import MainWindow
        except ImportError:
            self.skipTest('PyQt6 is unavailable')
        self.assertEqual(MainWindow._neutralize_csv_formula('=cmd()'), "'=cmd()")
        self.assertEqual(MainWindow._neutralize_csv_formula('example.test'), 'example.test')

    def test_evidence_manifest_contains_file_hash(self):
        try:
            from gui import MainWindow
        except ImportError:
            self.skipTest('PyQt6 is unavailable')
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'evidence.csv'
            output.write_bytes(b'evidence')
            manifest_path = MainWindow._write_evidence_manifest(output, [])
            manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
            self.assertEqual(
                manifest['file']['sha256'], hashlib.sha256(b'evidence').hexdigest()
            )


if __name__ == '__main__':
    unittest.main()
