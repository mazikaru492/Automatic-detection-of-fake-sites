import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))

from monitor import evaluate_domain
from analyzer import ScamAnalyzer
from scanner import UrlScanner
from verification import decide_report


def confirmed_analysis(**overrides):
    values = {
        'verdict': 'confirmed_scam',
        'confidence': 96,
        'target_brand': 'PayPay',
        'brand_domain_mismatch': True,
        'credential_or_payment_request': True,
        'deceptive_commerce': False,
        'impersonation_evidence': 'PayPayのロゴとログイン画面を表示',
        'features': '認証情報の入力を要求',
    }
    values.update(overrides)
    return SimpleNamespace(**values)


class DomainCandidateTests(unittest.TestCase):
    def test_generic_wildcard_is_not_dcard(self):
        self.assertEqual(evaluate_domain('wildcard.plantologyaromatherapy.com')[0], 0)

    def test_generic_card_label_is_not_dcard(self):
        self.assertEqual(evaluate_domain('crear-mi-solicitud-card-production.up.railway.app')[0], 0)

    def test_official_domain_is_excluded(self):
        self.assertEqual(evaluate_domain('login.paypay.ne.jp')[0], 0)
        self.assertEqual(evaluate_domain('www.paypay-card.co.jp')[0], 0)
        self.assertEqual(evaluate_domain('login.paypay-bank.co.jp')[0], 0)

    def test_brand_prefix_remains_candidate(self):
        score, brand, _ = evaluate_domain('paypayvejp781.replit.app')
        self.assertGreaterEqual(score, 4)
        self.assertEqual(brand, 'PayPay')


class ReportGateTests(unittest.TestCase):
    def setUp(self):
        self.domain = {
            'domain': 'paypayvejp781.replit.app',
            'brand': 'PayPay',
            'known_phishing': True,
        }
        self.scan = {
            'page_domain': 'paypayvejp781.replit.app',
            'urlscan_malicious': False,
            'urlscan_score': 6,
            'urlscan_categories': [],
        }

    def test_feed_plus_strong_ai_can_be_reported(self):
        decision = decide_report(self.domain, self.scan, confirmed_analysis())
        self.assertTrue(decision.confirmed)
        self.assertEqual(decision.report_category, 'フィッシングサイト')

    def test_feed_alone_is_never_reported(self):
        decision = decide_report(self.domain, self.scan, confirmed_analysis(verdict='suspicious'))
        self.assertFalse(decision.confirmed)

    def test_low_confidence_ai_is_not_reported(self):
        decision = decide_report(self.domain, self.scan, confirmed_analysis(confidence=89))
        self.assertFalse(decision.confirmed)

    def test_brand_disagreement_is_not_reported(self):
        decision = decide_report(self.domain, self.scan, confirmed_analysis(target_brand='PayPal'))
        self.assertFalse(decision.confirmed)

    def test_official_redirect_is_not_reported(self):
        scan = {**self.scan, 'page_apex_domain': 'paypay.ne.jp'}
        decision = decide_report(self.domain, scan, confirmed_analysis())
        self.assertFalse(decision.confirmed)

    def test_urlscan_requires_high_score_and_category(self):
        domain = {**self.domain, 'known_phishing': False}
        weak = decide_report(domain, self.scan, confirmed_analysis())
        self.assertFalse(weak.confirmed)
        strong_scan = {
            **self.scan,
            'urlscan_malicious': True,
            'urlscan_score': 92,
            'urlscan_categories': ['phishing'],
        }
        strong = decide_report(domain, strong_scan, confirmed_analysis())
        self.assertTrue(strong.confirmed)

    def test_new_phishing_can_use_strong_domain_and_credential_page_evidence(self):
        domain = {
            **self.domain,
            'known_phishing': False,
            'candidate_kind': 'brand_impersonation',
            'score': 9,
        }
        scan = {
            **self.scan,
            'page_signals': {'credential': ['ログイン', 'パスワード']},
        }

        decision = decide_report(domain, scan, confirmed_analysis())

        self.assertTrue(decision.confirmed)
        self.assertIn('認証入力画面', decision.evidence_summary)


class EvidenceParsingTests(unittest.TestCase):
    def test_schema_defaults_missing_values_to_suspicious(self):
        result = ScamAnalyzer._result_from_dict({'target_brand': 'PayPay'})
        self.assertEqual(result.verdict, 'suspicious')
        self.assertFalse(result.is_scam)

    def test_deprecated_engine_verdict_does_not_confirm(self):
        scanner = object.__new__(UrlScanner)
        scanner._fetch_dom_text = lambda _uuid: ''
        result = scanner._extract_evidence('test-id', {
            'page': {'domain': 'example.test'},
            'task': {},
            'lists': {},
            'verdicts': {
                'urlscan': {'malicious': False, 'score': 6, 'categories': []},
                'engines': {'malicious': True, 'score': 100},
            },
        })
        self.assertFalse(result['urlscan_malicious'])
        self.assertEqual(result['urlscan_score'], 6)


if __name__ == '__main__':
    unittest.main()
