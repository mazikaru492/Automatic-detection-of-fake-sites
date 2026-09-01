import sys
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))

from analyzer import ScamAnalyzer
from scanner import UrlScanner


class UrlscanUsageTests(unittest.TestCase):
    def test_rate_limit_headers_are_exposed_for_the_gui(self):
        scanner = UrlScanner('test-key')
        response = SimpleNamespace(headers={
            'X-Rate-Limit-Action': 'public',
            'X-Rate-Limit-Window': 'minute',
            'X-Rate-Limit-Limit': '30',
            'X-Rate-Limit-Remaining': '24',
            'X-Rate-Limit-Reset': '2026-09-01T12:01:00.000Z',
            'X-Rate-Limit-Reset-After': '17',
        })

        scanner._capture_rate_limit(response)
        status = scanner.rate_limit_status

        self.assertEqual(status['limit'], 30)
        self.assertEqual(status['remaining'], 24)
        self.assertEqual(status['window'], 'minute')
        self.assertGreaterEqual(status['reset_after'], 15)
        self.assertLessEqual(status['reset_after'], 17)

    def test_cooldown_is_reported_as_remaining_seconds(self):
        scanner = UrlScanner('test-key')
        scanner._cooldown_until = time.time() + 5
        self.assertGreaterEqual(scanner.rate_limit_status['cooldown_seconds'], 3)


class GeminiUsageTests(unittest.TestCase):
    def test_response_usage_metadata_is_accumulated(self):
        analyzer = object.__new__(ScamAnalyzer)
        analyzer._request_count = 0
        analyzer._prompt_token_count = 0
        analyzer._output_token_count = 0
        analyzer._total_token_count = 0
        analyzer._current_model = 'gemini-test'
        analyzer._cooldown_until = 0.0
        analyzer._status_callback = None
        response = SimpleNamespace(usage_metadata=SimpleNamespace(
            prompt_token_count=120,
            candidates_token_count=30,
            total_token_count=150,
        ))

        analyzer._record_usage(response, 'gemini-test')
        status = analyzer.usage_status

        self.assertEqual(status['requests'], 1)
        self.assertEqual(status['prompt_tokens'], 120)
        self.assertEqual(status['output_tokens'], 30)
        self.assertEqual(status['total_tokens'], 150)
        self.assertEqual(status['model'], 'gemini-test')


if __name__ == '__main__':
    unittest.main()
