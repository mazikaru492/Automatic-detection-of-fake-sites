import json
import queue
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))

from monitor import DomainMonitor
from url_audit_log import UrlAuditLog


def read_entries(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding='utf-8').splitlines()
        if line.strip()
    ]


class UrlAuditLogTests(unittest.TestCase):
    def test_two_logs_are_created_and_url_secrets_are_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            audit = UrlAuditLog(directory)
            self.assertTrue(audit.filter_passed_path.exists())
            self.assertTrue(audit.scanned_path.exists())

            secret_url = 'https://Example.test/login?token=secret#fragment'
            self.assertTrue(audit.record_filter_passed(
                secret_url,
                domain='example.test',
                source='test',
                candidate_kind='brand_impersonation',
                score=7,
            ))
            self.assertTrue(audit.record_scanned(
                secret_url,
                domain='example.test',
                source='test',
                candidate_kind='brand_impersonation',
            ))

            filter_text = audit.filter_passed_path.read_text(encoding='utf-8')
            scan_text = audit.scanned_path.read_text(encoding='utf-8')
            self.assertNotIn('secret', filter_text + scan_text)
            self.assertNotIn('fragment', filter_text + scan_text)
            self.assertEqual(read_entries(audit.filter_passed_path)[-1]['url'], 'https://example.test/login')
            self.assertEqual(read_entries(audit.scanned_path)[-1]['event'], 'scan_started')

    def test_parallel_writes_remain_valid_json_lines(self):
        with tempfile.TemporaryDirectory() as directory:
            audit = UrlAuditLog(directory)
            with ThreadPoolExecutor(max_workers=4) as executor:
                results = list(executor.map(
                    lambda index: audit.record_scanned(
                        f'https://item-{index}.example/path',
                        domain=f'item-{index}.example',
                        source='test',
                        candidate_kind='suspicious_shop',
                    ),
                    range(20),
                ))
            self.assertTrue(all(results))
            entries = read_entries(audit.scanned_path)
            self.assertEqual(sum(entry['event'] == 'scan_started' for entry in entries), 20)

    def test_monitor_records_only_accepted_filter_candidates(self):
        with tempfile.TemporaryDirectory() as directory:
            audit = UrlAuditLog(directory)
            monitor = DomainMonitor(queue.Queue(), audit_log=audit)
            accepted = monitor._enqueue_candidate(
                domain='paypal-login.example',
                url='https://paypal-login.example/account?token=hidden',
                brand='PayPal',
                score=7,
                reason='test',
                source='test',
                candidate_kind='brand_impersonation',
            )
            duplicate = monitor._enqueue_candidate(
                domain='paypal-login.example',
                url='https://paypal-login.example/duplicate',
                brand='PayPal',
                score=7,
                reason='test',
                source='test',
                candidate_kind='brand_impersonation',
            )
            entries = read_entries(audit.filter_passed_path)
            self.assertTrue(accepted)
            self.assertFalse(duplicate)
            self.assertEqual(sum(entry['event'] == 'filter_passed' for entry in entries), 1)
            self.assertNotIn('hidden', audit.filter_passed_path.read_text(encoding='utf-8'))


if __name__ == '__main__':
    unittest.main()
