import base64
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))

from supabase_repository import (
    SupabaseConfigurationError,
    SupabaseRepository,
    _validate_project_url,
)


class FakeResponse:
    def __init__(self, status_code=200, data=None):
        self.status_code = status_code
        self._data = data
        self.content = b'{}' if data is not None else b''
        self.headers = {}

    def json(self):
        return self._data


class FakeSession:
    def __init__(self):
        self.calls = []
        self.responses = [
            FakeResponse(data={'access_token': 'user-token', 'expires_in': 3600}),
            FakeResponse(data=True),
            FakeResponse(data='11111111-1111-1111-1111-111111111111'),
        ]

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.responses.pop(0)

    def close(self):
        pass


def jwt_with_role(role):
    payload = base64.urlsafe_b64encode(json.dumps({'role': role}).encode()).decode().rstrip('=')
    return f'header.{payload}.signature'


class SupabaseRepositoryTests(unittest.TestCase):
    def test_authentication_error_is_safely_classified(self):
        session = FakeSession()
        session.responses = [FakeResponse(400, {
            'error_code': 'invalid_credentials',
            'msg': 'Invalid login credentials',
        })]
        repository = SupabaseRepository(
            'https://demo.supabase.co', 'public-anon-key',
            'operator@example.com', 'do-not-echo-this-password', session=session,
        )
        from supabase_repository import SupabaseConnectionError
        with self.assertRaisesRegex(SupabaseConnectionError, 'メールアドレスまたはパスワード') as caught:
            repository.connect()
        self.assertNotIn('do-not-echo', str(caught.exception))

    def test_authenticated_but_unapproved_user_is_rejected(self):
        session = FakeSession()
        session.responses = [
            FakeResponse(data={'access_token': 'user-token', 'expires_in': 3600}),
            FakeResponse(data=False),
        ]
        repository = SupabaseRepository(
            'https://demo.supabase.co', 'public-anon-key',
            'unapproved@example.com', 'password', session=session,
        )
        from supabase_repository import SupabaseConnectionError
        with self.assertRaisesRegex(SupabaseConnectionError, '許可一覧'):
            repository.connect()

    def test_rejects_non_supabase_and_insecure_urls(self):
        for url in ('http://demo.supabase.co', 'https://127.0.0.1', 'https://example.com/path'):
            with self.subTest(url=url), self.assertRaises(SupabaseConfigurationError):
                _validate_project_url(url)

    def test_rejects_service_role_key(self):
        with self.assertRaises(SupabaseConfigurationError):
            SupabaseRepository(
                'https://demo.supabase.co', jwt_with_role('service_role'),
                'operator@example.com', 'password',
            )

    def test_rejects_candidate_url_credentials(self):
        session = FakeSession()
        repository = SupabaseRepository(
            'https://demo.supabase.co', 'public-anon-key',
            'operator@example.com', 'password', session=session,
        )
        repository.connect()
        with self.assertRaises(ValueError):
            repository.claim_candidate({
                'domain': 'example.test',
                'url': 'https://user:secret@example.test/login',
                'source': 'test', 'candidate_kind': 'test',
            })

    def test_authenticates_and_claims_without_persisting_query(self):
        session = FakeSession()
        repository = SupabaseRepository(
            'https://demo.supabase.co', 'public-anon-key',
            'operator@example.com', 'password', session=session,
        )
        repository.connect()
        claim = repository.claim_candidate({
            'domain': 'login-example.test',
            'url': 'https://login-example.test/account?token=secret',
            'source': 'test', 'candidate_kind': 'brand_impersonation',
            'brand': 'Example', 'score': 9, 'reason': 'test',
        })

        self.assertIsNotNone(claim)
        rpc_payload = session.calls[-1][1]['json']
        self.assertEqual(rpc_payload['p_safe_url'], 'https://login-example.test/')
        self.assertNotIn('secret', json.dumps(rpc_payload))

        session.responses.append(FakeResponse(data=True))
        repository.record_scan(claim.candidate_id, {
            'scan_url': 'https://urlscan.io/result/example/',
            'dom_text': 'do-not-persist-this-secret',
            'page_signals': {'credential': ['パスワード']},
        })
        evidence_payload = session.calls[-1][1]['json']
        self.assertNotIn('do-not-persist', json.dumps(evidence_payload))

    def test_human_review_uses_versioned_narrow_rpc(self):
        session = FakeSession()
        session.responses = [
            FakeResponse(data={'access_token': 'user-token', 'expires_in': 3600}),
            FakeResponse(data=True),
            FakeResponse(data=1),
        ]
        repository = SupabaseRepository(
            'https://demo.supabase.co', 'public-anon-key',
            'operator@example.com', 'password', session=session,
        )
        repository.connect()
        version = repository.submit_review(
            '11111111-1111-1111-1111-111111111111',
            'strong_suspicion', '画面と登録情報を人手確認',
            evidence_refs=['https://urlscan.io/result/example/'],
            expected_version=0,
        )
        self.assertEqual(version, 1)
        url, kwargs = session.calls[-1]
        self.assertTrue(url.endswith('/rpc/submit_candidate_review'))
        self.assertEqual(kwargs['json']['p_expected_version'], 0)

    def test_migration_enforces_rls_and_narrow_rpc_access(self):
        migration = (
            Path(__file__).resolve().parents[1]
            / 'supabase' / 'migrations' / '202609020001_detection_schema.sql'
        ).read_text(encoding='utf-8').lower()
        self.assertIn('force row level security', migration)
        self.assertIn('revoke all on public.detection_candidates from anon, authenticated', migration)
        self.assertNotIn('grant select on public.detection_candidates', migration)
        self.assertIn('private.claim_candidate', migration)
        self.assertIn('security definer', migration)
        self.assertIn('security invoker', migration)
        self.assertIn("set search_path = ''", migration)
        history_migration = (
            Path(__file__).resolve().parents[1]
            / 'supabase' / 'migrations' / '202609030001_spec_v11_history.sql'
        ).read_text(encoding='utf-8').lower()
        self.assertIn('create table if not exists public.candidate_observations', history_migration)
        self.assertIn('create table if not exists public.candidate_reviews', history_migration)
        self.assertIn('p_expected_version', history_migration)
        self.assertIn('force row level security', history_migration)

        learning_migration = (
            Path(__file__).resolve().parents[1]
            / 'supabase' / 'migrations' / '202609030002_online_learning.sql'
        ).read_text(encoding='utf-8').lower()
        self.assertIn('force row level security', learning_migration)
        self.assertIn('human-review-derived labels only', learning_migration)
        self.assertIn("v_status = 'no_issue'", learning_migration)
        self.assertIn("v_status in ('strong_suspicion'", learning_migration)
        self.assertIn('distinct on (candidate_id)', learning_migration)
        self.assertIn('rollback_learning_model', learning_migration)

        shared_migration = (
            Path(__file__).resolve().parents[1]
            / 'supabase' / 'migrations' / '202609060001_shared_trusted_learning.sql'
        ).read_text(encoding='utf-8').lower()
        self.assertIn('private.trusted_app_users', shared_migration)
        self.assertIn('private.require_trusted_user()', shared_migration)
        self.assertIn('detection_candidates_shared_domain_hash_idx', shared_migration)
        self.assertIn("where domain_hash = p_domain_hash", shared_migration)
        self.assertNotIn(
            'where owner_id = v_actor and domain_hash = p_domain_hash',
            shared_migration,
        )
        self.assertIn('learning_models_one_active_shared_idx', shared_migration)
        self.assertIn('p_expected_parent_version', shared_migration)
        self.assertIn("where status = 'active'", shared_migration)

    def test_learning_operations_use_narrow_rpcs(self):
        session = FakeSession()
        session.responses = [
            FakeResponse(data={'access_token': 'user-token', 'expires_in': 3600}),
            FakeResponse(data=True),
            FakeResponse(data=True),
            FakeResponse(data=[{'label': True, 'features': {}}]),
            FakeResponse(data={'schema_version': 'review-logistic-v1'}),
            FakeResponse(data='model-v1'),
        ]
        repository = SupabaseRepository(
            'https://demo.supabase.co', 'public-anon-key',
            'operator@example.com', 'password', session=session,
        )
        repository.connect()
        self.assertTrue(repository.record_learning_example(
            '11111111-1111-1111-1111-111111111111',
            1,
            'phishing',
            {'rule_score': 1.0},
        ))
        self.assertEqual(len(repository.get_learning_examples(500)), 1)
        self.assertIsNotNone(repository.get_active_learning_model())
        self.assertEqual(repository.publish_learning_model(
            {'model_version': 'model-v1'}, {'precision': 1.0},
            expected_parent_version='model-v0',
        ), 'model-v1')
        self.assertEqual(
            session.calls[-1][1]['json']['p_expected_parent_version'],
            'model-v0',
        )
        rpc_names = [call[0].rsplit('/', 1)[-1] for call in session.calls[2:]]
        self.assertEqual(rpc_names, [
            'record_learning_example',
            'get_learning_examples',
            'get_active_learning_model',
            'publish_learning_model',
        ])

    def test_invalid_learning_example_is_rejected_before_network_call(self):
        repository = SupabaseRepository(
            'https://demo.supabase.co', 'public-anon-key',
            'operator@example.com', 'password', session=FakeSession(),
        )
        with self.assertRaises(ValueError):
            repository.record_learning_example('candidate', 0, 'phishing', {})


if __name__ == '__main__':
    unittest.main()
