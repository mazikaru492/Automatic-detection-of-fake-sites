import math
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))

from online_learning import (
    FEATURE_NAMES,
    LearningModel,
    build_feature_vector,
    sanitize_features,
    train_challenger,
)


def example(label: bool, category: str, strength: float) -> dict:
    features = {name: 0.0 for name in FEATURE_NAMES}
    features['rule_score'] = strength
    features['page_observed'] = 1.0
    if label:
        features['transaction_signal'] = 1.0
        features['fraud_signal'] = 1.0
        features['urlscan_malicious'] = 1.0
    return {'label': label, 'category': category, 'features': features}


class FeatureTests(unittest.TestCase):
    def test_feature_values_are_bounded_and_invalid_numbers_are_removed(self):
        clean = sanitize_features({
            'rule_score': 4,
            'urlscan_score': -2,
            'vocabulary_score': float('nan'),
            'llm_confidence': 'invalid',
            'unknown': 1,
        })
        self.assertEqual(tuple(clean), FEATURE_NAMES)
        self.assertEqual(clean['rule_score'], 1.0)
        self.assertEqual(clean['urlscan_score'], 0.0)
        self.assertEqual(clean['vocabulary_score'], 0.0)
        self.assertTrue(all(math.isfinite(value) for value in clean.values()))

    def test_feature_builder_uses_category_and_observed_content(self):
        features = build_feature_vector(
            {
                'candidate_kind': 'counterfeit_goods',
                'domain_age_days': 12,
                'dns_status': 'resolved',
            },
            {
                'fetch_status': 'observed',
                'page_signals': {'counterfeit': ['replica']},
                'vocabulary_score': 80,
            },
            SimpleNamespace(score=30),
        )
        self.assertEqual(features['kind_counterfeit'], 1.0)
        self.assertEqual(features['counterfeit_signal'], 1.0)
        self.assertEqual(features['page_observed'], 1.0)
        self.assertEqual(features['new_domain'], 1.0)


class ModelTests(unittest.TestCase):
    def test_model_round_trip_and_corrupt_payload_rejection(self):
        model = LearningModel(
            model_version='v1',
            weights=tuple(1.0 for _ in FEATURE_NAMES),
            bias=-1.0,
            trained_at='2026-09-03T00:00:00+00:00',
            training_examples=40,
            supported_categories=('phishing',),
        )
        restored = LearningModel.from_dict(model.as_dict())
        self.assertIsNotNone(restored)
        self.assertGreater(
            restored.predict({name: 1.0 for name in FEATURE_NAMES}),
            restored.predict({}),
        )
        self.assertIsNone(restored.predict_for_category('fraudulent_ec', {}))
        payload = model.as_dict()
        payload['weights'][0] = float('nan')
        self.assertIsNone(LearningModel.from_dict(payload))

    def test_training_waits_for_both_human_review_classes(self):
        samples = [example(True, 'phishing', 0.9) for _ in range(20)]
        result = train_challenger(samples, minimum_per_class=5)
        self.assertFalse(result.promoted)
        self.assertIsNone(result.model)
        self.assertEqual(result.metrics['negative'], 0)

    def test_model_is_not_deployed_across_categories_without_both_labels(self):
        samples = [example(True, 'phishing', 0.9) for _ in range(10)]
        samples.extend(example(False, 'fraudulent_ec', 0.1) for _ in range(10))
        result = train_challenger(samples, minimum_per_class=5)
        self.assertFalse(result.promoted)
        self.assertIsNone(result.model)
        self.assertIn('同じ分類', result.reason)

    def test_balanced_reviews_train_promote_and_avoid_model_churn(self):
        categories = ('phishing', 'fraudulent_ec', 'suspected_counterfeit')
        samples = []
        for category in categories:
            samples.extend(example(True, category, 0.9) for _ in range(10))
            samples.extend(example(False, category, 0.1) for _ in range(10))
        result = train_challenger(samples, minimum_per_class=5)
        self.assertTrue(result.promoted, result.reason)
        self.assertIsNotNone(result.model)
        self.assertGreaterEqual(result.metrics['challenger_precision'], 0.8)

        unchanged = train_challenger(
            samples,
            current_model=result.model,
            minimum_per_class=5,
        )
        self.assertFalse(unchanged.promoted)
        self.assertIn('追加', unchanged.reason)

    def test_string_false_label_is_not_silently_treated_as_positive(self):
        samples = [
            example(True, 'phishing', 0.9),
            {'label': 'false', 'category': 'phishing', 'features': {}},
        ]
        result = train_challenger(samples, minimum_per_class=1)
        self.assertEqual(result.metrics['samples'], 1)
        self.assertEqual(result.metrics['positive'], 1)


class GuiLearningIntegrationTests(unittest.TestCase):
    def test_confirmed_review_is_recorded_and_promoted_model_is_published(self):
        try:
            from gui import MainWindow
        except ImportError:
            self.skipTest('PyQt6 is unavailable')

        categories = ('phishing', 'fraudulent_ec', 'suspected_counterfeit')
        examples = []
        for category in categories:
            examples.extend(example(True, category, 0.9) for _ in range(10))
            examples.extend(example(False, category, 0.1) for _ in range(10))

        class Log:
            def __init__(self):
                self.entries = []

            def append_log(self, level, message):
                self.entries.append((level, message))

        class Repository:
            def __init__(self):
                self.recorded = []
                self.published = []

            def record_learning_example(self, *args):
                self.recorded.append(args)
                return True

            def get_learning_examples(self, _limit):
                return examples

            def get_active_learning_model(self):
                return None

            def publish_learning_model(self, model, metrics):
                self.published.append((model, metrics))
                return model['model_version']

        context = SimpleNamespace(
            _scam_records=[{
                'candidate_id': 'candidate-id',
                'review_version': 1,
                'category': 'phishing',
                'learning_features': example(True, 'phishing', 0.9)['features'],
            }],
            _learning_max_examples=5000,
            _learning_minimum_per_class=5,
            _learning_status={},
            _log_view=Log(),
        )
        repository = Repository()
        MainWindow._run_automatic_learning(
            context, repository, [0], 'strong_suspicion'
        )
        self.assertEqual(len(repository.recorded), 1)
        self.assertEqual(len(repository.published), 1)
        self.assertIn('更新済み', context._learning_status['status'])


if __name__ == '__main__':
    unittest.main()
