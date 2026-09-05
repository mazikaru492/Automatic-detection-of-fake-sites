"""Auditable classifier trained only from completed human reviews.

The learned probability supplements deterministic rules. It never changes a
human review, creates a report, or replaces the specification's rule score.
The implementation intentionally uses a small fixed feature schema so saved
models remain inspectable and do not depend on pickle or executable payloads.
"""

from __future__ import annotations

import datetime as dt
import math
import uuid
from collections import Counter, defaultdict
from dataclasses import dataclass, replace
from typing import Any, Iterable


MODEL_SCHEMA_VERSION = 'review-logistic-v1'
PREDICTION_THRESHOLD = 0.65
LEARNING_CATEGORIES = ('phishing', 'fraudulent_ec', 'suspected_counterfeit')
FEATURE_NAMES = (
    'rule_score', 'known_feed', 'brand_present', 'kind_phishing',
    'kind_fraudulent_ec', 'kind_counterfeit', 'page_observed',
    'urlscan_malicious', 'urlscan_score', 'vocabulary_score',
    'credential_signal', 'transaction_signal', 'fraud_signal',
    'counterfeit_signal', 'illegal_goods_signal', 'new_domain',
    'dns_resolved', 'llm_confidence', 'llm_reportable',
)


def _number(value: Any, default: float = 0.0) -> float:
    try:
        converted = float(value)
    except (TypeError, ValueError, OverflowError):
        return default
    return converted if math.isfinite(converted) else default


def build_feature_vector(
    domain_info: dict,
    scan_result: dict,
    assessment,
    analysis=None,
) -> dict[str, float]:
    """Create non-identifying, bounded features from the collected evidence."""
    signals = scan_result.get('page_signals') or {}
    if not isinstance(signals, dict):
        signals = {}
    fraud_evidence = signals.get('fraud') or []
    fraud_count = (
        len(fraud_evidence)
        if isinstance(fraud_evidence, (list, tuple, set))
        else int(bool(fraud_evidence))
    )
    kind = str(domain_info.get('candidate_kind', ''))
    age = domain_info.get('domain_age_days')
    raw_features = {
        'rule_score': _number(getattr(assessment, 'score', 0)) / 95.0,
        'known_feed': float(domain_info.get('known_phishing') is True),
        'brand_present': float(bool(domain_info.get('brand'))),
        'kind_phishing': float(kind in ('brand_impersonation', 'known_phishing')),
        'kind_fraudulent_ec': float(kind in ('suspicious_shop', 'suspected_illegal_goods')),
        'kind_counterfeit': float(kind == 'counterfeit_goods'),
        'page_observed': float(scan_result.get('fetch_status') == 'observed'),
        'urlscan_malicious': float(scan_result.get('urlscan_malicious') is True),
        'urlscan_score': _number(scan_result.get('urlscan_score')) / 100.0,
        'vocabulary_score': _number(scan_result.get('vocabulary_score')) / 100.0,
        'credential_signal': float(bool(signals.get('credential'))),
        'transaction_signal': float(bool(signals.get('transaction'))),
        'fraud_signal': fraud_count / 3.0,
        'counterfeit_signal': float(bool(signals.get('counterfeit'))),
        'illegal_goods_signal': float(bool(signals.get('illegal_goods'))),
        'new_domain': float(isinstance(age, (int, float)) and 0 <= age <= 30),
        'dns_resolved': float(domain_info.get('dns_status') == 'resolved'),
        'llm_confidence': _number(getattr(analysis, 'confidence', 0)) / 100.0,
        'llm_reportable': float(
            getattr(analysis, 'verdict', '') in ('reportable', 'confirmed_scam')
        ),
    }
    return sanitize_features(raw_features)


def sanitize_features(features: dict[str, Any]) -> dict[str, float]:
    """Accept only the fixed schema and clamp every value to a safe range."""
    source = features if isinstance(features, dict) else {}
    return {
        name: min(max(_number(source.get(name)), 0.0), 1.0)
        for name in FEATURE_NAMES
    }


@dataclass(frozen=True)
class LearningModel:
    model_version: str
    weights: tuple[float, ...]
    bias: float
    trained_at: str
    training_examples: int
    supported_categories: tuple[str, ...]

    def predict(self, features: dict[str, Any]) -> float:
        values = sanitize_features(features)
        linear = self.bias + sum(
            weight * values[name] for name, weight in zip(FEATURE_NAMES, self.weights)
        )
        linear = min(max(linear, -35.0), 35.0)
        return 1.0 / (1.0 + math.exp(-linear))

    def predict_for_category(
        self,
        category: str,
        features: dict[str, Any],
    ) -> float | None:
        if category not in self.supported_categories:
            return None
        return self.predict(features)

    def as_dict(self) -> dict[str, Any]:
        return {
            'schema_version': MODEL_SCHEMA_VERSION,
            'model_version': self.model_version,
            'feature_names': list(FEATURE_NAMES),
            'weights': list(self.weights),
            'bias': self.bias,
            'trained_at': self.trained_at,
            'training_examples': self.training_examples,
            'supported_categories': list(self.supported_categories),
            'prediction_threshold': PREDICTION_THRESHOLD,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> 'LearningModel | None':
        if not isinstance(data, dict) or data.get('schema_version') != MODEL_SCHEMA_VERSION:
            return None
        if tuple(data.get('feature_names') or ()) != FEATURE_NAMES:
            return None
        weights = data.get('weights')
        if not isinstance(weights, list) or len(weights) != len(FEATURE_NAMES):
            return None
        raw_categories = data.get('supported_categories')
        if (
            not isinstance(raw_categories, list)
            or not raw_categories
            or any(not isinstance(category, str) for category in raw_categories)
        ):
            return None
        try:
            converted_weights = tuple(float(value) for value in weights)
            bias = float(data['bias'])
            model_version = str(data['model_version'])
            training_examples = int(data['training_examples'])
            trained_at = str(data['trained_at'])
            supported_categories = tuple(raw_categories)
        except (KeyError, TypeError, ValueError, OverflowError):
            return None
        if (
            not model_version or len(model_version) > 128
            or training_examples < 1
            or not trained_at
            or not supported_categories
            or any(category not in LEARNING_CATEGORIES for category in supported_categories)
            or len(set(supported_categories)) != len(supported_categories)
            or not math.isfinite(bias) or abs(bias) > 100.0
            or any(not math.isfinite(value) or abs(value) > 100.0 for value in converted_weights)
        ):
            return None
        return cls(
            model_version=model_version,
            weights=converted_weights,
            bias=bias,
            trained_at=trained_at,
            training_examples=training_examples,
            supported_categories=supported_categories,
        )


@dataclass(frozen=True)
class TrainingResult:
    promoted: bool
    reason: str
    model: LearningModel | None
    metrics: dict[str, float | int]


TrainingExample = tuple[dict[str, float], int, str]


def _fit(examples: list[TrainingExample]) -> LearningModel:
    weights = [0.0] * len(FEATURE_NAMES)
    bias = 0.0
    group_counts = Counter((label, category) for _, label, category in examples)
    group_total = len(group_counts)
    epochs = max(50, min(500, 20_000 // len(examples)))
    for epoch in range(epochs):
        gradient = [0.0] * len(weights)
        bias_gradient = 0.0
        for features, label, category in examples:
            linear = bias + sum(
                weights[index] * features[name]
                for index, name in enumerate(FEATURE_NAMES)
            )
            bounded = min(max(linear, -35.0), 35.0)
            probability = 1.0 / (1.0 + math.exp(-bounded))
            group_weight = len(examples) / (
                group_total * group_counts[(label, category)]
            )
            error = (probability - label) * group_weight
            for index, name in enumerate(FEATURE_NAMES):
                gradient[index] += error * features[name]
            bias_gradient += error
        learning_rate = 0.25 / math.sqrt(epoch + 1)
        for index in range(len(weights)):
            regularized = gradient[index] / len(examples) + 0.01 * weights[index]
            weights[index] -= learning_rate * regularized
        bias -= learning_rate * bias_gradient / len(examples)
    category_labels: dict[str, set[int]] = defaultdict(set)
    for _, label, category in examples:
        category_labels[category].add(label)
    supported_categories = tuple(sorted(
        category for category, labels in category_labels.items()
        if labels == {0, 1}
    ))
    return LearningModel(
        model_version=str(uuid.uuid4()),
        weights=tuple(weights),
        bias=bias,
        trained_at=dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds'),
        training_examples=len(examples),
        supported_categories=supported_categories,
    )


def _metrics(labels: Iterable[int], probabilities: Iterable[float]) -> dict[str, float | int]:
    pairs = list(zip(labels, probabilities))
    true_positive = false_positive = true_negative = false_negative = 0
    for label, probability in pairs:
        predicted = probability >= PREDICTION_THRESHOLD
        if predicted and label:
            true_positive += 1
        elif predicted:
            false_positive += 1
        elif label:
            false_negative += 1
        else:
            true_negative += 1
    precision = (
        true_positive / (true_positive + false_positive)
        if true_positive + false_positive else 0.0
    )
    recall = (
        true_positive / (true_positive + false_negative)
        if true_positive + false_negative else 0.0
    )
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        'samples': len(pairs),
        'true_positive': true_positive,
        'false_positive': false_positive,
        'true_negative': true_negative,
        'false_negative': false_negative,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'false_positive_rate': (
            false_positive / (false_positive + true_negative)
            if false_positive + true_negative else 0.0
        ),
        'accuracy': (
            (true_positive + true_negative) / len(pairs) if pairs else 0.0
        ),
    }


def _parse_examples(raw_examples: list[dict[str, Any]]) -> list[TrainingExample]:
    parsed: list[TrainingExample] = []
    for item in raw_examples:
        if not isinstance(item, dict):
            continue
        raw_label = item.get('label')
        if isinstance(raw_label, bool):
            label = int(raw_label)
        elif isinstance(raw_label, int) and raw_label in (0, 1):
            label = raw_label
        else:
            continue
        category = str(item.get('category', ''))
        if category not in LEARNING_CATEGORIES:
            continue
        parsed.append((sanitize_features(item.get('features') or {}), label, category))
    return parsed


def _split_training_validation(
    examples: list[TrainingExample],
) -> tuple[list[TrainingExample], list[TrainingExample]]:
    """Use the newest tail of each represented label/category group for validation."""
    groups: dict[tuple[int, str], list[TrainingExample]] = defaultdict(list)
    for example in examples:
        groups[(example[1], example[2])].append(example)
    training: list[TrainingExample] = []
    validation: list[TrainingExample] = []
    for group in groups.values():
        validation_size = max(1, len(group) // 5) if len(group) >= 5 else 0
        if validation_size:
            training.extend(group[:-validation_size])
            validation.extend(group[-validation_size:])
        else:
            training.extend(group)
    return training, validation


def train_challenger(
    raw_examples: list[dict[str, Any]],
    current_model: LearningModel | None = None,
    *,
    minimum_per_class: int = 10,
) -> TrainingResult:
    """Train and evaluate a challenger; return promoted only when gates pass."""
    examples = _parse_examples(raw_examples)
    positive_count = sum(label for _, label, _ in examples)
    negative_count = len(examples) - positive_count
    count_metrics: dict[str, float | int] = {
        'samples': len(examples),
        'positive': positive_count,
        'negative': negative_count,
    }
    if min(positive_count, negative_count) < minimum_per_class:
        return TrainingResult(
            False,
            f'学習待ち: 陽性{positive_count}件・陰性{negative_count}件'
            f'（各{minimum_per_class}件必要）',
            None,
            count_metrics,
        )

    training, validation = _split_training_validation(examples)
    training_labels = {label for _, label, _ in training}
    validation_labels = {label for _, label, _ in validation}
    if training_labels != {0, 1} or validation_labels != {0, 1}:
        return TrainingResult(
            False,
            '学習待ち: 学習用と評価用の両方に陽性・陰性例が必要です',
            None,
            count_metrics,
        )

    required_training_size = (
        current_model.training_examples
        + max(5, current_model.training_examples // 10)
        if current_model else 0
    )
    if current_model and len(training) < required_training_size:
        return TrainingResult(
            False,
            '追加の人手レビューが蓄積するまで現行モデルを維持',
            None,
            {
                **count_metrics,
                'training_samples': len(training),
                'validation_samples': len(validation),
                'required_training_samples': required_training_size,
            },
        )

    challenger = _fit(training)
    validation_category_labels: dict[str, set[int]] = defaultdict(set)
    for _, label, category in validation:
        validation_category_labels[category].add(label)
    evaluated_categories = tuple(
        category for category in challenger.supported_categories
        if validation_category_labels[category] == {0, 1}
    )
    if not evaluated_categories:
        return TrainingResult(
            False,
            '学習待ち: 同じ分類の学習用・評価用に陽性・陰性の両方が必要です',
            None,
            {
                **count_metrics,
                'training_samples': len(training),
                'validation_samples': len(validation),
            },
        )
    challenger = replace(challenger, supported_categories=evaluated_categories)
    validation = [
        item for item in validation if item[2] in challenger.supported_categories
    ]
    labels = [label for _, label, _ in validation]
    challenger_probabilities = [
        challenger.predict(features) for features, _, _ in validation
    ]
    challenger_metrics = _metrics(labels, challenger_probabilities)
    if current_model:
        baseline_probabilities = []
        for features, _, category in validation:
            current_probability = current_model.predict_for_category(category, features)
            baseline_probabilities.append(
                current_probability
                if current_probability is not None else features['rule_score']
            )
    else:
        baseline_probabilities = [features['rule_score'] for features, _, _ in validation]
    baseline_metrics = _metrics(labels, baseline_probabilities)
    metrics: dict[str, float | int] = {
        **count_metrics,
        **{f'challenger_{key}': value for key, value in challenger_metrics.items()},
        **{f'baseline_{key}': value for key, value in baseline_metrics.items()},
        'training_samples': len(training),
        'validation_samples': len(validation),
    }
    category_quality_passed = True
    for category in challenger.supported_categories:
        category_indexes = [
            index for index, (_, _, item_category) in enumerate(validation)
            if item_category == category
        ]
        category_labels = [labels[index] for index in category_indexes]
        if set(category_labels) != {0, 1}:
            continue
        challenger_category = _metrics(
            category_labels,
            [challenger_probabilities[index] for index in category_indexes],
        )
        baseline_category = _metrics(
            category_labels,
            [baseline_probabilities[index] for index in category_indexes],
        )
        for key in ('precision', 'recall', 'f1', 'false_positive_rate', 'samples'):
            metrics[f'challenger_{category}_{key}'] = challenger_category[key]
            metrics[f'baseline_{category}_{key}'] = baseline_category[key]
        category_quality_passed = category_quality_passed and (
            challenger_category['precision'] >= 0.70
            and challenger_category['recall'] + 0.10 >= baseline_category['recall']
            and challenger_category['false_positive_rate']
            <= baseline_category['false_positive_rate'] + 0.05
        )
    quality_passed = (
        challenger_metrics['precision'] >= 0.80
        and challenger_metrics['recall'] + 0.05 >= baseline_metrics['recall']
        and challenger_metrics['f1'] + 0.01 >= baseline_metrics['f1']
        and challenger_metrics['false_positive_rate']
        <= baseline_metrics['false_positive_rate'] + 0.02
        and category_quality_passed
    )
    promoted = quality_passed
    if not quality_passed:
        reason = '評価基準を満たさないため現行モデルを維持'
    else:
        reason = '評価基準を満たした新モデルを採用'
    return TrainingResult(promoted, reason, challenger, metrics)
