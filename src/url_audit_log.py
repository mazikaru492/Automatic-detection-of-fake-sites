"""Thread-safe, append-only audit logs for candidate and scan URLs."""

from __future__ import annotations

import datetime as dt
import json
import logging
import threading
import uuid
from pathlib import Path
from typing import Any

from url_normalization import safe_observation_url


logger = logging.getLogger(__name__)
FILTER_PASSED_LOG_NAME = 'filter_passed_urls.log'
SCANNED_LOG_NAME = 'scanned_urls.log'


class UrlAuditLog:
    """Write two human-readable JSON Lines files without URL secrets."""

    def __init__(self, log_dir: str | Path | None = None):
        self.log_dir = (
            Path(log_dir)
            if log_dir is not None
            else Path(__file__).resolve().parents[1] / 'logs'
        )
        self.filter_passed_path = self.log_dir / FILTER_PASSED_LOG_NAME
        self.scanned_path = self.log_dir / SCANNED_LOG_NAME
        self.session_id = str(uuid.uuid4())
        self._lock = threading.Lock()
        self._enabled = True
        self._failure_reported = False
        self._start_session()

    @property
    def paths(self) -> tuple[Path, Path]:
        return self.filter_passed_path, self.scanned_path

    def _start_session(self) -> None:
        try:
            self.log_dir.mkdir(parents=True, exist_ok=True)
            for path, stream in (
                (self.filter_passed_path, 'filter_passed'),
                (self.scanned_path, 'scanned'),
            ):
                self._append(path, {
                    'timestamp': self._timestamp(),
                    'event': 'session_started',
                    'stream': stream,
                    'session_id': self.session_id,
                })
        except OSError as exc:
            self._enabled = False
            self._report_failure(exc)

    def record_filter_passed(
        self,
        url: str,
        *,
        domain: str,
        source: str,
        candidate_kind: str,
        score: int,
    ) -> bool:
        try:
            safe_score = max(0, min(int(score), 100))
        except (TypeError, ValueError):
            safe_score = 0
        return self._record(self.filter_passed_path, {
            'event': 'filter_passed',
            'url': url,
            'domain': str(domain)[:253],
            'source': str(source)[:64],
            'candidate_kind': str(candidate_kind)[:64],
            'score': safe_score,
        })

    def record_scanned(
        self,
        url: str,
        *,
        domain: str,
        source: str,
        candidate_kind: str,
    ) -> bool:
        return self._record(self.scanned_path, {
            'event': 'scan_started',
            'url': url,
            'domain': str(domain)[:253],
            'source': str(source)[:64],
            'candidate_kind': str(candidate_kind)[:64],
        })

    def _record(self, path: Path, values: dict[str, Any]) -> bool:
        if not self._enabled:
            return False
        try:
            safe_url = safe_observation_url(values['url'])
            entry = {
                'timestamp': self._timestamp(),
                'session_id': self.session_id,
                **values,
                'url': safe_url,
            }
            self._append(path, entry)
            return True
        except (OSError, TypeError, ValueError) as exc:
            self._report_failure(exc)
            return False

    def _append(self, path: Path, entry: dict[str, Any]) -> None:
        line = json.dumps(entry, ensure_ascii=False, separators=(',', ':'))
        with self._lock:
            with path.open('a', encoding='utf-8', newline='\n') as handle:
                handle.write(line + '\n')

    def _report_failure(self, exc: Exception) -> None:
        if not self._failure_reported:
            logger.warning('URL監査ログを書き込めません。監視処理は継続します: %s', exc)
            self._failure_reported = True

    @staticmethod
    def _timestamp() -> str:
        return dt.datetime.now().astimezone().isoformat(timespec='seconds')
