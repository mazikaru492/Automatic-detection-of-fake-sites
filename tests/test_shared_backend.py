import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from shared_backend import (
    SharedBackendConfigurationError,
    load_shared_backend_config,
)


class SharedBackendConfigTests(unittest.TestCase):
    def _write(self, directory: str, data: dict) -> Path:
        path = Path(directory) / "shared_backend.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def test_loads_administrator_managed_publishable_settings(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(directory, {
                "display_name": "Team database",
                "project_url": "https://demo.supabase.co",
                "publishable_key": "sb_publishable_example",
            })
            config = load_shared_backend_config(path)
            self.assertEqual(config.project_url, "https://demo.supabase.co")
            self.assertEqual(config.publishable_key, "sb_publishable_example")
            self.assertEqual(config.display_name, "Team database")

    def test_rejects_unconfigured_template(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(directory, {
                "project_url": "https://YOUR_PROJECT_REF.supabase.co",
                "publishable_key": "SET_BY_ADMINISTRATOR",
            })
            with self.assertRaisesRegex(
                SharedBackendConfigurationError, "初期設定"
            ):
                load_shared_backend_config(path)

    def test_rejects_secret_key(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(directory, {
                "project_url": "https://demo.supabase.co",
                "publishable_key": "sb_secret_do_not_ship",
            })
            with self.assertRaisesRegex(
                SharedBackendConfigurationError, "Secret key"
            ):
                load_shared_backend_config(path)


if __name__ == "__main__":
    unittest.main()
