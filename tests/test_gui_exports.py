import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import openpyxl

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))


class GuiExportTests(unittest.TestCase):
    def test_reviewed_result_is_saved_directly_to_chosen_excel_path(self):
        try:
            import gui
        except ImportError:
            self.skipTest('PyQt6 is unavailable')
        MainWindow = gui.MainWindow

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            template = root / 'template.xlsx'
            workbook = openpyxl.Workbook()
            sheet = workbook.active
            sheet.title = '様式'
            for column, value in enumerate(
                ['実施年月日', 'ＳＮＳ別', 'サイト名・ユーザー名', 'ＵＲＬ', '該当項目', '備考'],
                start=1,
            ):
                sheet.cell(1, column, value)
            workbook.save(template)
            selected = root / 'results' / '確認結果.xlsx'

            class Field:
                def __init__(self, value):
                    self._value = value

                def text(self):
                    return self._value

            class Log:
                def append_log(self, _level, _message):
                    pass

            context = SimpleNamespace(
                _scam_records=[{
                    'review_status': 'strong_suspicion',
                    'url': 'https://example.test/path',
                    'target_brand': '確認対象',
                    'features': '確認済み',
                    'review_reason': '複数根拠あり',
                    'rules': 'R-TEST',
                    'completeness_label': '十分',
                    'category': 'phishing',
                }],
                _excel_path_input=Field(str(template)),
                _report_output_input=Field(str(selected.parent)),
                _reporter_name_input=Field('確認者'),
                _last_excel_report_path='',
                _log_view=Log(),
                _resolve_local_path=MainWindow._resolve_local_path,
                _write_evidence_manifest=MainWindow._write_evidence_manifest,
            )
            with (
                patch.object(gui.QFileDialog, 'getSaveFileName', return_value=(str(selected), '')),
                patch.object(gui.QMessageBox, 'information'),
                patch.object(gui.QMessageBox, 'critical') as critical,
            ):
                MainWindow._save_excel_report(context)

            self.assertFalse(critical.called)
            self.assertTrue(selected.exists())
            self.assertTrue(selected.with_suffix('.xlsx.manifest.json').exists())
            self.assertEqual(context._last_excel_report_path, str(selected))


if __name__ == '__main__':
    unittest.main()
