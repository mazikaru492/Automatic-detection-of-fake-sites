import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Optional
import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment
from openpyxl.utils import get_column_letter
logger = logging.getLogger(__name__)
TARGET_SHEET_NAME = '様式'
COLUMN_KEYWORDS = {'実施年月日': ['実施年月日', '年月日', 'date'], 'ＳＮＳ別': ['ＳＮＳ別', 'sns別', 'sns', '種別'], 'サイト名・ユーザー名': ['サイト名・ユーザー名', 'サイト名', 'ユーザー名', '名称'], 'ＵＲＬ': ['ＵＲＬ', 'url', 'アドレス'], '該当項目': ['該当項目', '分類', 'カテゴリ'], '備考': ['備考', '特徴', 'メモ']}

class ExcelReporter:

    def __init__(self, excel_path: str):
        self._excel_path: Path = Path(excel_path)
        self._workbook: Optional[openpyxl.Workbook] = None
        self._sheet = None
        self._column_map: dict[str, int] = {}
        self._first_data_row: int = 0
        self._next_row: int = 0
        self._appended_count: int = 0
        if self._excel_path.suffix.lower() == '.xls':
            self._output_path = self._excel_path.with_suffix('.xlsx')
        else:
            self._output_path = self._excel_path
        self._load_workbook()

    def _load_workbook(self) -> None:
        if not self._excel_path.exists():
            logger.warning(f'テンプレートファイルが見つかりません: {self._excel_path}\n新規ワークブックを作成します。')
            self._create_new_workbook()
            return
        file_ext = self._excel_path.suffix.lower()
        try:
            if file_ext == '.xls':
                self._load_from_xls()
            elif file_ext in ('.xlsx', '.xlsm'):
                self._workbook = openpyxl.load_workbook(str(self._excel_path))
                self._setup_sheet()
            else:
                logger.error(f'サポートされていないファイル形式: {file_ext}')
                self._create_new_workbook()
        except Exception as e:
            logger.error(f'Excel 読み込みエラー: {e}')
            self._create_new_workbook()

    def _load_from_xls(self) -> None:
        try:
            import xlrd
        except ImportError:
            logger.error('xlrd がインストールされていません。`pip install xlrd==1.2.0` を実行してください。')
            self._create_new_workbook()
            return
        xls_book = xlrd.open_workbook(str(self._excel_path))
        sheet_names = xls_book.sheet_names()
        if TARGET_SHEET_NAME in sheet_names:
            xls_sheet = xls_book.sheet_by_name(TARGET_SHEET_NAME)
        elif sheet_names:
            xls_sheet = xls_book.sheet_by_index(0)
            logger.warning(f"シート '{TARGET_SHEET_NAME}' が見つかりません。最初のシート '{xls_sheet.name}' を使用します。")
        else:
            self._create_new_workbook()
            return
        self._workbook = openpyxl.Workbook()
        ws = self._workbook.active
        ws.title = xls_sheet.name
        for row_idx in range(xls_sheet.nrows):
            for col_idx in range(xls_sheet.ncols):
                cell_value = xls_sheet.cell_value(row_idx, col_idx)
                ws.cell(row=row_idx + 1, column=col_idx + 1, value=cell_value)
        logger.info(f'✅ .xls ファイルを読み込み、xlsx 形式に変換しました')
        self._setup_sheet()

    def _create_new_workbook(self) -> None:
        self._workbook = openpyxl.Workbook()
        ws = self._workbook.active
        ws.title = TARGET_SHEET_NAME
        headers = ['実施年月日', 'ＳＮＳ別', 'サイト名・ユーザー名', 'ＵＲＬ', '該当項目', '備考']
        for col_idx, header in enumerate(headers, start=1):
            cell = ws.cell(row=1, column=col_idx, value=header)
            cell.font = Font(bold=True)
            cell.fill = PatternFill(start_color='4472C4', end_color='4472C4', fill_type='solid')
            cell.font = Font(bold=True, color='FFFFFF')
        self._output_path = Path('CYCOT_report.xlsx')
        logger.info('新規 Excel ワークブックを作成しました')
        self._setup_sheet()

    def _setup_sheet(self) -> None:
        ws = self._workbook[TARGET_SHEET_NAME] if TARGET_SHEET_NAME in self._workbook.sheetnames else self._workbook.active
        self._sheet = ws
        self._column_map = self._detect_columns()
        self._next_row = self._find_last_data_row() + 1
        logger.info(f"📊 シート '{ws.title}' を使用。データ追記開始行: {self._next_row}")

    def _detect_columns(self) -> dict[str, int]:
        column_map = {}
        ws = self._sheet
        for row in ws.iter_rows(min_row=1, max_row=5):
            for cell in row:
                if cell.value is None:
                    continue
                cell_str = str(cell.value).strip().lower()
                for col_key, keywords in COLUMN_KEYWORDS.items():
                    if col_key in column_map:
                        continue
                    if any((kw in cell_str for kw in keywords)):
                        column_map[col_key] = cell.column
                        logger.debug(f"列マッピング: '{col_key}' → 列 {cell.column}")
                        break
        if not column_map:
            logger.warning('列ヘッダーを自動検出できませんでした。デフォルト順を使用します。')
            column_map = {'実施年月日': 1, 'ＳＮＳ別': 2, 'サイト名・ユーザー名': 3, 'ＵＲＬ': 4, '該当項目': 5, '備考': 6}
        return column_map

    def _find_last_data_row(self) -> int:
        ws = self._sheet
        last_row = 1
        for row in ws.iter_rows(min_row=1, max_row=ws.max_row):
            if any((cell.value is not None for cell in row)):
                last_row = row[0].row
        return last_row

    def append_record(self, url: str, target_brand: str, features: str, detected_at: Optional[str]=None) -> None:
        ws = self._sheet
        row = self._next_row
        date_str = detected_at or datetime.now().strftime('%Y/%m/%d')
        data_map = {'実施年月日': date_str, 'ＳＮＳ別': 'サイト', 'サイト名・ユーザー名': target_brand, 'ＵＲＬ': url, '該当項目': '偽ショッピングサイト', '備考': features}
        for col_name, value in data_map.items():
            col_idx = self._column_map.get(col_name)
            if col_idx is None:
                continue
            cell = ws.cell(row=row, column=col_idx, value=value)
            if col_name == 'ＵＲＬ':
                cell.font = Font(color='000000', underline=None)
                cell.alignment = Alignment(wrap_text=False)
        self._next_row += 1
        self._appended_count += 1
        logger.info(f'📝 Excel に追記 (行 {row}): {url[:60]}...')

    def save(self) -> str:
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_path = self._output_path.with_stem(f'{self._output_path.stem}_{timestamp}')
            self._workbook.save(str(output_path))
            logger.info(f'✅ Excel レポートを保存しました: {output_path} ({self._appended_count} 件追記)')
            return str(output_path)
        except Exception as e:
            logger.error(f'Excel 保存エラー: {e}')
            raise

    @property
    def appended_count(self) -> int:
        return self._appended_count
