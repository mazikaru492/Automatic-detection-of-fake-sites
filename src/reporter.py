"""
reporter.py — Output モジュール (Excel レポート出力)

CYCOT サイパト実施結果フォーマットの Excel ファイルに
AIが詐欺と判定したデータを追記する。

設計上の判断:
- .xls (旧形式) はopenpyxlでは読めないため、xlrdで読み込み後にopenpyxlで処理。
- もし元ファイルが .xlsx なら直接 openpyxl で読み書きする。
- URL はテキストとして書き込み、セルをリンク化しない（セキュリティ要件）。
- 追記のみ行い、既存データは一切変更しない（証拠保全の原則）。
"""

import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Optional

import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment
from openpyxl.utils import get_column_letter

logger = logging.getLogger(__name__)

# 対象シート名（要件より）
TARGET_SHEET_NAME = "様式"

# Excel 列マッピング（要件より）
# フォーマット: 列名 → 列インデックス（1始まり）
# 実際のファイルのヘッダー行を確認してから動的にマッピングする設計にする
COLUMN_KEYWORDS = {
    "実施年月日": ["実施年月日", "年月日", "date"],
    "ＳＮＳ別": ["ＳＮＳ別", "sns別", "sns", "種別"],
    "サイト名・ユーザー名": ["サイト名・ユーザー名", "サイト名", "ユーザー名", "名称"],
    "ＵＲＬ": ["ＵＲＬ", "url", "アドレス"],
    "該当項目": ["該当項目", "分類", "カテゴリ"],
    "備考": ["備考", "特徴", "メモ"],
}


class ExcelReporter:
    """
    Excel ファイルへの詐欺データ追記クラス。

    使い方:
        reporter = ExcelReporter("path/to/report.xls")
        reporter.append_record(
            url="https://...",
            target_brand="Amazon",
            features="不自然な日本語...",
            detected_at="2024-01-01",
        )
        reporter.save()
    """

    def __init__(self, excel_path: str):
        self._excel_path: Path = Path(excel_path)
        self._workbook: Optional[openpyxl.Workbook] = None
        self._sheet = None
        self._column_map: dict[str, int] = {}
        self._first_data_row: int = 0
        self._next_row: int = 0
        self._appended_count: int = 0

        # 出力ファイルパス（xlsの場合はxlsxで出力）
        if self._excel_path.suffix.lower() == ".xls":
            self._output_path = self._excel_path.with_suffix(".xlsx")
        else:
            self._output_path = self._excel_path

        self._load_workbook()

    def _load_workbook(self) -> None:
        """
        既存の Excel ファイルを読み込む。

        .xls 形式の場合:
            xlrd で読み込み → openpyxl の Workbook に変換する。
            これは openpyxl が .xls 形式をサポートしていないためのワークアラウンド。
        .xlsx 形式の場合:
            openpyxl で直接読み込む。
        """
        if not self._excel_path.exists():
            logger.warning(
                f"テンプレートファイルが見つかりません: {self._excel_path}\n"
                "新規ワークブックを作成します。"
            )
            self._create_new_workbook()
            return

        file_ext = self._excel_path.suffix.lower()

        try:
            if file_ext == ".xls":
                self._load_from_xls()
            elif file_ext in (".xlsx", ".xlsm"):
                self._workbook = openpyxl.load_workbook(str(self._excel_path))
                self._setup_sheet()
            else:
                logger.error(f"サポートされていないファイル形式: {file_ext}")
                self._create_new_workbook()

        except Exception as e:
            logger.error(f"Excel 読み込みエラー: {e}")
            self._create_new_workbook()

    def _load_from_xls(self) -> None:
        """
        xlrd を使って .xls を読み込み、openpyxl の Workbook に変換する。

        なぜ変換が必要か:
        - 古い .xls 形式 (BIFF8) は openpyxl で書き込めない。
        - xlwt は Python 3.9+ での互換性が不安定。
        - xlrd → openpyxl 変換が最も安定した方法。
        """
        try:
            import xlrd
        except ImportError:
            logger.error(
                "xlrd がインストールされていません。"
                "`pip install xlrd==1.2.0` を実行してください。"
            )
            self._create_new_workbook()
            return

        xls_book = xlrd.open_workbook(str(self._excel_path))

        # 対象シートを特定
        sheet_names = xls_book.sheet_names()
        if TARGET_SHEET_NAME in sheet_names:
            xls_sheet = xls_book.sheet_by_name(TARGET_SHEET_NAME)
        elif sheet_names:
            xls_sheet = xls_book.sheet_by_index(0)
            logger.warning(
                f"シート '{TARGET_SHEET_NAME}' が見つかりません。"
                f"最初のシート '{xls_sheet.name}' を使用します。"
            )
        else:
            self._create_new_workbook()
            return

        # openpyxl Workbook に変換
        self._workbook = openpyxl.Workbook()
        ws = self._workbook.active
        ws.title = xls_sheet.name

        for row_idx in range(xls_sheet.nrows):
            for col_idx in range(xls_sheet.ncols):
                cell_value = xls_sheet.cell_value(row_idx, col_idx)
                ws.cell(row=row_idx + 1, column=col_idx + 1, value=cell_value)

        logger.info(f"✅ .xls ファイルを読み込み、xlsx 形式に変換しました")
        self._setup_sheet()

    def _create_new_workbook(self) -> None:
        """
        テンプレートファイルが存在しない場合に新規作成する。

        フォールバック処理として、CYCOT 様式に準拠したヘッダーを自動生成する。
        """
        self._workbook = openpyxl.Workbook()
        ws = self._workbook.active
        ws.title = TARGET_SHEET_NAME

        # ヘッダー行を作成（要件に基づく列名）
        headers = [
            "実施年月日",
            "ＳＮＳ別",
            "サイト名・ユーザー名",
            "ＵＲＬ",
            "該当項目",
            "備考",
        ]
        for col_idx, header in enumerate(headers, start=1):
            cell = ws.cell(row=1, column=col_idx, value=header)
            cell.font = Font(bold=True)
            cell.fill = PatternFill(
                start_color="4472C4", end_color="4472C4", fill_type="solid"
            )
            cell.font = Font(bold=True, color="FFFFFF")

        self._output_path = Path("CYCOT_report.xlsx")
        logger.info("新規 Excel ワークブックを作成しました")
        self._setup_sheet()

    def _setup_sheet(self) -> None:
        """
        シートを特定し、列マッピングとデータ開始行を設定する。
        """
        ws = self._workbook[TARGET_SHEET_NAME] if TARGET_SHEET_NAME in self._workbook.sheetnames else self._workbook.active
        self._sheet = ws

        # ヘッダー行を検索して列マッピングを構築
        self._column_map = self._detect_columns()

        # 既存データの末尾行を特定
        self._next_row = self._find_last_data_row() + 1
        logger.info(
            f"📊 シート '{ws.title}' を使用。"
            f"データ追記開始行: {self._next_row}"
        )

    def _detect_columns(self) -> dict[str, int]:
        """
        ヘッダー行を走査して列名 → 列インデックスのマッピングを作成する。

        なぜ動的検出か:
        - テンプレートファイルの実際の列順が不明なため、
          キーワードマッチングで柔軟に対応する。
        """
        column_map = {}
        ws = self._sheet

        # ヘッダーは最初の数行に存在すると仮定して走査
        for row in ws.iter_rows(min_row=1, max_row=5):
            for cell in row:
                if cell.value is None:
                    continue
                cell_str = str(cell.value).strip().lower()

                for col_key, keywords in COLUMN_KEYWORDS.items():
                    if col_key in column_map:
                        continue
                    if any(kw in cell_str for kw in keywords):
                        column_map[col_key] = cell.column
                        logger.debug(f"列マッピング: '{col_key}' → 列 {cell.column}")
                        break

        if not column_map:
            # ヘッダーが検出できない場合はデフォルト列順を使用
            logger.warning("列ヘッダーを自動検出できませんでした。デフォルト順を使用します。")
            column_map = {
                "実施年月日": 1,
                "ＳＮＳ別": 2,
                "サイト名・ユーザー名": 3,
                "ＵＲＬ": 4,
                "該当項目": 5,
                "備考": 6,
            }

        return column_map

    def _find_last_data_row(self) -> int:
        """
        シート内の最後のデータ行番号を返す。

        max_row を信用しない理由:
        - Excel ファイルによっては空白行を "データ" として誤カウントする場合がある。
        - 実際にセル値を確認してより正確な末尾行を特定する。
        """
        ws = self._sheet
        last_row = 1  # 少なくともヘッダー行は存在する

        for row in ws.iter_rows(min_row=1, max_row=ws.max_row):
            if any(cell.value is not None for cell in row):
                last_row = row[0].row

        return last_row

    def append_record(
        self,
        url: str,
        target_brand: str,
        features: str,
        detected_at: Optional[str] = None,
    ) -> None:
        """
        詐欺判定データを Excel の末尾行に追記する。

        セキュリティ要件:
        - URL はテキストとして書き込む（hyperlink を設定しない）。
        - これにより Excel 上で誤クリックによる不審サイトへのアクセスを防ぐ。

        Args:
            url: 検出された不審 URL（テキストとして記録）
            target_brand: AI が判定した偽装ブランド名
            features: AI が抽出した不審な特徴
            detected_at: 検出日時（省略時は現在時刻）
        """
        ws = self._sheet
        row = self._next_row
        date_str = detected_at or datetime.now().strftime("%Y/%m/%d")

        # 各列にデータを書き込む
        data_map = {
            "実施年月日": date_str,
            "ＳＮＳ別": "サイト",
            "サイト名・ユーザー名": target_brand,
            "ＵＲＬ": url,          # ← テキストとして書き込む（セキュリティ要件）
            "該当項目": "偽ショッピングサイト",
            "備考": features,
        }

        for col_name, value in data_map.items():
            col_idx = self._column_map.get(col_name)
            if col_idx is None:
                continue

            cell = ws.cell(row=row, column=col_idx, value=value)

            # URL セルは明示的にリンクを無効化する
            # (ハイパーリンク属性を設定しないことで無害化)
            if col_name == "ＵＲＬ":
                cell.font = Font(color="000000", underline=None)
                cell.alignment = Alignment(wrap_text=False)

        self._next_row += 1
        self._appended_count += 1
        logger.info(f"📝 Excel に追記 (行 {row}): {url[:60]}...")

    def save(self) -> str:
        """
        ワークブックをファイルに保存し、保存先パスを返す。
        """
        try:
            # タイムスタンプ付きファイル名で保存（上書き防止）
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = self._output_path.with_stem(
                f"{self._output_path.stem}_{timestamp}"
            )
            self._workbook.save(str(output_path))
            logger.info(
                f"✅ Excel レポートを保存しました: {output_path} "
                f"({self._appended_count} 件追記)"
            )
            return str(output_path)
        except Exception as e:
            logger.error(f"Excel 保存エラー: {e}")
            raise

    @property
    def appended_count(self) -> int:
        """追記されたレコード数"""
        return self._appended_count
