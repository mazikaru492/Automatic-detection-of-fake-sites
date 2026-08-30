"""
gui.py — PyQt6 メインウィンドウ

サイバーセキュリティテーマのダークUI。
左サイドバー: 設定・コントロール
中央: リアルタイムログ（ターミナル風）
右パネル: 統計ダッシュボード
下部タブ: 検出一覧テーブル
"""

import os
import sys
import csv
from datetime import datetime
from pathlib import Path

from PyQt6.QtCore import (
    Qt, QTimer, QThread, pyqtSlot, QPropertyAnimation,
    QEasingCurve, QSize,
)
from PyQt6.QtGui import (
    QColor, QFont, QFontDatabase, QIcon, QPalette,
    QTextCharFormat, QTextCursor, QPixmap,
)
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QGridLayout, QLabel, QPushButton, QLineEdit, QTextEdit,
    QTableWidget, QTableWidgetItem, QTabWidget, QFrame,
    QFileDialog, QMessageBox, QHeaderView, QScrollArea,
    QSplitter, QSizePolicy, QSpinBox, QGroupBox,
    QStatusBar, QProgressBar, QCheckBox,
)

# ワーカーモジュールのパスを追加
sys.path.insert(0, str(Path(__file__).parent))
from worker import PipelineWorker

# -----------------------------------------------------------------------
# カラーパレット（サイバーセキュリティテーマ）
# -----------------------------------------------------------------------
COLORS = {
    "bg_dark":      "#0a0e1a",   # メイン背景（ディープネイビー）
    "bg_panel":     "#0f1628",   # パネル背景
    "bg_card":      "#151e35",   # カード背景
    "bg_input":     "#1a2545",   # 入力フィールド背景
    "accent_cyan":  "#00d4ff",   # シアン（メインアクセント）
    "accent_blue":  "#4d9fff",   # ブルー
    "accent_green": "#00ff88",   # グリーン（正常）
    "accent_red":   "#ff4757",   # レッド（警告・詐欺）
    "accent_orange":"#ffa502",   # オレンジ（警告）
    "text_primary": "#e8f4f8",   # メインテキスト
    "text_secondary":"#7fa3c0",  # サブテキスト
    "text_dim":     "#3d5a78",   # 薄いテキスト
    "border":       "#1e3a5a",   # ボーダー
    "border_glow":  "#00d4ff33", # グローボーダー
}

STYLE_SHEET = f"""
/* ===== グローバルスタイル ===== */
QMainWindow, QWidget {{
    background-color: {COLORS['bg_dark']};
    color: {COLORS['text_primary']};
    font-family: 'Segoe UI', 'Meiryo UI', 'Yu Gothic UI', sans-serif;
    font-size: 13px;
}}

/* ===== サイドバー ===== */
#sidebar {{
    background-color: {COLORS['bg_panel']};
    border-right: 1px solid {COLORS['border']};
}}

/* ===== カード ===== */
#card {{
    background-color: {COLORS['bg_card']};
    border: 1px solid {COLORS['border']};
    border-radius: 8px;
}}

/* ===== グループボックス ===== */
QGroupBox {{
    background-color: {COLORS['bg_card']};
    border: 1px solid {COLORS['border']};
    border-radius: 8px;
    margin-top: 12px;
    padding: 12px 8px 8px 8px;
    font-weight: bold;
    color: {COLORS['accent_cyan']};
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    left: 12px;
    padding: 0 6px;
}}

/* ===== 入力フィールド ===== */
QLineEdit, QSpinBox {{
    background-color: {COLORS['bg_input']};
    border: 1px solid {COLORS['border']};
    border-radius: 6px;
    padding: 7px 10px;
    color: {COLORS['text_primary']};
    font-size: 13px;
}}
QLineEdit:focus, QSpinBox:focus {{
    border: 1px solid {COLORS['accent_cyan']};
}}

/* ===== ボタン共通 ===== */
QPushButton {{
    border-radius: 6px;
    padding: 9px 18px;
    font-weight: bold;
    font-size: 13px;
    border: none;
    cursor: pointer;
}}
QPushButton:disabled {{
    opacity: 0.4;
    background-color: {COLORS['text_dim']};
    color: {COLORS['bg_dark']};
}}

/* ===== 開始ボタン ===== */
#btn_start {{
    background-color: {COLORS['accent_cyan']};
    color: {COLORS['bg_dark']};
}}
#btn_start:hover {{
    background-color: #33ddff;
}}
#btn_start:pressed {{
    background-color: #0099cc;
}}

/* ===== 停止ボタン ===== */
#btn_stop {{
    background-color: {COLORS['accent_red']};
    color: white;
}}
#btn_stop:hover {{
    background-color: #ff6b7a;
}}
#btn_stop:pressed {{
    background-color: #cc2233;
}}

/* ===== 保存ボタン ===== */
#btn_save {{
    background-color: {COLORS['accent_green']};
    color: {COLORS['bg_dark']};
}}
#btn_save:hover {{
    background-color: #33ffaa;
}}

/* ===== セカンダリボタン ===== */
#btn_secondary {{
    background-color: {COLORS['bg_input']};
    color: {COLORS['text_primary']};
    border: 1px solid {COLORS['border']};
}}
#btn_secondary:hover {{
    border-color: {COLORS['accent_cyan']};
    color: {COLORS['accent_cyan']};
}}

/* ===== テキストエリア（ログ） ===== */
QTextEdit#log_view {{
    background-color: #050810;
    border: 1px solid {COLORS['border']};
    border-radius: 8px;
    font-family: 'Cascadia Code', 'Consolas', 'Courier New', monospace;
    font-size: 12px;
    color: {COLORS['accent_green']};
    padding: 8px;
}}

/* ===== タブ ===== */
QTabWidget::pane {{
    border: 1px solid {COLORS['border']};
    border-radius: 8px;
    background-color: {COLORS['bg_panel']};
}}
QTabBar::tab {{
    background-color: {COLORS['bg_card']};
    color: {COLORS['text_secondary']};
    padding: 8px 20px;
    border: none;
    border-radius: 6px 6px 0 0;
    margin-right: 2px;
    font-weight: bold;
}}
QTabBar::tab:selected {{
    background-color: {COLORS['bg_panel']};
    color: {COLORS['accent_cyan']};
    border-bottom: 2px solid {COLORS['accent_cyan']};
}}
QTabBar::tab:hover:!selected {{
    color: {COLORS['text_primary']};
    background-color: {COLORS['bg_input']};
}}

/* ===== テーブル ===== */
QTableWidget {{
    background-color: {COLORS['bg_panel']};
    border: none;
    gridline-color: {COLORS['border']};
    color: {COLORS['text_primary']};
    selection-background-color: {COLORS['bg_input']};
}}
QTableWidget::item {{
    padding: 8px;
    border-bottom: 1px solid {COLORS['border']};
}}
QTableWidget::item:selected {{
    background-color: {COLORS['bg_input']};
    color: {COLORS['accent_cyan']};
}}
QHeaderView::section {{
    background-color: {COLORS['bg_card']};
    color: {COLORS['accent_cyan']};
    padding: 8px 12px;
    border: none;
    border-bottom: 2px solid {COLORS['accent_cyan']};
    font-weight: bold;
    font-size: 12px;
    letter-spacing: 1px;
    text-transform: uppercase;
}}

/* ===== スクロールバー ===== */
QScrollBar:vertical {{
    background-color: {COLORS['bg_dark']};
    width: 8px;
    border-radius: 4px;
}}
QScrollBar::handle:vertical {{
    background-color: {COLORS['border']};
    border-radius: 4px;
    min-height: 30px;
}}
QScrollBar::handle:vertical:hover {{
    background-color: {COLORS['accent_cyan']};
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0px;
}}

/* ===== ステータスバー ===== */
QStatusBar {{
    background-color: {COLORS['bg_panel']};
    border-top: 1px solid {COLORS['border']};
    color: {COLORS['text_secondary']};
    font-size: 12px;
}}

/* ===== プログレスバー ===== */
QProgressBar {{
    background-color: {COLORS['bg_input']};
    border: none;
    border-radius: 4px;
    height: 6px;
    text-align: center;
    font-size: 0px;
}}
QProgressBar::chunk {{
    background-color: {COLORS['accent_cyan']};
    border-radius: 4px;
}}

/* ===== チェックボックス ===== */
QCheckBox {{
    color: {COLORS['text_secondary']};
    spacing: 8px;
}}
QCheckBox::indicator {{
    width: 16px;
    height: 16px;
    border: 1px solid {COLORS['border']};
    border-radius: 3px;
    background-color: {COLORS['bg_input']};
}}
QCheckBox::indicator:checked {{
    background-color: {COLORS['accent_cyan']};
    border-color: {COLORS['accent_cyan']};
}}

/* ===== ラベル ===== */
#label_title {{
    font-size: 18px;
    font-weight: bold;
    color: {COLORS['accent_cyan']};
    letter-spacing: 2px;
}}
#label_subtitle {{
    font-size: 11px;
    color: {COLORS['text_dim']};
    letter-spacing: 1px;
}}
#stat_value {{
    font-size: 28px;
    font-weight: bold;
    color: {COLORS['accent_cyan']};
}}
#stat_label {{
    font-size: 11px;
    color: {COLORS['text_secondary']};
    letter-spacing: 1px;
}}
#status_dot_active {{
    color: {COLORS['accent_green']};
    font-size: 20px;
}}
#status_dot_inactive {{
    color: {COLORS['text_dim']};
    font-size: 20px;
}}
#status_dot_warning {{
    color: {COLORS['accent_orange']};
    font-size: 20px;
}}
"""


# -----------------------------------------------------------------------
# ウィジェットコンポーネント
# -----------------------------------------------------------------------

class StatCard(QFrame):
    """統計値表示カード"""

    def __init__(self, title: str, value: str = "0", color: str = None):
        super().__init__()
        self.setObjectName("card")
        self._color = color or COLORS['accent_cyan']

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(4)

        self._value_label = QLabel(value)
        self._value_label.setObjectName("stat_value")
        self._value_label.setStyleSheet(
            f"color: {self._color}; font-size: 32px; font-weight: bold;"
        )
        self._value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        title_label = QLabel(title.upper())
        title_label.setObjectName("stat_label")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        layout.addWidget(self._value_label)
        layout.addWidget(title_label)

    def set_value(self, value: str) -> None:
        self._value_label.setText(value)


class ApiKeyInput(QWidget):
    """APIキー入力フィールド（表示/非表示トグル付き）"""

    def __init__(self, label: str, placeholder: str = ""):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        lbl = QLabel(label)
        lbl.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 12px;")

        row = QHBoxLayout()
        self._input = QLineEdit()
        self._input.setPlaceholderText(placeholder)
        self._input.setEchoMode(QLineEdit.EchoMode.Password)

        self._toggle_btn = QPushButton("👁")
        self._toggle_btn.setObjectName("btn_secondary")
        self._toggle_btn.setFixedWidth(40)
        self._toggle_btn.setFixedHeight(36)
        self._toggle_btn.setToolTip("表示/非表示")
        self._toggle_btn.clicked.connect(self._toggle_visibility)

        row.addWidget(self._input)
        row.addWidget(self._toggle_btn)

        layout.addWidget(lbl)
        layout.addLayout(row)

    def _toggle_visibility(self) -> None:
        if self._input.echoMode() == QLineEdit.EchoMode.Password:
            self._input.setEchoMode(QLineEdit.EchoMode.Normal)
            self._toggle_btn.setText("🙈")
        else:
            self._input.setEchoMode(QLineEdit.EchoMode.Password)
            self._toggle_btn.setText("👁")

    @property
    def value(self) -> str:
        return self._input.text().strip()

    def set_value(self, v: str) -> None:
        self._input.setText(v)


class LogView(QTextEdit):
    """ターミナル風ログビューア"""

    LOG_COLORS = {
        "DEBUG":   COLORS['text_dim'],
        "INFO":    COLORS['accent_green'],
        "WARNING": COLORS['accent_orange'],
        "ERROR":   COLORS['accent_red'],
        "CRITICAL":COLORS['accent_red'],
    }
    MAX_LINES = 1000

    def __init__(self):
        super().__init__()
        self.setObjectName("log_view")
        self.setReadOnly(True)

    @pyqtSlot(str, str)
    def append_log(self, level: str, message: str) -> None:
        color = self.LOG_COLORS.get(level, COLORS['text_primary'])

        cursor = self.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)

        fmt = QTextCharFormat()
        fmt.setForeground(QColor(color))
        cursor.setCharFormat(fmt)
        cursor.insertText(message + "\n")

        # 最大行数超過時は先頭から削除（メモリ節約）
        doc = self.document()
        if doc.lineCount() > self.MAX_LINES:
            trim_cursor = QTextCursor(doc)
            trim_cursor.movePosition(QTextCursor.MoveOperation.Start)
            trim_cursor.movePosition(
                QTextCursor.MoveOperation.Down,
                QTextCursor.MoveMode.KeepAnchor,
                doc.lineCount() - self.MAX_LINES,
            )
            trim_cursor.removeSelectedText()

        # 自動スクロール（末尾へ）
        self.verticalScrollBar().setValue(
            self.verticalScrollBar().maximum()
        )


# -----------------------------------------------------------------------
# メインウィンドウ
# -----------------------------------------------------------------------

class MainWindow(QMainWindow):

    def __init__(self):
        super().__init__()
        self._worker: PipelineWorker | None = None
        self._scam_records: list[dict] = []

        self.setWindowTitle("🛡️ 詐欺サイト自動検知システム — CYCOT サイバーパトロール")
        self.setMinimumSize(1280, 800)
        self.resize(1400, 900)

        self.setStyleSheet(STYLE_SHEET)
        self._setup_ui()
        self._load_env()
        self._update_status("待機中", "inactive")

    # ------------------------------------------------------------------
    # UI 構築
    # ------------------------------------------------------------------

    def _setup_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # 左サイドバー
        sidebar = self._build_sidebar()
        root.addWidget(sidebar)

        # 右メインエリア（スプリッター）
        main_area = self._build_main_area()
        root.addWidget(main_area, 1)

        # ステータスバー
        self._statusbar = QStatusBar()
        self.setStatusBar(self._statusbar)
        self._status_dot = QLabel("●")
        self._status_dot.setObjectName("status_dot_inactive")
        self._status_text = QLabel("システム待機中")
        self._statusbar.addWidget(self._status_dot)
        self._statusbar.addWidget(self._status_text)

        # スキャン進捗バー
        self._progress = QProgressBar()
        self._progress.setFixedWidth(200)
        self._progress.setValue(0)
        self._statusbar.addPermanentWidget(self._progress)

        # バージョン
        ver_label = QLabel("v1.0.0  |  CYCOT 2026")
        ver_label.setStyleSheet(f"color: {COLORS['text_dim']}; padding-right: 8px;")
        self._statusbar.addPermanentWidget(ver_label)

    def _build_sidebar(self) -> QWidget:
        sidebar = QWidget()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(320)
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)

        # ロゴエリア
        logo_layout = QVBoxLayout()
        logo_layout.setSpacing(4)

        icon_label = QLabel("🛡️")
        icon_label.setStyleSheet("font-size: 40px;")
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        title_label = QLabel("SCAM DETECTOR")
        title_label.setObjectName("label_title")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        sub_label = QLabel("CYCOT サイバーパトロール支援システム")
        sub_label.setObjectName("label_subtitle")
        sub_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sub_label.setWordWrap(True)

        logo_layout.addWidget(icon_label)
        logo_layout.addWidget(title_label)
        logo_layout.addWidget(sub_label)
        layout.addLayout(logo_layout)

        # 区切り線
        layout.addWidget(self._make_separator())

        # API キー設定グループ
        api_group = QGroupBox("🔑 API キー設定")
        api_layout = QVBoxLayout(api_group)
        api_layout.setSpacing(10)

        self._urlscan_input = ApiKeyInput(
            "urlscan.io API キー",
            "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
        )
        self._gemini_input = ApiKeyInput(
            "Gemini API キー",
            "AIzaSy..."
        )
        api_layout.addWidget(self._urlscan_input)
        api_layout.addWidget(self._gemini_input)

        save_btn = QPushButton("💾  キーを保存 (.env)")
        save_btn.setObjectName("btn_secondary")
        save_btn.clicked.connect(self._save_env)
        api_layout.addWidget(save_btn)

        layout.addWidget(api_group)

        # スキャン設定グループ
        scan_group = QGroupBox("⚙️ スキャン設定")
        scan_layout = QGridLayout(scan_group)
        scan_layout.setSpacing(8)

        scan_layout.addWidget(QLabel("最大スキャン数:"), 0, 0)
        self._max_scan_spin = QSpinBox()
        self._max_scan_spin.setRange(1, 5000)
        self._max_scan_spin.setValue(50)
        self._max_scan_spin.setSuffix(" 件")
        scan_layout.addWidget(self._max_scan_spin, 0, 1)

        scan_layout.addWidget(QLabel("Excelテンプレート:"), 1, 0)
        excel_row = QHBoxLayout()
        self._excel_path_input = QLineEdit()
        self._excel_path_input.setPlaceholderText("テンプレート.xls")
        browse_btn = QPushButton("📂")
        browse_btn.setObjectName("btn_secondary")
        browse_btn.setFixedWidth(40)
        browse_btn.clicked.connect(self._browse_excel)
        excel_row.addWidget(self._excel_path_input)
        excel_row.addWidget(browse_btn)
        excel_row.setSpacing(4)
        scan_layout.addLayout(excel_row, 1, 1)

        layout.addWidget(scan_group)

        # 開始/停止ボタン
        self._btn_start = QPushButton("▶  監視開始")
        self._btn_start.setObjectName("btn_start")
        self._btn_start.setMinimumHeight(48)
        self._btn_start.clicked.connect(self._start_pipeline)

        self._btn_stop = QPushButton("■  停止")
        self._btn_stop.setObjectName("btn_stop")
        self._btn_stop.setMinimumHeight(48)
        self._btn_stop.setEnabled(False)
        self._btn_stop.clicked.connect(self._stop_pipeline)

        btn_row = QHBoxLayout()
        btn_row.addWidget(self._btn_start)
        btn_row.addWidget(self._btn_stop)
        layout.addLayout(btn_row)

        # レポート保存ボタン
        self._btn_save_report = QPushButton("📊  Excelレポートを保存")
        self._btn_save_report.setObjectName("btn_save")
        self._btn_save_report.setEnabled(False)
        self._btn_save_report.clicked.connect(self._save_report_csv)
        layout.addWidget(self._btn_save_report)

        # ログクリアボタン
        clear_btn = QPushButton("🗑  ログをクリア")
        clear_btn.setObjectName("btn_secondary")
        clear_btn.clicked.connect(self._clear_log)
        layout.addWidget(clear_btn)

        layout.addStretch()

        # フッター
        footer = QLabel("⚠️ 教育・研究目的のみに使用してください")
        footer.setStyleSheet(
            f"color: {COLORS['accent_orange']}; font-size: 10px;"
        )
        footer.setWordWrap(True)
        footer.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(footer)

        return sidebar

    def _build_main_area(self) -> QWidget:
        area = QWidget()
        layout = QVBoxLayout(area)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # 統計カードエリア
        stats_row = QHBoxLayout()
        stats_row.setSpacing(12)

        self._stat_processed = StatCard("監視済ドメイン", "0", COLORS['text_secondary'])
        self._stat_detected = StatCard("フィルタ通過", "0", COLORS['accent_blue'])
        self._stat_scanned = StatCard("スキャン実行", "0", COLORS['accent_cyan'])
        self._stat_scams = StatCard("詐欺判定", "0", COLORS['accent_red'])

        for card in [self._stat_processed, self._stat_detected,
                     self._stat_scanned, self._stat_scams]:
            stats_row.addWidget(card)

        layout.addLayout(stats_row)

        # タブエリア（ログ + 検出一覧）
        tabs = QTabWidget()

        # タブ1: リアルタイムログ
        log_tab = QWidget()
        log_layout = QVBoxLayout(log_tab)
        log_layout.setContentsMargins(8, 8, 8, 8)
        self._log_view = LogView()
        log_layout.addWidget(self._log_view)
        tabs.addTab(log_tab, "📡  リアルタイムログ")

        # タブ2: 検出一覧
        result_tab = QWidget()
        result_layout = QVBoxLayout(result_tab)
        result_layout.setContentsMargins(8, 8, 8, 8)

        # テーブル操作バー
        table_bar = QHBoxLayout()
        table_title = QLabel(f"🚨  詐欺サイト検出一覧")
        table_title.setStyleSheet(
            f"color: {COLORS['accent_red']}; font-weight: bold; font-size: 14px;"
        )
        self._result_count_label = QLabel("0 件")
        self._result_count_label.setStyleSheet(
            f"color: {COLORS['text_secondary']};"
        )
        export_csv_btn = QPushButton("📥  CSVエクスポート")
        export_csv_btn.setObjectName("btn_secondary")
        export_csv_btn.clicked.connect(self._export_csv)

        table_bar.addWidget(table_title)
        table_bar.addWidget(self._result_count_label)
        table_bar.addStretch()
        table_bar.addWidget(export_csv_btn)

        self._result_table = QTableWidget()
        self._result_table.setColumnCount(6)
        self._result_table.setHorizontalHeaderLabels([
            "検出日時", "ドメイン", "ブランド", "URL", "特徴", "urlscan レポート"
        ])
        self._result_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.ResizeToContents
        )
        self._result_table.horizontalHeader().setSectionResizeMode(
            4, QHeaderView.ResizeMode.Stretch
        )
        self._result_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self._result_table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )
        self._result_table.verticalHeader().setVisible(False)
        self._result_table.setShowGrid(False)
        self._result_table.setAlternatingRowColors(False)

        result_layout.addLayout(table_bar)
        result_layout.addWidget(self._result_table)
        tabs.addTab(result_tab, "🚨  検出一覧 (0)")

        self._tabs = tabs
        layout.addWidget(tabs, 1)

        return area

    def _make_separator(self) -> QFrame:
        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setStyleSheet(f"color: {COLORS['border']};")
        return line

    # ------------------------------------------------------------------
    # 環境変数の読み書き
    # ------------------------------------------------------------------

    def _load_env(self) -> None:
        """起動時に .env から設定を読み込む"""
        env_path = Path(__file__).parent.parent / ".env"
        if not env_path.exists():
            env_path = Path(".env")
        if not env_path.exists():
            return

        env_values = {}
        try:
            with open(env_path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, _, val = line.partition("=")
                    env_values[key.strip()] = val.strip()
        except Exception:
            return

        self._urlscan_input.set_value(env_values.get("URLSCAN_API_KEY", ""))
        self._gemini_input.set_value(env_values.get("GEMINI_API_KEY", ""))
        self._excel_path_input.setText(
            env_values.get(
                "EXCEL_TEMPLATE_PATH",
                "CYCOTサイパト実施結果（京都テック、氏名欄あり）_.xls"
            )
        )
        max_scan = env_values.get("MAX_SCAN_COUNT", "50")
        try:
            self._max_scan_spin.setValue(int(max_scan))
        except ValueError:
            pass

    def _save_env(self) -> None:
        """現在の入力値を .env ファイルに保存する"""
        env_path = Path(__file__).parent.parent / ".env"

        content = (
            f"URLSCAN_API_KEY={self._urlscan_input.value}\n"
            f"GEMINI_API_KEY={self._gemini_input.value}\n"
            f"EXCEL_TEMPLATE_PATH={self._excel_path_input.text()}\n"
            f"MAX_SCAN_COUNT={self._max_scan_spin.value()}\n"
            f"QUEUE_SIZE=500\n"
        )

        try:
            with open(env_path, "w", encoding="utf-8") as f:
                f.write(content)
            self._log_view.append_log("INFO", "✅ APIキーを .env に保存しました")
            QMessageBox.information(self, "保存完了", ".env ファイルを保存しました。")
        except Exception as e:
            QMessageBox.critical(self, "保存エラー", str(e))

    def _browse_excel(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Excelテンプレートを選択",
            str(Path.home()),
            "Excel Files (*.xls *.xlsx)"
        )
        if path:
            self._excel_path_input.setText(path)

    # ------------------------------------------------------------------
    # パイプライン制御
    # ------------------------------------------------------------------

    def _validate_inputs(self) -> bool:
        if not self._urlscan_input.value:
            QMessageBox.warning(
                self, "入力エラー",
                "urlscan.io APIキーを入力してください。\n\n"
                "取得先: https://urlscan.io/user/signup"
            )
            return False
        if not self._gemini_input.value:
            QMessageBox.warning(
                self, "入力エラー",
                "Gemini APIキーを入力してください。\n\n"
                "取得先: https://aistudio.google.com/app/apikey"
            )
            return False
        return True

    def _start_pipeline(self) -> None:
        if not self._validate_inputs():
            return

        self._log_view.clear()
        self._log_view.append_log("INFO", "=" * 60)
        self._log_view.append_log("INFO", "🛡️  詐欺サイト検知システム 起動")
        self._log_view.append_log("INFO", "=" * 60)

        self._worker = PipelineWorker(
            urlscan_api_key=self._urlscan_input.value,
            gemini_api_key=self._gemini_input.value,
            excel_template_path=self._excel_path_input.text(),
            max_scan_count=self._max_scan_spin.value(),
        )

        # シグナル接続
        self._worker.log_emitted.connect(self._log_view.append_log)
        self._worker.scam_detected.connect(self._on_scam_detected)
        self._worker.stats_updated.connect(self._on_stats_updated)
        self._worker.finished_with_result.connect(self._on_finished)
        self._worker.error_occurred.connect(self._on_error)

        self._worker.start()

        # UI 状態更新
        self._btn_start.setEnabled(False)
        self._btn_stop.setEnabled(True)
        self._progress.setRange(0, 0)  # インジケーターモード（無限ループ）
        self._update_status("監視中", "active")

    def _stop_pipeline(self) -> None:
        if self._worker:
            self._worker.request_stop()
            self._log_view.append_log("WARNING", "⏹️  停止リクエストを送信しました...")
        self._btn_stop.setEnabled(False)

    # ------------------------------------------------------------------
    # スロット（シグナル受信）
    # ------------------------------------------------------------------

    @pyqtSlot(dict)
    def _on_scam_detected(self, data: dict) -> None:
        """詐欺サイト検出時にテーブルに行を追加する"""
        self._scam_records.append(data)
        row = self._result_table.rowCount()
        self._result_table.insertRow(row)

        def make_item(text: str, color: str = None) -> QTableWidgetItem:
            item = QTableWidgetItem(str(text))
            item.setFlags(Qt.ItemFlag.ItemIsSelectable | Qt.ItemFlag.ItemIsEnabled)
            if color:
                item.setForeground(QColor(color))
            return item

        self._result_table.setItem(row, 0, make_item(data.get("detected_at", "")))
        self._result_table.setItem(
            row, 1,
            make_item(data.get("domain", ""), COLORS['accent_orange'])
        )
        self._result_table.setItem(
            row, 2,
            make_item(data.get("target_brand", ""), COLORS['accent_red'])
        )
        # URL はテキストのみ（リンク化しない — セキュリティ要件）
        url_item = make_item(data.get("url", ""), COLORS['text_secondary'])
        url_item.setToolTip("URLはセキュリティのためリンク化されていません")
        self._result_table.setItem(row, 3, url_item)
        self._result_table.setItem(row, 4, make_item(data.get("features", "")))
        self._result_table.setItem(
            row, 5,
            make_item(data.get("scan_url", ""), COLORS['accent_blue'])
        )

        # タブのカウントを更新
        count = self._result_table.rowCount()
        self._tabs.setTabText(1, f"🚨  検出一覧 ({count})")
        self._result_count_label.setText(f"{count} 件")

        # 検出があったらレポート保存ボタンを有効化
        self._btn_save_report.setEnabled(True)

        # 検出タブへ自動切り替え
        self._tabs.setCurrentIndex(1)

    @pyqtSlot(dict)
    def _on_stats_updated(self, stats: dict) -> None:
        """統計カードを更新する"""
        self._stat_processed.set_value(f"{stats.get('processed', 0):,}")
        self._stat_detected.set_value(f"{stats.get('accepted', 0):,}")
        self._stat_scanned.set_value(f"{stats.get('scanned', 0):,}")
        self._stat_scams.set_value(f"{stats.get('scams', 0):,}")

        # プログレスバー更新
        scanned = stats.get('scanned', 0)
        max_scan = self._max_scan_spin.value()
        if max_scan > 0:
            self._progress.setRange(0, max_scan)
            self._progress.setValue(scanned)

    @pyqtSlot(str)
    def _on_finished(self, saved_path: str) -> None:
        """パイプライン完了時の処理"""
        self._btn_start.setEnabled(True)
        self._btn_stop.setEnabled(False)
        self._progress.setRange(0, 100)
        self._progress.setValue(100)
        self._update_status("完了", "inactive")

        if saved_path:
            msg = f"✅ 完了！Excelレポートを保存しました:\n{saved_path}"
            self._log_view.append_log("INFO", msg)
            QMessageBox.information(
                self, "検知完了",
                f"処理が完了しました。\n\n📄 Excel保存先:\n{saved_path}"
            )
        else:
            self._log_view.append_log("INFO", "ℹ️  詐欺判定されたサイトはありませんでした")

        self._worker = None

    @pyqtSlot(str)
    def _on_error(self, message: str) -> None:
        """エラー発生時の処理"""
        self._log_view.append_log("ERROR", f"❌ {message}")
        self._btn_start.setEnabled(True)
        self._btn_stop.setEnabled(False)
        self._progress.setRange(0, 100)
        self._progress.setValue(0)
        self._update_status("エラー", "warning")
        QMessageBox.critical(self, "エラー", message)
        self._worker = None

    # ------------------------------------------------------------------
    # その他操作
    # ------------------------------------------------------------------

    def _clear_log(self) -> None:
        self._log_view.clear()

    def _save_report_csv(self) -> None:
        """検出結果を CSV として保存する（簡易エクスポート）"""
        self._export_csv()

    def _export_csv(self) -> None:
        if not self._scam_records:
            QMessageBox.information(self, "情報", "エクスポートするデータがありません。")
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_name = f"scam_report_{timestamp}.csv"

        path, _ = QFileDialog.getSaveFileName(
            self, "CSVレポートを保存", default_name, "CSV Files (*.csv)"
        )
        if not path:
            return

        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as f:
                writer = csv.DictWriter(f, fieldnames=[
                    "detected_at", "domain", "target_brand",
                    "url", "features", "ip_address", "scan_url"
                ])
                writer.writeheader()
                writer.writerows(self._scam_records)
            self._log_view.append_log("INFO", f"📥 CSV エクスポート完了: {path}")
            QMessageBox.information(self, "エクスポート完了", f"保存しました:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "保存エラー", str(e))

    def _update_status(self, text: str, state: str) -> None:
        """ステータスバーのドットと文字を更新する"""
        self._status_text.setText(f"状態: {text}")
        dot_obj = {
            "active": "status_dot_active",
            "warning": "status_dot_warning",
            "inactive": "status_dot_inactive",
        }.get(state, "status_dot_inactive")
        self._status_dot.setObjectName(dot_obj)
        # スタイルシートを再適用してObjectName変更を反映
        self._status_dot.setStyleSheet(self.styleSheet())

    def closeEvent(self, event) -> None:
        """ウィンドウ閉じる時にワーカーを安全に停止"""
        if self._worker and self._worker.isRunning():
            reply = QMessageBox.question(
                self,
                "終了確認",
                "監視が実行中です。終了しますか？\n\n"
                "（停止後、検出済みデータは Excel に自動保存されます）",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if reply == QMessageBox.StandardButton.No:
                event.ignore()
                return
            self._worker.request_stop()
            self._worker.wait(5000)  # 最大5秒待機
        event.accept()


# -----------------------------------------------------------------------
# エントリーポイント
# -----------------------------------------------------------------------

def main() -> None:
    app = QApplication(sys.argv)
    app.setApplicationName("詐欺サイト自動検知システム")
    app.setOrganizationName("CYCOT")

    # Windows での高DPI対応
    app.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )

    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
