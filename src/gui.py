import os
import sys
import csv
import hashlib
import json
import re
import time
import webbrowser
from datetime import datetime
from pathlib import Path
from PyQt6.QtCore import Qt, QTimer, pyqtSlot
from PyQt6.QtGui import QColor, QTextCharFormat, QTextCursor
from PyQt6.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel, QPushButton, QLineEdit, QTextEdit, QTableWidget, QTableWidgetItem, QTabWidget, QFrame, QFileDialog, QMessageBox, QHeaderView, QScrollArea, QSplitter, QSpinBox, QGroupBox, QStatusBar, QProgressBar, QCheckBox, QInputDialog, QComboBox
sys.path.insert(0, str(Path(__file__).parent))
from worker import PipelineWorker
from online_learning import LearningModel, train_challenger
from app_config import (
    DEFAULT_FEATURES,
    DEFAULT_LIMITS,
    DEFAULT_REPORT_OUTPUT_DIR,
    DEFAULT_TEMPLATE_PATH,
)
from key_manager import (
    GEMINI_KEY_NAME,
    SUPABASE_PASSWORD_NAME,
    URLSCAN_KEY_NAME,
    load_all_keys,
    save_api_key,
)
from shared_backend import (
    DEFAULT_SHARED_BACKEND_PATH,
    SharedBackendConfig,
    SharedBackendConfigurationError,
    load_shared_backend_config,
)
COLORS = {'bg_dark': '#0a0e1a', 'bg_panel': '#0f1628', 'bg_card': '#151e35', 'bg_input': '#1a2545', 'accent_cyan': '#00d4ff', 'accent_blue': '#4d9fff', 'accent_green': '#00ff88', 'accent_red': '#ff4757', 'accent_orange': '#ffa502', 'text_primary': '#e8f4f8', 'text_secondary': '#7fa3c0', 'text_dim': '#3d5a78', 'border': '#1e3a5a', 'border_glow': '#00d4ff33'}
PROJECT_ROOT = Path(__file__).resolve().parents[1]
OPTIONAL_FEATURE_TOOLTIPS = {
    'ct': (
        'Certificate Transparency（証明書公開ログ）を監視し、'
        '新しく発行された証明書から不審なドメイン候補を探します。\n'
        '通信量と候補数が増えるため、既定では無効です。'
    ),
    'urlscan_submission': (
        '既存のurlscan.io結果が見つからない場合に、対象URLをurlscan.ioへ送信します。\n'
        '外部サービスへのURL送信とAPI利用枠の消費を伴うため、既定では無効です。'
    ),
    'llm': (
        '取得済みのページ情報をGeminiで補助分析し、候補分類と根拠の整理に利用します。\n'
        '最終判定は行わず、API利用枠を消費するため、既定では無効です。'
    ),
    'automatic_learning': (
        '人が確定したレビューだけを教師データとして学習します。\n'
        '評価基準を通過したモデルだけを次回の監視から候補抽出に使用し、'
        '自動通報や自動確定は行いません。'
    ),
}
SPIN_UP_ICON = (Path(__file__).parent / 'assets' / 'spin-up.svg').as_posix()
SPIN_DOWN_ICON = (Path(__file__).parent / 'assets' / 'spin-down.svg').as_posix()
SCANNING_BANNER = '''
                                                           -=====+==+====-.
                                                     .==#%%%%%##%%%%%%%##%%%#*=-
                                                  -=#%#%##%####%%%%#%%%%####%%##%#==
                                                =##%%%%#%%%%%%%%%%%%%#%%%####%%#%####+-
                                              =%#####%#%%*@%%%%%=+%%#%%%%####%#%##%#%%%#=
                                             -%%%#%##%%%:-%%==#@-:=@%%%###%#%##%####%%%###.
                 .--+==::                    =%%%#%###@::-%::::@:::-%%#%##%##%%#%#%##%%###%
           .+*#%%%@@@@@%%%%#+=                #%%##%%%#:::@#--*%-:::%%%%%#%%#%%##%%%%%%%%%%:
        :*%@%%%%%@@@@@@%%%%%%@@*-              :#####%%+:::=#+%-:::=@%%%%%%%%#%%%%%##%%%%%:
      =#@@@@%%%%%@@@@@%%%%%%%@@@@%=              *%%%%%%##+###*###%@%%%@%%%@%%%@@%%%%%%%.
     *%@@@@@%#%%%%@@@@@%%%%%%@@@@@@*              %@%%@@%%%%%%%%%%%%%%%%%%%%%%%%%%%%@@@%
    #%%@@@%-..-%%%@@@@@%%%%%%@@@@@@%#           +*%##****##%%%%%%%%%%%%%%%%%%%%%%%%%%%%
   #%%%@*:.....:%%@@@@@%%%%%%%@@@@@%%+      .*%*********#%%%%%%%%%%%%%%%%%%%%%%%@@%%@%*
   %%%%:.........-@@@@@%%%%%%%@@@@%%%%      #%%%%%%%%%%%%%%%%%%%%%%%+*=----::..@@@@%%%.
  :%%%.............:@@@%%%%%%%@@@@%%%%=              ....:@@....=@=..........::%@@%%@#
  .%%-...............:#%%%%%%%@@@@%%%%#              ................::::.:::::**-:::::
   %%...................:=%%%%@@@@%%%%%     +%*=*@@@@@@@@*==+%@@@@#=.:::..::::::::::::::
   ##....:+++++......+++++..::#@@@%%%%%    @=.. .==@@@@+....-==@@##.........-:::::::::::.
   -....................:.......:=%%%%   =+....====@@@:...====*@%...........::::::::::.
   .:::.......................:::-=::-   :*..-=====@@@=.-=====#@@@%.........:::::::.
.:::...%#.........-@-...::::::::::::.  **======@@@@@+=====#@@@@+:........-:::::
:::::..%@@-.......-@@*.::::::::::::::    -%@@@@@@@%#*#@@@@@@#*:.:........-...::
.:::::.................::::::::::::..       ........ ...........::.-%%@%#%%..=#%%####.
     ::::::..................::::::=--+         ..:-=*#%*  .....==***:%%#%%%%#%%.%%#%%#####%
      :::.:......:............:.::@@%%%         ######%##     ........%##%%#%%#%%%%%#%%%%%%%%+
       ........................:#@@@@%#         +##%###%##      #%#%%%%%%%%###%%%%%%%%###%%###*
         ........**+*:.......:#%@@@@@%           ##%#%#%#%=   ####%%##%%######%%%%#%%#%%%%###%%
               ...........  :%%%@@@%=            ####%%###%  #%%###%%%%%#%%%#%#%#%%%%%%%#%#####+
            ==:             ===%%*               *#######%#%%##%%%%#%%%%%%%#%##%%%%%#%%#%#######
          -=====...-..:   .=====-                :#######%%%%%%###%#%%%%%%%%##%##%%%#%#%#%%###%%
         ==##******=#  . :========                %%%%%%%%%%%%###%%%%%%%%%%#%#%#%#%%%%##%%%####%
        ===########**  .==========-               -#%###%#####%%##%%%#-*%%###%######%#%#%#####%%
       ====#########*+=============:               *%%%%%##%%%##%#%%%%%%%%%#######%%%##%%###%%%#
      ===-....:#####+*==============                =#%%%%##%%####%%#%#%#%%%%###%%%#%%#%%%%%###%
     .=+:.....:#####+#========+=====:                 -*******=.  -%%%%%%%%%%%%%%%%%%%%%%%%%%#%%
     =*+......:*####*#=======++======                              %###%###%#**%###%###%%#%%%%#%
     ===-.....:*#####*========+======                              %%%###%#%%==%####%#%%#%##%%%#
    :====-...:#######*========+======.                             #%%%%#%%%%%%####%##%####%%%#%
    :=========================+======-                             ##%#%#%##%=-%%%%####%%%#%####
     ========:================++======                             %%%%%##%%%##%%%###%%%%%%%%%%#
      :-==-:  ================++======                             ##%%%%#%%%#%%###%%%%%#%%%%%%#
              ================*+======                             %%%%######*-*%%#%%#%%%%%%%%##.
              ================++======                             ##%%%%%%%####%###%#########%#.
              ================+*======                             *%#%%%%%%%%%%%%%%%#%%####%%%%.
              ================++=====-                             *%%%%%%%%##%%#%%%%%%%%%%%%%%%
'''
STYLE_SHEET = f"\n/* ===== グローバルスタイル ===== */\nQMainWindow, QWidget {{\n    background-color: {COLORS['bg_dark']};\n    color: {COLORS['text_primary']};\n    font-family: 'Segoe UI', 'Meiryo UI', 'Yu Gothic UI', sans-serif;\n    font-size: 13px;\n}}\n\n/* ===== サイドバー ===== */\n#sidebar {{\n    background-color: {COLORS['bg_panel']};\n    border-right: 1px solid {COLORS['border']};\n}}\n\n/* ===== カード ===== */\n#card {{\n    background-color: {COLORS['bg_card']};\n    border: 1px solid {COLORS['border']};\n    border-radius: 8px;\n}}\n\n#scan_banner {{\n    background-color: {COLORS['bg_dark']};\n    color: {COLORS['accent_cyan']};\n    border: 1px solid {COLORS['border']};\n    border-radius: 8px;\n    padding: 8px;\n    font-family: 'Consolas', 'Cascadia Code', 'Meiryo UI', monospace;\n    font-size: 9px;\n    line-height: 1.0;\n}}\n\n/* ===== グループボックス ===== */\nQGroupBox {{\n    background-color: {COLORS['bg_card']};\n    border: 1px solid {COLORS['border']};\n    border-radius: 8px;\n    margin-top: 12px;\n    padding: 12px 8px 8px 8px;\n    font-weight: bold;\n    color: {COLORS['accent_cyan']};\n}}\nQGroupBox::title {{\n    subcontrol-origin: margin;\n    left: 12px;\n    padding: 0 6px;\n}}\n\n/* ===== 入力フィールド ===== */\nQLineEdit, QSpinBox {{\n    background-color: {COLORS['bg_input']};\n    border: 1px solid {COLORS['border']};\n    border-radius: 6px;\n    padding: 7px 10px;\n    color: {COLORS['text_primary']};\n    font-size: 13px;\n}}\nQLineEdit:focus, QSpinBox:focus {{\n    border: 1px solid {COLORS['accent_cyan']};\n}}\n\n/* ===== ボタン共通 ===== */\nQPushButton {{\n    border-radius: 6px;\n    padding: 9px 18px;\n    font-weight: bold;\n    font-size: 13px;\n    border: none;\n}}\nQPushButton:disabled {{\n    opacity: 0.4;\n    background-color: {COLORS['text_dim']};\n    color: {COLORS['bg_dark']};\n}}\n\n/* ===== 開始ボタン ===== */\n#btn_start {{\n    background-color: {COLORS['accent_cyan']};\n    color: {COLORS['bg_dark']};\n}}\n#btn_start:hover {{\n    background-color: #33ddff;\n}}\n#btn_start:pressed {{\n    background-color: #0099cc;\n}}\n\n/* ===== 停止ボタン ===== */\n#btn_stop {{\n    background-color: {COLORS['accent_red']};\n    color: white;\n}}\n#btn_stop:hover {{\n    background-color: #ff6b7a;\n}}\n#btn_stop:pressed {{\n    background-color: #cc2233;\n}}\n\n/* ===== 保存ボタン ===== */\n#btn_save {{\n    background-color: {COLORS['accent_green']};\n    color: {COLORS['bg_dark']};\n}}\n#btn_save:hover {{\n    background-color: #33ffaa;\n}}\n\n/* ===== セカンダリボタン ===== */\n#btn_secondary {{\n    background-color: {COLORS['bg_input']};\n    color: {COLORS['text_primary']};\n    border: 1px solid {COLORS['border']};\n}}\n#btn_secondary:hover {{\n    border-color: {COLORS['accent_cyan']};\n    color: {COLORS['accent_cyan']};\n}}\n\n/* ===== テキストエリア（ログ） ===== */\nQTextEdit#log_view {{\n    background-color: #050810;\n    border: 1px solid {COLORS['border']};\n    border-radius: 8px;\n    font-family: 'Cascadia Code', 'Consolas', 'Courier New', monospace;\n    font-size: 12px;\n    color: {COLORS['accent_green']};\n    padding: 8px;\n}}\n\n/* ===== タブ ===== */\nQTabWidget::pane {{\n    border: 1px solid {COLORS['border']};\n    border-radius: 8px;\n    background-color: {COLORS['bg_panel']};\n}}\nQTabBar::tab {{\n    background-color: {COLORS['bg_card']};\n    color: {COLORS['text_secondary']};\n    padding: 8px 20px;\n    border: none;\n    border-radius: 6px 6px 0 0;\n    margin-right: 2px;\n    font-weight: bold;\n}}\nQTabBar::tab:selected {{\n    background-color: {COLORS['bg_panel']};\n    color: {COLORS['accent_cyan']};\n    border-bottom: 2px solid {COLORS['accent_cyan']};\n}}\nQTabBar::tab:hover:!selected {{\n    color: {COLORS['text_primary']};\n    background-color: {COLORS['bg_input']};\n}}\n\n/* ===== テーブル ===== */\nQTableWidget {{\n    background-color: {COLORS['bg_panel']};\n    border: none;\n    gridline-color: {COLORS['border']};\n    color: {COLORS['text_primary']};\n    selection-background-color: {COLORS['bg_input']};\n}}\nQTableWidget::item {{\n    padding: 8px;\n    border-bottom: 1px solid {COLORS['border']};\n}}\nQTableWidget::item:selected {{\n    background-color: {COLORS['bg_input']};\n    color: {COLORS['accent_cyan']};\n}}\nQHeaderView::section {{\n    background-color: {COLORS['bg_card']};\n    color: {COLORS['accent_cyan']};\n    padding: 8px 12px;\n    border: none;\n    border-bottom: 2px solid {COLORS['accent_cyan']};\n    font-weight: bold;\n    font-size: 12px;\n    letter-spacing: 1px;\n    text-transform: uppercase;\n}}\n\n/* ===== スクロールバー ===== */\nQScrollBar:vertical {{\n    background-color: {COLORS['bg_dark']};\n    width: 8px;\n    border-radius: 4px;\n}}\nQScrollBar::handle:vertical {{\n    background-color: {COLORS['border']};\n    border-radius: 4px;\n    min-height: 30px;\n}}\nQScrollBar::handle:vertical:hover {{\n    background-color: {COLORS['accent_cyan']};\n}}\nQScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{\n    height: 0px;\n}}\n\n/* ===== ステータスバー ===== */\nQStatusBar {{\n    background-color: {COLORS['bg_panel']};\n    border-top: 1px solid {COLORS['border']};\n    color: {COLORS['text_secondary']};\n    font-size: 12px;\n}}\n\n/* ===== プログレスバー ===== */\nQProgressBar {{\n    background-color: {COLORS['bg_input']};\n    border: none;\n    border-radius: 4px;\n    height: 6px;\n    text-align: center;\n}}\nQProgressBar::chunk {{\n    background-color: {COLORS['accent_cyan']};\n    border-radius: 4px;\n}}\n\n/* ===== チェックボックス ===== */\nQCheckBox {{\n    color: {COLORS['text_secondary']};\n    spacing: 8px;\n}}\nQCheckBox::indicator {{\n    width: 16px;\n    height: 16px;\n    border: 1px solid {COLORS['border']};\n    border-radius: 3px;\n    background-color: {COLORS['bg_input']};\n}}\nQCheckBox::indicator:checked {{\n    background-color: {COLORS['accent_cyan']};\n    border-color: {COLORS['accent_cyan']};\n}}\n\n/* ===== ラベル ===== */\n#label_title {{\n    font-size: 18px;\n    font-weight: bold;\n    color: {COLORS['accent_cyan']};\n    letter-spacing: 2px;\n}}\n#label_subtitle {{\n    font-size: 11px;\n    color: {COLORS['text_dim']};\n    letter-spacing: 1px;\n}}\n#stat_value {{\n    font-size: 28px;\n    font-weight: bold;\n    color: {COLORS['accent_cyan']};\n}}\n#stat_label {{\n    font-size: 11px;\n    color: {COLORS['text_secondary']};\n    letter-spacing: 1px;\n}}\n#status_dot_active {{\n    color: {COLORS['accent_green']};\n    font-size: 20px;\n}}\n#status_dot_inactive {{\n    color: {COLORS['text_dim']};\n    font-size: 20px;\n}}\n#status_dot_warning {{\n    color: {COLORS['accent_orange']};\n    font-size: 20px;\n}}\n"

# Settings-field refinements: keep labels on the card surface and make the
# numeric stepper use the same dark control treatment as the other inputs.
STYLE_SHEET += f"""
QLabel#field_label {{
    background-color: transparent;
    color: {COLORS['text_secondary']};
    font-size: 12px;
    font-weight: normal;
}}
QSpinBox::up-button, QSpinBox::down-button {{
    subcontrol-origin: border;
    width: 20px;
    background-color: {COLORS['bg_card']};
    border-left: 1px solid {COLORS['border']};
}}
QSpinBox::up-button {{
    subcontrol-position: top right;
    border-top-right-radius: 5px;
    border-bottom: 1px solid {COLORS['border']};
}}
QSpinBox::down-button {{
    subcontrol-position: bottom right;
    border-bottom-right-radius: 5px;
}}
QSpinBox::up-button:hover, QSpinBox::down-button:hover {{
    background-color: {COLORS['border']};
}}
QSpinBox::up-arrow {{
    image: url("{SPIN_UP_ICON}");
    width: 10px;
    height: 7px;
}}
QSpinBox::down-arrow {{
    image: url("{SPIN_DOWN_ICON}");
    width: 10px;
    height: 7px;
}}
"""

class StatCard(QFrame):

    def __init__(self, title: str, value: str='0', color: str=None):
        super().__init__()
        self.setObjectName('card')
        self._color = color or COLORS['accent_cyan']
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(4)
        self._value_label = QLabel(value)
        self._value_label.setObjectName('stat_value')
        self._value_label.setStyleSheet(f'color: {self._color}; font-size: 32px; font-weight: bold;')
        self._value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label = QLabel(title.upper())
        title_label.setObjectName('stat_label')
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self._value_label)
        layout.addWidget(title_label)

    def set_value(self, value: str) -> None:
        self._value_label.setText(value)

class ApiUsageCard(QFrame):

    def __init__(self, title: str, color: str):
        super().__init__()
        self.setObjectName('card')
        self._color = color
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(4)
        title_label = QLabel(title)
        title_label.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 11px; font-weight: bold;")
        self._value_label = QLabel('未取得')
        self._value_label.setStyleSheet(f'color: {color}; font-size: 18px; font-weight: bold;')
        self._detail_label = QLabel('開始後に自動更新')
        self._detail_label.setStyleSheet(f"color: {COLORS['text_dim']}; font-size: 10px;")
        self._detail_label.setWordWrap(True)
        self._progress = QProgressBar()
        self._progress.setRange(0, 100)
        self._progress.setTextVisible(False)
        self._progress.setFixedHeight(6)
        self._progress.hide()
        layout.addWidget(title_label)
        layout.addWidget(self._value_label)
        layout.addWidget(self._detail_label)
        layout.addWidget(self._progress)

    def set_usage(self, value: str, detail: str, percent: int | None = None,
                  warning: bool = False) -> None:
        color = COLORS['accent_orange'] if warning else self._color
        self._value_label.setText(value)
        self._value_label.setStyleSheet(f'color: {color}; font-size: 18px; font-weight: bold;')
        self._detail_label.setText(detail)
        if percent is None:
            self._progress.hide()
        else:
            self._progress.setValue(max(0, min(100, percent)))
            self._progress.show()

class ApiKeyInput(QWidget):

    def __init__(self, label: str, placeholder: str='', help_url: str | None = None):
        super().__init__()
        self._help_url = help_url
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)
        lbl = QLabel(label)
        lbl.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 12px;")
        row = QHBoxLayout()
        row.setSpacing(8)
        self._input = QLineEdit()
        self._input.setPlaceholderText(placeholder)
        self._input.setEchoMode(QLineEdit.EchoMode.Password)
        self._toggle_btn = QPushButton('👁 表示')
        self._toggle_btn.setObjectName('btn_secondary')
        self._toggle_btn.setMinimumWidth(92)
        self._toggle_btn.setFixedHeight(38)
        self._toggle_btn.setToolTip('表示/非表示')
        self._toggle_btn.clicked.connect(self._toggle_visibility)
        row.addWidget(self._input, 1)
        row.addWidget(self._toggle_btn)
        if self._help_url:
            self._copy_url_btn = QPushButton('コピー')
            self._copy_url_btn.setObjectName('btn_secondary')
            self._copy_url_btn.setMinimumWidth(96)
            self._copy_url_btn.setFixedHeight(38)
            self._copy_url_btn.setToolTip(f'取得URLをコピー: {self._help_url}')
            self._copy_url_btn.clicked.connect(self._copy_help_url)
            self._open_url_btn = QPushButton('開く')
            self._open_url_btn.setObjectName('btn_secondary')
            self._open_url_btn.setMinimumWidth(92)
            self._open_url_btn.setFixedHeight(38)
            self._open_url_btn.setToolTip(f'取得URLをブラウザで開く: {self._help_url}')
            self._open_url_btn.clicked.connect(self._open_help_url)
            row.addWidget(self._copy_url_btn)
            row.addWidget(self._open_url_btn)
        layout.addWidget(lbl)
        layout.addLayout(row)

    def _toggle_visibility(self) -> None:
        if self._input.echoMode() == QLineEdit.EchoMode.Password:
            self._input.setEchoMode(QLineEdit.EchoMode.Normal)
            self._toggle_btn.setText('非表示')
        else:
            self._input.setEchoMode(QLineEdit.EchoMode.Password)
            self._toggle_btn.setText('表示')

    def _copy_help_url(self) -> None:
        if not self._help_url:
            return
        clipboard = QApplication.clipboard()
        clipboard.setText(self._help_url)
        self._copy_url_btn.setText('コピー済み')
        QTimer.singleShot(1200, lambda: self._copy_url_btn.setText('コピー'))

    def _open_help_url(self) -> None:
        if not self._help_url:
            return
        webbrowser.open(self._help_url, new=2)

    @property
    def value(self) -> str:
        return self._input.text().strip()

    def set_value(self, v: str) -> None:
        self._input.setText(v)

class LogView(QTextEdit):
    LOG_COLORS = {'DEBUG': COLORS['text_dim'], 'INFO': COLORS['accent_green'], 'WARNING': COLORS['accent_orange'], 'ERROR': COLORS['accent_red'], 'CRITICAL': COLORS['accent_red']}
    MAX_LINES = 1000

    def __init__(self):
        super().__init__()
        self.setObjectName('log_view')
        self.setReadOnly(True)

    @pyqtSlot(str, str)
    def append_log(self, level: str, message: str) -> None:
        if not re.match(r'^\d{2}:\d{2}:\d{2} \[[A-Z]+\] ', message):
            message = f"{datetime.now().strftime('%H:%M:%S')} [{level.upper()}] {message}"
        color = self.LOG_COLORS.get(level, COLORS['text_primary'])
        cursor = self.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        fmt = QTextCharFormat()
        fmt.setForeground(QColor(color))
        cursor.setCharFormat(fmt)
        cursor.insertText(message + '\n')
        doc = self.document()
        if doc.lineCount() > self.MAX_LINES:
            trim_cursor = QTextCursor(doc)
            trim_cursor.movePosition(QTextCursor.MoveOperation.Start)
            trim_cursor.movePosition(QTextCursor.MoveOperation.Down, QTextCursor.MoveMode.KeepAnchor, doc.lineCount() - self.MAX_LINES)
            trim_cursor.removeSelectedText()
        self.verticalScrollBar().setValue(self.verticalScrollBar().maximum())

class MainWindow(QMainWindow):

    def __init__(self):
        super().__init__()
        self._worker: PipelineWorker | None = None
        self._scam_records: list[dict] = []
        self._last_excel_report_path: str = ''
        self._urlscan_status: dict = {}
        self._gemini_status: dict = {}
        self._learning_status: dict = {'status': '学習データ待ち'}
        self._learning_minimum_per_class = DEFAULT_LIMITS.learning_minimum_per_class
        self._learning_max_examples = DEFAULT_LIMITS.learning_max_examples
        self._scan_workers = 4
        self._shared_backend: SharedBackendConfig | None = None
        self._shared_backend_error = ''
        self.setWindowTitle('詐欺サイト自動検知システム — CYCOT サイバーパトロール')
        self.setMinimumSize(1280, 800)
        self.resize(1400, 900)
        self.setStyleSheet(STYLE_SHEET)
        self._setup_ui()
        self._refresh_shared_backend()
        self._scan_banner.hide()
        self._load_env()
        self._update_status('待機中', 'inactive')
        self._api_status_timer = QTimer(self)
        self._api_status_timer.timeout.connect(self._refresh_api_usage)
        self._api_status_timer.start(1000)

    def _setup_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        sidebar = self._build_sidebar()
        main_area = self._build_main_area()
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(sidebar)
        splitter.addWidget(main_area)
        # Match the reference layout: sidebar ~38%, main content ~62%.
        splitter.setSizes([540, 860])
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setChildrenCollapsible(False)
        splitter.setHandleWidth(8)
        root.addWidget(splitter)
        self._statusbar = QStatusBar()
        self.setStatusBar(self._statusbar)
        self._status_dot = QLabel('●')
        self._status_dot.setObjectName('status_dot_inactive')
        self._status_text = QLabel('システム待機中')
        self._statusbar.addWidget(self._status_dot)
        self._statusbar.addWidget(self._status_text)
        self._progress = QProgressBar()
        self._progress.setFixedWidth(200)
        self._progress.setValue(0)
        self._statusbar.addPermanentWidget(self._progress)
        ver_label = QLabel('v1.0.0  |  CYCOT 2026')
        ver_label.setStyleSheet(f"color: {COLORS['text_dim']}; padding-right: 8px;")
        self._statusbar.addPermanentWidget(ver_label)

    def _build_sidebar(self) -> QWidget:
        sidebar = QWidget()
        sidebar.setObjectName('sidebar')
        sidebar.setMinimumWidth(220)
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)
        logo_layout = QVBoxLayout()
        logo_layout.setSpacing(4)
        icon_label = QLabel('🛡️')
        icon_label.setStyleSheet('font-size: 40px;')
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label = QLabel('SCAM DETECTOR')
        title_label.setObjectName('label_title')
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sub_label = QLabel('CYCOT サイバーパトロール支援システム')
        sub_label.setObjectName('label_subtitle')
        sub_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sub_label.setWordWrap(True)
        logo_layout.addWidget(icon_label)
        logo_layout.addWidget(title_label)
        logo_layout.addWidget(sub_label)
        layout.addLayout(logo_layout)
        layout.addWidget(self._make_separator())
        api_group = QGroupBox('🔑 API キー・ログイン設定')
        api_layout = QVBoxLayout(api_group)
        api_layout.setSpacing(10)
        self._urlscan_input = ApiKeyInput('urlscan.io API キー', 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx', 'https://urlscan.io/user/signup')
        self._gemini_input = ApiKeyInput('Gemini API キー', 'AIzaSy...', 'https://aistudio.google.com/app/apikey')
        api_layout.addWidget(self._urlscan_input)
        api_layout.addWidget(self._gemini_input)
        self._supabase_email_input = QLineEdit()
        self._supabase_email_input.setPlaceholderText('管理者から通知されたログインメール')
        self._supabase_email_input.setToolTip('管理者が事前登録した、このアプリ専用の利用者メールアドレス')
        self._supabase_password_input = ApiKeyInput('Supabase パスワード', 'OS資格情報へ暗号化保存')
        self._shared_backend_status = QLabel('共通Supabase: 設定確認中')
        self._shared_backend_status.setObjectName('field_label')
        self._shared_backend_status.setWordWrap(True)
        api_layout.addWidget(self._shared_backend_status)
        api_layout.addWidget(QLabel('Supabase ログインメール'))
        api_layout.addWidget(self._supabase_email_input)
        api_layout.addWidget(self._supabase_password_input)
        save_btn = QPushButton('💾  認証情報を安全に保存')
        save_btn.setObjectName('btn_secondary')
        save_btn.clicked.connect(self._save_env)
        api_layout.addWidget(save_btn)
        layout.addWidget(api_group)
        scan_group = QGroupBox('⚙️ スキャン設定')
        scan_layout = QGridLayout(scan_group)
        scan_layout.setSpacing(8)
        name_label = QLabel('氏名:')
        name_label.setObjectName('field_label')
        scan_layout.addWidget(name_label, 0, 0)
        self._reporter_name_input = QLineEdit()
        self._reporter_name_input.setPlaceholderText('報告者の氏名を入力')
        self._reporter_name_input.setFixedHeight(38)
        self._reporter_name_input.setToolTip('Excelレポート上部の氏名欄へ記載します')
        scan_layout.addWidget(self._reporter_name_input, 0, 1)
        max_scan_label = QLabel('最大スキャン数:')
        max_scan_label.setObjectName('field_label')
        scan_layout.addWidget(max_scan_label, 1, 0)
        self._max_scan_spin = QSpinBox()
        self._max_scan_spin.setRange(1, 5000)
        self._max_scan_spin.setValue(DEFAULT_LIMITS.max_scan_count)
        self._max_scan_spin.setSuffix(' 件')
        self._max_scan_spin.setFixedHeight(38)
        self._max_scan_spin.setToolTip('1件以上のスキャン数を設定します')
        scan_layout.addWidget(self._max_scan_spin, 1, 1)
        excel_label = QLabel('Excelテンプレート:')
        excel_label.setObjectName('field_label')
        scan_layout.addWidget(excel_label, 2, 0)
        excel_row = QHBoxLayout()
        excel_row.setSpacing(6)
        self._excel_path_input = QLineEdit()
        self._excel_path_input.setPlaceholderText('テンプレート.xlsx')
        self._excel_path_input.setFixedHeight(38)
        self._excel_path_input.setToolTip('Excelテンプレートファイルの保存先')
        browse_btn = QPushButton('📂 テンプレートを選択')
        browse_btn.setObjectName('btn_secondary')
        browse_btn.setMinimumWidth(150)
        browse_btn.setFixedHeight(38)
        browse_btn.setToolTip('Excelテンプレートファイルを選択します')
        browse_btn.clicked.connect(self._browse_excel)
        excel_row.addWidget(self._excel_path_input, 1)
        excel_row.addWidget(browse_btn)
        scan_layout.addLayout(excel_row, 2, 1)
        output_label = QLabel('検出結果の保存先:')
        output_label.setObjectName('field_label')
        scan_layout.addWidget(output_label, 3, 0)
        output_row = QHBoxLayout()
        output_row.setSpacing(6)
        self._report_output_input = QLineEdit()
        self._report_output_input.setPlaceholderText('検出結果')
        self._report_output_input.setFixedHeight(38)
        self._report_output_input.setToolTip('検出後のExcelレポートを保存するフォルダー')
        output_browse_btn = QPushButton('📁 保存先を選択')
        output_browse_btn.setObjectName('btn_secondary')
        output_browse_btn.setMinimumWidth(150)
        output_browse_btn.setFixedHeight(38)
        output_browse_btn.clicked.connect(self._browse_report_output)
        output_row.addWidget(self._report_output_input, 1)
        output_row.addWidget(output_browse_btn)
        scan_layout.addLayout(output_row, 3, 1)
        feature_label = QLabel('任意機能:')
        feature_label.setObjectName('field_label')
        feature_label.setToolTip('各項目へカーソルを合わせると、機能と注意点を確認できます')
        scan_layout.addWidget(feature_label, 4, 0)
        feature_row = QGridLayout()
        self._ct_enabled_check = QCheckBox('CT監視')
        self._urlscan_submit_check = QCheckBox('新規urlscan送信')
        self._llm_enabled_check = QCheckBox('Gemini補助分析')
        self._automatic_learning_check = QCheckBox('自動学習')
        self._ct_enabled_check.setToolTip(OPTIONAL_FEATURE_TOOLTIPS['ct'])
        self._urlscan_submit_check.setToolTip(OPTIONAL_FEATURE_TOOLTIPS['urlscan_submission'])
        self._llm_enabled_check.setToolTip(OPTIONAL_FEATURE_TOOLTIPS['llm'])
        self._automatic_learning_check.setToolTip(OPTIONAL_FEATURE_TOOLTIPS['automatic_learning'])
        for index, checkbox in enumerate((
            self._ct_enabled_check,
            self._urlscan_submit_check,
            self._llm_enabled_check,
            self._automatic_learning_check,
        )):
            checkbox.setToolTipDuration(15000)
            feature_row.addWidget(checkbox, index // 2, index % 2)
        scan_layout.addLayout(feature_row, 4, 1)
        layout.addWidget(scan_group)
        self._btn_start = QPushButton('▶  監視開始')
        self._btn_start.setObjectName('btn_start')
        self._btn_start.setMinimumHeight(48)
        self._btn_start.clicked.connect(self._start_pipeline)
        self._btn_stop = QPushButton('■  停止')
        self._btn_stop.setObjectName('btn_stop')
        self._btn_stop.setMinimumHeight(48)
        self._btn_stop.setEnabled(False)
        self._btn_stop.clicked.connect(self._stop_pipeline)
        btn_row = QHBoxLayout()
        btn_row.addWidget(self._btn_start)
        btn_row.addWidget(self._btn_stop)
        layout.addLayout(btn_row)
        self._btn_save_report = QPushButton('📊  Excelレポートを保存')
        self._btn_save_report.setObjectName('btn_save')
        self._btn_save_report.setToolTip('「疑いが強い」または「資料作成済み」にした候補をExcelへ保存します')
        self._btn_save_report.clicked.connect(self._save_excel_report)
        layout.addWidget(self._btn_save_report)
        clear_btn = QPushButton('🗑  ログをクリア')
        clear_btn.setObjectName('btn_secondary')
        clear_btn.clicked.connect(self._clear_log)
        layout.addWidget(clear_btn)
        layout.addStretch()
        footer = QLabel('⚠️ 教育・研究目的のみに使用してください')
        footer.setStyleSheet(f"color: {COLORS['accent_orange']}; font-size: 10px;")
        footer.setWordWrap(True)
        footer.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(footer)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setWidget(sidebar)
        scroll.setMinimumWidth(220)
        return scroll

    def _build_main_area(self) -> QWidget:
        area = QWidget()
        layout = QVBoxLayout(area)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)
        stats_row = QHBoxLayout()
        stats_row.setSpacing(12)
        self._stat_processed = StatCard('監視済ドメイン', '0', COLORS['text_secondary'])
        self._stat_detected = StatCard('フィルタ通過', '0', COLORS['accent_blue'])
        self._stat_scanned = StatCard('スキャン実行', '0', COLORS['accent_cyan'])
        self._stat_scams = StatCard('レビュー候補', '0', COLORS['accent_red'])
        for card in [self._stat_processed, self._stat_detected, self._stat_scanned, self._stat_scams]:
            stats_row.addWidget(card)
        layout.addLayout(stats_row)
        self._operations_summary = QLabel('ソース別 －  |  重複率 0%  |  有用候補 0  |  滞留 0')
        self._operations_summary.setStyleSheet(
            f"color: {COLORS['text_secondary']}; background: {COLORS['bg_card']}; "
            f"border: 1px solid {COLORS['border']}; border-radius: 6px; padding: 6px 10px;"
        )
        layout.addWidget(self._operations_summary)
        api_row = QHBoxLayout()
        api_row.setSpacing(12)
        self._urlscan_usage = ApiUsageCard('URLSCAN.IO API 制限', COLORS['accent_blue'])
        self._urlscan_usage.setToolTip('urlscan.io が応答ヘッダで返す現在の制限値です')
        self._gemini_usage = ApiUsageCard('GEMINI API 使用量', COLORS['accent_green'])
        self._gemini_usage.setToolTip('Geminiの上限はモデルとプロジェクトTierによって異なります')
        api_row.addWidget(self._urlscan_usage)
        api_row.addWidget(self._gemini_usage)
        layout.addLayout(api_row)
        self._scan_banner = QLabel(SCANNING_BANNER)
        self._scan_banner.setObjectName('scan_banner')
        self._scan_banner.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._scan_banner.setVisible(False)
        self._scan_banner.setTextFormat(Qt.TextFormat.PlainText)
        self._scan_banner.setWordWrap(False)
        self._scan_banner.setMinimumHeight(260)
        layout.addWidget(self._scan_banner)
        tabs = QTabWidget()
        log_tab = QWidget()
        log_layout = QVBoxLayout(log_tab)
        log_layout.setContentsMargins(8, 8, 8, 8)
        self._log_view = LogView()
        log_layout.addWidget(self._log_view)
        log_button_row = QHBoxLayout()
        log_button_row.addStretch()
        export_log_btn = QPushButton('URLログをExcelで保存')
        export_log_btn.setObjectName('btn_secondary')
        export_log_btn.setToolTip('フィルタ通過URLとスキャン対象URLを、読みやすい2シートのExcelへ保存します')
        export_log_btn.clicked.connect(self._export_url_logs_excel)
        log_button_row.addWidget(export_log_btn)
        log_layout.addLayout(log_button_row)
        tabs.addTab(log_tab, '📡  リアルタイムログ')
        result_tab = QWidget()
        result_layout = QVBoxLayout(result_tab)
        result_layout.setContentsMargins(8, 8, 8, 8)
        table_bar = QHBoxLayout()
        table_title = QLabel('🚨  不審サイト・レビュー候補')
        table_title.setStyleSheet(f"color: {COLORS['accent_red']}; font-weight: bold; font-size: 14px;")
        self._result_count_label = QLabel('0 件')
        self._result_count_label.setStyleSheet(f"color: {COLORS['text_secondary']};")
        export_csv_btn = QPushButton('📥  CSVエクスポート')
        export_csv_btn.setObjectName('btn_secondary')
        export_csv_btn.clicked.connect(self._export_csv)
        self._review_action = QComboBox()
        for label, status in (
            ('調査中', 'investigating'),
            ('問題なし', 'no_issue'),
            ('疑いが強い', 'strong_suspicion'),
            ('判定不能', 'inconclusive'),
            ('資料作成済み', 'report_prepared'),
            ('対応確認済み', 'response_verified'),
        ):
            self._review_action.addItem(label, status)
        review_btn = QPushButton('✓  状態を更新')
        review_btn.setObjectName('btn_secondary')
        review_btn.clicked.connect(self._apply_selected_review)
        table_bar.addWidget(table_title)
        table_bar.addWidget(self._result_count_label)
        table_bar.addStretch()
        table_bar.addWidget(self._review_action)
        table_bar.addWidget(review_btn)
        table_bar.addWidget(export_csv_btn)
        filter_bar = QHBoxLayout()
        filter_bar.addWidget(QLabel('絞り込み:'))
        self._category_filter = QComboBox()
        self._category_filter.addItems(['分類: すべて', 'phishing', 'fraudulent_ec', 'suspected_counterfeit'])
        self._priority_filter = QComboBox()
        self._priority_filter.addItems(['優先度: すべて', '通常', '要確認', '高', '緊急'])
        self._review_filter = QComboBox()
        self._review_filter.addItems([
            'レビュー: すべて', '未レビュー', '調査中', '問題なし',
            '疑いが強い', '判定不能', '資料作成済み', '対応確認済み'
        ])
        self._brand_filter = QLineEdit()
        self._brand_filter.setPlaceholderText('ブランド検索')
        self._brand_filter.setMaximumWidth(180)
        self._source_filter = QComboBox()
        self._source_filter.addItems(['出典: すべて', 'OpenPhish', 'CT', 'urlscan'])
        self._date_filter = QLineEdit()
        self._date_filter.setPlaceholderText('発見日 YYYY-MM-DD')
        self._date_filter.setMaximumWidth(140)
        for widget in (
            self._category_filter, self._priority_filter,
            self._review_filter, self._source_filter,
        ):
            widget.currentIndexChanged.connect(self._apply_result_filters)
            filter_bar.addWidget(widget)
        self._brand_filter.textChanged.connect(self._apply_result_filters)
        self._date_filter.textChanged.connect(self._apply_result_filters)
        filter_bar.addWidget(self._brand_filter)
        filter_bar.addWidget(self._date_filter)
        filter_bar.addStretch()
        self._result_table = QTableWidget()
        self._result_table.setColumnCount(13)
        self._result_table.setHorizontalHeaderLabels([
            '初回発見', '最終観測', 'ドメイン', 'ブランド', '分類', '優先度',
            '情報充足度', '出典', 'レビュー状態', 'URL', '根拠', 'urlscan レポート', '候補ID'
        ])
        self._result_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self._result_table.horizontalHeader().setSectionResizeMode(10, QHeaderView.ResizeMode.Stretch)
        self._result_table.setColumnHidden(12, True)
        self._result_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._result_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._result_table.verticalHeader().setVisible(False)
        self._result_table.setShowGrid(False)
        self._result_table.setAlternatingRowColors(False)
        self._result_table.cellDoubleClicked.connect(self._show_candidate_details)
        result_layout.addLayout(table_bar)
        result_layout.addLayout(filter_bar)
        result_layout.addWidget(self._result_table)
        tabs.addTab(result_tab, '🚨  検出一覧 (0)')
        self._tabs = tabs
        layout.addWidget(tabs, 1)
        return area

    def _make_separator(self) -> QFrame:
        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setStyleSheet(f"color: {COLORS['border']};")
        return line

    def _refresh_shared_backend(self) -> bool:
        try:
            self._shared_backend = load_shared_backend_config()
            self._shared_backend_error = ''
            self._shared_backend_status.setText(
                f'共通Supabase: {self._shared_backend.display_name}（接続設定済み）'
            )
            self._shared_backend_status.setStyleSheet(
                f"color: {COLORS['accent_green']}; font-size: 12px;"
            )
            self._shared_backend_status.setToolTip(
                'Project URLとPublishable keyは管理者が共通設定済みです。'
                '利用者が入力する必要はありません。'
            )
            return True
        except SharedBackendConfigurationError as exc:
            self._shared_backend = None
            self._shared_backend_error = str(exc)
            self._shared_backend_status.setText('共通Supabase: 管理者設定待ち')
            self._shared_backend_status.setStyleSheet(
                f"color: {COLORS['accent_orange']}; font-size: 12px;"
            )
            self._shared_backend_status.setToolTip(
                f'{exc}\n設定ファイル: {DEFAULT_SHARED_BACKEND_PATH}'
            )
            return False

    def _load_env(self) -> None:
        saved_keys = load_all_keys()
        urlscan_val = saved_keys.get(URLSCAN_KEY_NAME, "")
        gemini_val = saved_keys.get(GEMINI_KEY_NAME, "")
        supabase_password_val = saved_keys.get(SUPABASE_PASSWORD_NAME, "")

        env_path = Path(__file__).parent.parent / '.env'
        if not env_path.exists():
            env_path = Path('.env')
        env_values = {}
        if env_path.exists():
            try:
                with open(env_path, encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith('#') or '=' not in line:
                            continue
                        key, _, val = line.partition('=')
                        env_values[key.strip()] = val.strip()
            except Exception:
                pass

        self._urlscan_input.set_value(urlscan_val or env_values.get('URLSCAN_API_KEY', ''))
        self._gemini_input.set_value(gemini_val or env_values.get('GEMINI_API_KEY', ''))
        self._supabase_email_input.setText(env_values.get('SUPABASE_EMAIL', ''))
        self._supabase_password_input.set_value(supabase_password_val or env_values.get('SUPABASE_PASSWORD', ''))
        self._excel_path_input.setText(env_values.get('EXCEL_TEMPLATE_PATH', DEFAULT_TEMPLATE_PATH))
        self._report_output_input.setText(env_values.get('REPORT_OUTPUT_DIR', DEFAULT_REPORT_OUTPUT_DIR))
        self._reporter_name_input.setText(env_values.get('REPORTER_NAME', ''))
        max_scan = env_values.get('MAX_SCAN_COUNT', str(DEFAULT_LIMITS.max_scan_count))
        try:
            self._max_scan_spin.setValue(int(max_scan))
        except ValueError:
            pass
        try:
            self._scan_workers = max(1, min(int(env_values.get('SCAN_WORKERS', str(DEFAULT_LIMITS.scan_workers))), 8))
        except ValueError:
            self._scan_workers = DEFAULT_LIMITS.scan_workers
        def checked(name: str, default: bool) -> bool:
            return env_values.get(name, str(default)).strip().casefold() in {
                '1', 'true', 'yes', 'on', 'enabled'
            }
        self._ct_enabled_check.setChecked(checked('CT_ENABLED', DEFAULT_FEATURES.ct_enabled))
        self._urlscan_submit_check.setChecked(checked(
            'URLSCAN_SUBMISSION_ENABLED', DEFAULT_FEATURES.urlscan_submission_enabled
        ))
        self._llm_enabled_check.setChecked(checked('LLM_ENABLED', DEFAULT_FEATURES.llm_enabled))
        self._automatic_learning_check.setChecked(checked(
            'AUTOMATIC_LEARNING_ENABLED', DEFAULT_FEATURES.automatic_learning_enabled
        ))
        try:
            self._learning_minimum_per_class = max(
                5,
                int(env_values.get(
                    'LEARNING_MINIMUM_PER_CLASS',
                    str(DEFAULT_LIMITS.learning_minimum_per_class),
                )),
            )
        except ValueError:
            self._learning_minimum_per_class = DEFAULT_LIMITS.learning_minimum_per_class
        try:
            self._learning_max_examples = max(
                100,
                min(
                    int(env_values.get(
                        'LEARNING_MAX_EXAMPLES',
                        str(DEFAULT_LIMITS.learning_max_examples),
                    )),
                    100_000,
                ),
            )
        except ValueError:
            self._learning_max_examples = DEFAULT_LIMITS.learning_max_examples

    def _save_env(self) -> None:
        u_key = self._urlscan_input.value
        g_key = self._gemini_input.value
        s_password = self._supabase_password_input.value

        saved = [
            save_api_key(URLSCAN_KEY_NAME, u_key),
            save_api_key(SUPABASE_PASSWORD_NAME, s_password),
        ]
        if g_key:
            saved.append(save_api_key(GEMINI_KEY_NAME, g_key))
        if not all(saved):
            QMessageBox.critical(self, '保存エラー', 'OSの資格情報マネージャーへ保存できませんでした。秘密情報は平文保存していません。')
            return

        env_path = Path(__file__).parent.parent / '.env'
        content = (
            'URLSCAN_API_KEY=\nGEMINI_API_KEY=\nSUPABASE_PASSWORD=\n'
            f'SUPABASE_EMAIL={self._supabase_email_input.text().strip()}\n'
            f'REPORTER_NAME={self._reporter_name_input.text().strip()}\n'
            f'EXCEL_TEMPLATE_PATH={self._excel_path_input.text()}\n'
            f'REPORT_OUTPUT_DIR={self._report_output_input.text().strip()}\n'
            f'MAX_SCAN_COUNT={self._max_scan_spin.value()}\n'
            f'QUEUE_SIZE={DEFAULT_LIMITS.queue_size}\nSCAN_WORKERS={self._scan_workers}\n'
            f'CT_ENABLED={str(self._ct_enabled_check.isChecked()).lower()}\n'
            'PHISHING_FEED_ENABLED=true\n'
            f'URLSCAN_SUBMISSION_ENABLED={str(self._urlscan_submit_check.isChecked()).lower()}\n'
            f'LLM_ENABLED={str(self._llm_enabled_check.isChecked()).lower()}\n'
            f'AUTOMATIC_LEARNING_ENABLED={str(self._automatic_learning_check.isChecked()).lower()}\n'
            f'LEARNING_MINIMUM_PER_CLASS={self._learning_minimum_per_class}\n'
            f'LEARNING_MAX_EXAMPLES={self._learning_max_examples}\n'
            'SIMILARITY_ENABLED=false\nAUTOMATIC_REPORTING_ENABLED=false\n'
        )
        try:
            with open(env_path, 'w', encoding='utf-8') as f:
                f.write(content)
            self._log_view.append_log('INFO', '🔒 秘密情報をOS資格情報へ暗号化保存しました（.envへは保存していません）')
            QMessageBox.information(self, '保存完了', 'APIキーとパスワードをOSの資格情報マネージャーに保存しました。')
        except Exception as e:
            QMessageBox.critical(self, '保存エラー', str(e))

    def _browse_excel(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, 'Excelテンプレートを選択', str(Path.home()), 'Excel Files (*.xls *.xlsx)')
        if path:
            self._excel_path_input.setText(path)

    def _browse_report_output(self) -> None:
        current = self._report_output_input.text().strip()
        initial = current if current and Path(current).is_absolute() else str(Path.home())
        path = QFileDialog.getExistingDirectory(self, '検出結果の保存先を選択', initial)
        if path:
            self._report_output_input.setText(path)

    def _validate_inputs(self) -> bool:
        if not self._reporter_name_input.text().strip():
            QMessageBox.warning(self, '入力エラー', 'Excelレポートへ記載する氏名を入力してください。')
            self._reporter_name_input.setFocus()
            return False
        if not self._urlscan_input.value:
            QMessageBox.warning(self, '入力エラー', 'urlscan.io APIキーを入力してください。\n\n取得先: https://urlscan.io/user/signup')
            return False
        if self._llm_enabled_check.isChecked() and not self._gemini_input.value:
            QMessageBox.warning(self, '入力エラー', 'Gemini APIキーを入力してください。\n\n取得先: https://aistudio.google.com/app/apikey')
            return False
        if not self._refresh_shared_backend():
            QMessageBox.warning(
                self,
                '管理者設定エラー',
                '共通Supabaseへ接続する準備が完了していません。\n'
                '管理者へ連絡してください。\n\n'
                f'{self._shared_backend_error}\n\n設定ファイル: {DEFAULT_SHARED_BACKEND_PATH}',
            )
            return False
        if not self._supabase_email_input.text().strip():
            QMessageBox.warning(self, '入力エラー', '管理者から通知されたログインメールを入力してください。')
            return False
        if not self._supabase_password_input.value:
            QMessageBox.warning(self, '入力エラー', 'Supabaseログインパスワードを入力してください。')
            return False
        if not self._excel_path_input.text().strip():
            QMessageBox.warning(self, '入力エラー', 'Excelテンプレートを選択してください。')
            return False
        if not self._report_output_input.text().strip():
            QMessageBox.warning(self, '入力エラー', '検出結果の保存先を選択してください。')
            return False
        template_path = self._resolve_local_path(self._excel_path_input.text().strip())
        if not template_path.is_file():
            QMessageBox.warning(
                self, '入力エラー', f'Excelテンプレートが見つかりません。\n\n{template_path}'
            )
            return False
        if template_path.suffix.lower() not in ('.xls', '.xlsx', '.xlsm'):
            QMessageBox.warning(self, '入力エラー', 'Excelテンプレートは.xls、.xlsx、.xlsmを選択してください。')
            return False
        output_dir = self._resolve_local_path(self._report_output_input.text().strip())
        try:
            output_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            QMessageBox.warning(
                self, '入力エラー', f'検出結果の保存先を作成できません。\n\n{output_dir}\n{exc}'
            )
            return False
        if not output_dir.is_dir():
            QMessageBox.warning(self, '入力エラー', f'検出結果の保存先がフォルダーではありません。\n\n{output_dir}')
            return False
        return True

    @staticmethod
    def _resolve_local_path(value: str) -> Path:
        path = Path(value).expanduser()
        return path.resolve() if path.is_absolute() else (PROJECT_ROOT / path).resolve()

    def _start_pipeline(self) -> None:
        if not self._validate_inputs():
            return

        self._last_excel_report_path = ''
        save_api_key(URLSCAN_KEY_NAME, self._urlscan_input.value)
        save_api_key(GEMINI_KEY_NAME, self._gemini_input.value)
        save_api_key(SUPABASE_PASSWORD_NAME, self._supabase_password_input.value)

        shared_backend = self._shared_backend
        if shared_backend is None:
            QMessageBox.warning(self, '管理者設定エラー', '共通Supabase設定を読み込めません。')
            return

        self._scan_banner.show()
        self._scan_banner.raise_()
        self._scan_banner.setVisible(True)
        self._tabs.setCurrentIndex(0)
        self._log_view.clear()
        self._log_view.append_log('INFO', '=' * 60)
        self._log_view.append_log('INFO', '🛡️  詐欺サイト検知システム 起動')
        self._log_view.append_log('INFO', '=' * 60)
        self._worker = PipelineWorker(
            urlscan_api_key=self._urlscan_input.value,
            gemini_api_key=self._gemini_input.value,
            max_scan_count=self._max_scan_spin.value(),
            supabase_url=shared_backend.project_url,
            supabase_publishable_key=shared_backend.publishable_key,
            supabase_email=self._supabase_email_input.text().strip(),
            supabase_password=self._supabase_password_input.value,
            supabase_allowed_custom_host=shared_backend.allowed_custom_host,
            scan_workers=self._scan_workers,
            urlscan_submission_enabled=self._urlscan_submit_check.isChecked(),
            ct_enabled=self._ct_enabled_check.isChecked(),
            phishing_feed_enabled=True,
            llm_enabled=self._llm_enabled_check.isChecked(),
            automatic_learning_enabled=self._automatic_learning_check.isChecked(),
        )

        self._worker.log_emitted.connect(self._on_worker_log)
        self._worker.scam_detected.connect(self._on_scam_detected)
        self._worker.stats_updated.connect(self._on_stats_updated)
        self._worker.finished_with_result.connect(self._on_finished)
        self._worker.error_occurred.connect(self._on_error)
        self._worker.start()
        self._btn_start.setEnabled(False)
        self._btn_stop.setEnabled(True)
        self._progress.setRange(0, 0)
        self._update_status('監視中', 'active')

    @pyqtSlot(str, str)
    def _on_worker_log(self, level: str, message: str) -> None:
        self._log_view.append_log(level, message)
        if self._scan_banner.isVisible():
            self._scan_banner.setVisible(False)
            self._tabs.setCurrentIndex(0)
            self._log_view.setFocus()

    def _stop_pipeline(self) -> None:
        if self._worker:
            self._worker.request_stop()
            self._log_view.append_log('WARNING', '⏹️  停止リクエストを送信しました...')
        self._scan_banner.setVisible(False)
        self._btn_stop.setEnabled(False)

    @pyqtSlot(dict)
    def _on_scam_detected(self, data: dict) -> None:
        self._scam_records.append(data)
        row = self._result_table.rowCount()
        self._result_table.insertRow(row)

        def make_item(text: str, color: str=None) -> QTableWidgetItem:
            item = QTableWidgetItem(str(text))
            item.setFlags(Qt.ItemFlag.ItemIsSelectable | Qt.ItemFlag.ItemIsEnabled)
            if color:
                item.setForeground(QColor(color))
            return item
        self._result_table.setItem(row, 0, make_item(data.get('first_seen_at', data.get('detected_at', ''))))
        self._result_table.setItem(row, 1, make_item(data.get('last_observed_at', '') or '未観測'))
        self._result_table.setItem(row, 2, make_item(data.get('domain', ''), COLORS['accent_orange']))
        self._result_table.setItem(row, 3, make_item(data.get('target_brand', ''), COLORS['accent_red']))
        self._result_table.setItem(row, 4, make_item(data.get('category', ''), COLORS['accent_cyan']))
        risk_text = f"{data.get('priority_label', '通常')} ({data.get('risk_score', 0)}点)"
        learning_probability = data.get('learning_probability')
        if isinstance(learning_probability, (int, float)):
            risk_text += f" / 学習 {learning_probability:.0%}"
        risk_color = COLORS['accent_red'] if data.get('priority') in ('urgent', 'high') else COLORS['accent_orange']
        self._result_table.setItem(row, 5, make_item(risk_text, risk_color))
        self._result_table.setItem(row, 6, make_item(data.get('completeness_label', '情報不足')))
        self._result_table.setItem(row, 7, make_item(data.get('source', '')))
        self._result_table.setItem(row, 8, make_item(data.get('review_status_label', '未レビュー'), COLORS['accent_orange']))
        url_item = make_item(data.get('url', ''), COLORS['text_secondary'])
        url_item.setToolTip('URLはセキュリティのためリンク化されていません')
        self._result_table.setItem(row, 9, url_item)
        evidence = data.get('features', '')
        if data.get('missing_evidence'):
            evidence = f"{evidence}; 不足={data['missing_evidence']}"
        self._result_table.setItem(row, 10, make_item(evidence))
        self._result_table.setItem(row, 11, make_item(data.get('scan_url', ''), COLORS['accent_blue']))
        self._result_table.setItem(row, 12, make_item(data.get('candidate_id', '')))
        count = self._result_table.rowCount()
        self._tabs.setTabText(1, f'🚨  検出一覧 ({count})')
        self._result_count_label.setText(f'{count} 件')
        self._tabs.setCurrentIndex(1)
        self._apply_result_filters()

    def _set_review_status(self, status: str, label: str) -> None:
        rows = sorted({index.row() for index in self._result_table.selectedIndexes()})
        if not rows:
            QMessageBox.information(self, 'レビュー', '判定する行を選択してください。')
            return
        reason, accepted = QInputDialog.getMultiLineText(
            self,
            'レビュー理由',
            f'「{label}」と判断した理由（必須）:',
        )
        if not accepted:
            return
        reason = reason.strip()
        if not reason:
            QMessageBox.warning(self, '入力エラー', 'レビュー理由は必須です。')
            return
        repository = None
        reviewed_rows: list[int] = []
        review_failures: list[str] = []
        try:
            from supabase_repository import SupabaseRepository
            if not self._refresh_shared_backend() or self._shared_backend is None:
                raise RuntimeError(
                    f'共通Supabase設定を読み込めません: {self._shared_backend_error}'
                )
            repository = SupabaseRepository(
                self._shared_backend.project_url,
                self._shared_backend.publishable_key,
                self._supabase_email_input.text().strip(),
                self._supabase_password_input.value,
                allowed_custom_host=self._shared_backend.allowed_custom_host,
            )
            repository.connect()
            for row in rows:
                if row >= len(self._scam_records):
                    continue
                record = self._scam_records[row]
                candidate_id = record.get('candidate_id', '')
                if not candidate_id:
                    review_failures.append(f'{row + 1}行目: 候補IDなし')
                    continue
                try:
                    record['review_version'] = repository.submit_review(
                        candidate_id,
                        status,
                        reason,
                        evidence_refs=[record.get('scan_url', '')],
                        expected_version=int(record.get('review_version', 0)),
                    )
                    reviewed_rows.append(row)
                except Exception as row_exc:
                    review_failures.append(f'{row + 1}行目: {row_exc}')
            if not reviewed_rows:
                raise RuntimeError('\n'.join(review_failures) or '保存対象がありません')
            if self._automatic_learning_check.isChecked():
                try:
                    self._run_automatic_learning(repository, reviewed_rows, status)
                except Exception as learning_exc:
                    self._learning_status = {'status': '学習DB更新待ち'}
                    self._log_view.append_log(
                        'WARNING',
                        '⚠️ レビューは保存済みですが自動学習は見送りました。'
                        '202609060001_shared_trusted_learning.sql の適用を確認してください: '
                        f'{learning_exc}',
                    )
        except Exception as exc:
            QMessageBox.critical(
                self, 'レビュー保存エラー',
                f'Supabaseへレビュー履歴を保存できませんでした。\n'
                f'利用者の許可登録と最新マイグレーションを確認してください。\n\n{exc}'
            )
            return
        finally:
            if repository is not None:
                repository.close()
        reviewed_at = datetime.now().astimezone().isoformat(timespec='seconds')
        for row in reviewed_rows:
            if row >= len(self._scam_records):
                continue
            record = self._scam_records[row]
            record['review_status'] = status
            record['review_status_label'] = label
            record['review_reason'] = reason
            record['reviewer'] = self._reporter_name_input.text().strip()
            record['reviewed_at'] = reviewed_at
            item = self._result_table.item(row, 8)
            if item:
                item.setText(label)
                item.setForeground(QColor(
                    COLORS['accent_red'] if status == 'strong_suspicion'
                    else COLORS['accent_green']
                ))
        self._last_excel_report_path = ''
        self._btn_save_report.setEnabled(True)
        self._log_view.append_log(
            'INFO', f'👤 人手レビューを記録: {label} ({len(reviewed_rows)}件)'
        )
        if review_failures:
            QMessageBox.warning(
                self,
                '一部保存エラー',
                f'{len(reviewed_rows)}件は保存しましたが、{len(review_failures)}件は保存できませんでした。\n\n'
                + '\n'.join(review_failures[:5]),
            )
        self._apply_result_filters()

    def _run_automatic_learning(self, repository, rows: list[int], status: str) -> None:
        if status not in ('no_issue', 'strong_suspicion', 'report_prepared', 'response_verified'):
            self._learning_status = {'status': '確定ラベル待ち'}
            return

        recorded = 0
        for row in rows:
            if row >= len(self._scam_records):
                continue
            record = self._scam_records[row]
            features = record.get('learning_features')
            if not isinstance(features, dict) or not features:
                continue
            if repository.record_learning_example(
                record.get('candidate_id', ''),
                int(record.get('review_version', 0)),
                record.get('category', ''),
                features,
            ):
                recorded += 1
        if not recorded:
            self._learning_status = {'status': '特徴量データ待ち'}
            return

        examples = repository.get_learning_examples(self._learning_max_examples)
        current_model = LearningModel.from_dict(repository.get_active_learning_model())
        result = train_challenger(
            examples,
            current_model,
            minimum_per_class=self._learning_minimum_per_class,
        )
        positives = int(result.metrics.get('positive', 0) or 0)
        negatives = int(result.metrics.get('negative', 0) or 0)
        if not result.promoted or result.model is None:
            if result.model is None:
                status_text = f'例待ち +{positives}/-{negatives}'
            else:
                challenger_f1 = float(result.metrics.get('challenger_f1', 0) or 0)
                status_text = f'評価保留 F1 {challenger_f1:.2f}'
            self._learning_status = {
                'status': status_text,
                'model_version': current_model.model_version if current_model else '',
            }
            self._log_view.append_log('INFO', f'🧠 自動学習: {result.reason}')
            return

        version = repository.publish_learning_model(
            result.model.as_dict(),
            result.metrics,
            expected_parent_version=current_model.model_version if current_model else '',
        )
        self._learning_status = {
            'status': f'更新済み ({len(examples)}件)',
            'model_version': version,
        }
        precision = float(result.metrics.get('challenger_precision', 0) or 0)
        recall = float(result.metrics.get('challenger_recall', 0) or 0)
        self._log_view.append_log(
            'INFO',
            f'🧠 新しい学習モデルを採用: {version} '
            f'(適合率 {precision:.1%} / 再現率 {recall:.1%})。次回監視から使用します',
        )

    def _apply_selected_review(self) -> None:
        self._set_review_status(
            str(self._review_action.currentData()),
            self._review_action.currentText(),
        )

    def _apply_result_filters(self, *_args) -> None:
        category = self._category_filter.currentText()
        priority = self._priority_filter.currentText()
        review = self._review_filter.currentText()
        source = self._source_filter.currentText()
        brand = self._brand_filter.text().strip().casefold()
        discovered_date = self._date_filter.text().strip()
        for row, record in enumerate(self._scam_records):
            visible = True
            if self._category_filter.currentIndex() > 0:
                visible = visible and record.get('category') == category
            if self._priority_filter.currentIndex() > 0:
                visible = visible and record.get('priority_label') == priority
            if self._review_filter.currentIndex() > 0:
                visible = visible and record.get('review_status_label') == review
            if self._source_filter.currentIndex() > 0:
                visible = visible and record.get('source') == source
            if brand:
                visible = visible and brand in str(record.get('target_brand', '')).casefold()
            if discovered_date:
                visible = visible and str(record.get('first_seen_at', '')).startswith(discovered_date)
            self._result_table.setRowHidden(row, not visible)

    def _show_candidate_details(self, row: int, _column: int) -> None:
        if row >= len(self._scam_records):
            return
        record = self._scam_records[row]
        learning_probability = record.get('learning_probability')
        learning_probability_text = (
            f'{learning_probability:.1%}'
            if isinstance(learning_probability, (int, float)) else 'なし'
        )
        details = (
            f"候補ID: {record.get('candidate_id', '')}\n"
            f"分類: {record.get('category', '')}\n"
            f"優先度: {record.get('priority_label', '')} ({record.get('risk_score', 0)}点)\n"
            f"学習モデル: {record.get('learning_model_version', '') or '未使用'}\n"
            f"学習予測: {learning_probability_text}\n"
            f"情報充足度: {record.get('completeness_label', '')}\n"
            f"不足情報: {record.get('missing_evidence', '') or 'なし'}\n"
            f"出典: {record.get('source', '')}\n"
            f"初回発見: {record.get('first_seen_at', '')}\n"
            f"最終観測: {record.get('last_observed_at', '') or '未観測'}\n"
            f"レビュー: {record.get('review_status_label', '未レビュー')}\n"
            f"レビュー理由: {record.get('review_reason', '')}\n"
            f"適用ルール: {record.get('rules', '')}\n"
            f"DNS: {record.get('dns_status', '')} {record.get('dns_addresses', '')}\n"
            f"RDAP: {record.get('rdap_status', '')} 登録経過日数={record.get('domain_age_days')}\n"
            f"根拠: {record.get('features', '')}\n"
            f"保存画像参照: {record.get('screenshot_url', '') or '取得なし'}\n"
            f"urlscan参照: {record.get('scan_url', '') or '取得なし'}"
        )
        box = QMessageBox(self)
        box.setWindowTitle('候補詳細（安全なテキスト表示）')
        box.setIcon(QMessageBox.Icon.Information)
        box.setText('危険なHTML/JavaScriptは表示・実行しません。')
        box.setDetailedText(details)
        box.exec()

    @pyqtSlot(dict)
    def _on_stats_updated(self, stats: dict) -> None:
        if 'processed' in stats:
            self._stat_processed.set_value(f"{stats['processed']:,}")
        if 'accepted' in stats:
            self._stat_detected.set_value(f"{stats['accepted']:,}")
        if 'scanned' in stats:
            self._stat_scanned.set_value(f"{stats['scanned']:,}")
        if 'scams' in stats:
            self._stat_scams.set_value(f"{stats['scams']:,}")
        if 'urlscan' in stats:
            self._urlscan_status = stats['urlscan'] or {}
        if 'gemini' in stats:
            self._gemini_status = stats['gemini'] or {}
        if 'learning' in stats:
            self._learning_status = stats['learning'] or {'status': '停止'}
        source_counts = stats.get('source_counts') or {}
        source_text = ', '.join(f'{key} {value}' for key, value in sorted(source_counts.items())) or '－'
        accepted = int(stats.get('accepted', 0) or 0)
        duplicates = int(stats.get('duplicates', 0) or 0)
        duplicate_rate = (duplicates / (accepted + duplicates) * 100) if accepted + duplicates else 0
        useful = sum(
            record.get('review_status') in ('strong_suspicion', 'report_prepared')
            for record in self._scam_records
        )
        learning_text = str(self._learning_status.get('status') or '待機中')
        self._operations_summary.setText(
            f"ソース別 {source_text}  |  重複率 {duplicate_rate:.1f}%  |  "
            f"確認済み有用候補 {useful}  |  滞留 {int(stats.get('backlog', 0) or 0)}  |  "
            f"学習 {learning_text}"
        )
        self._refresh_api_usage()
        scanned = stats.get('scanned', 0)
        max_scan = self._max_scan_spin.value()
        if 'scanned' in stats and max_scan > 0:
            self._progress.setRange(0, max_scan)
            self._progress.setValue(scanned)

    def _refresh_api_usage(self) -> None:
        now = time.time()
        urlscan = self._urlscan_status
        cooldown = max(0, int(float(urlscan.get('cooldown_until') or 0) - now))
        if urlscan.get('source_disabled_reason'):
            self._urlscan_usage.set_usage(
                'ソース停止', str(urlscan['source_disabled_reason']), warning=True
            )
        elif cooldown:
            self._urlscan_usage.set_usage(
                f'制限待機 {cooldown}秒', 'HTTP 429・リセット待ち', warning=True
            )
        elif urlscan:
            limit = urlscan.get('limit')
            remaining = urlscan.get('remaining')
            submissions = int(urlscan.get('successful_submissions') or 0)
            reused = int(urlscan.get('reused_scans') or 0)
            searches = int(urlscan.get('search_requests') or 0)
            submission_note = '' if urlscan.get('submission_enabled') else '・新規送信OFF'
            if isinstance(limit, int) and isinstance(remaining, int) and limit > 0:
                reset_at = float(urlscan.get('reset_at_epoch') or 0)
                reset_after = max(0, int(reset_at - now)) if reset_at else None
                window = {'minute': '1分', 'hour': '1時間', 'day': '1日'}.get(
                    urlscan.get('window'), urlscan.get('window') or '現在'
                )
                action = urlscan.get('action') or 'スキャン送信'
                if reset_at and reset_after == 0:
                    self._urlscan_usage.set_usage(
                        '次回応答で更新',
                        f'{action}・{window}枠はリセット済み・直前の残数 {remaining:,} / {limit:,}',
                    )
                else:
                    reset_text = f'{reset_after}秒後リセット' if reset_after is not None else 'リセット時刻不明'
                    percent = round((limit - remaining) / limit * 100)
                    self._urlscan_usage.set_usage(
                        f'残り {remaining:,} / {limit:,}',
                        f'{action}・{window}枠・{reset_text}・新規 {submissions:,}件・再利用 {reused:,}件・検索 {searches:,}回{submission_note}',
                        percent,
                        remaining / limit <= 0.1,
                    )
            else:
                self._urlscan_usage.set_usage(
                    f'新規 {submissions:,}件 / 再利用 {reused:,}件',
                    f'既存検索 {searches:,}回・制限値は最初のAPI応答後に表示{submission_note}'
                )

        gemini = self._gemini_status
        cooldown = max(0, int(float(gemini.get('cooldown_until') or 0) - now))
        if cooldown:
            self._gemini_usage.set_usage(
                f'制限待機 {cooldown}秒',
                f"{gemini.get('model') or 'Gemini'}・別モデルへリトライ",
                warning=True,
            )
        elif gemini:
            requests_used = int(gemini.get('requests') or 0)
            total_tokens = int(gemini.get('total_tokens') or 0)
            prompt_tokens = int(gemini.get('prompt_tokens') or 0)
            output_tokens = int(gemini.get('output_tokens') or 0)
            parse_retries = int(gemini.get('parse_retries') or 0)
            recovery_text = f'・出力再生成 {parse_retries:,}回' if parse_retries else ''
            self._gemini_usage.set_usage(
                f'{requests_used:,}回 / {total_tokens:,} tokens',
                f"{gemini.get('model') or 'Gemini'}・入力 {prompt_tokens:,}・出力 {output_tokens:,}{recovery_text}・上限はAI Studio",
            )

    @pyqtSlot(str)
    def _on_finished(self, saved_path: str) -> None:
        self._scan_banner.setVisible(False)
        self._btn_start.setEnabled(True)
        self._btn_stop.setEnabled(False)
        self._progress.setRange(0, 100)
        self._progress.setValue(100)
        self._update_status('完了', 'inactive')
        if saved_path:
            self._last_excel_report_path = saved_path
            self._btn_save_report.setEnabled(True)
            msg = f'✅ 完了！Excelレポートを保存しました:\n{saved_path}'
            self._log_view.append_log('INFO', msg)
            QMessageBox.information(self, '検知完了', f'処理が完了しました。\n\n📄 Excel保存先:\n{saved_path}')
        else:
            if self._scam_records:
                self._log_view.append_log(
                    'INFO', 'ℹ️  収集完了。CSVは未レビューでも保存できます。レビューは随時行えます'
                )
                QMessageBox.information(
                    self, '収集完了',
                    '処理が完了しました。\n\nCSVは未レビューでも保存できます。\n'
                    'レビューは検出一覧で候補を選び、必要なときに行ってください。'
                )
            else:
                self._log_view.append_log('INFO', 'ℹ️  レビュー候補はありませんでした')
        self._worker = None

    @pyqtSlot(str)
    def _on_error(self, message: str) -> None:
        self._scan_banner.setVisible(False)
        self._log_view.append_log('ERROR', f'❌ {message}')
        self._btn_start.setEnabled(True)
        self._btn_stop.setEnabled(False)
        self._progress.setRange(0, 100)
        self._progress.setValue(0)
        self._update_status('エラー', 'warning')
        QMessageBox.critical(self, 'エラー', message)
        self._worker = None

    def _clear_log(self) -> None:
        self._log_view.clear()

    def _save_excel_report(self) -> None:
        exportable = [
            record for record in self._scam_records
            if record.get('review_status') in ('strong_suspicion', 'report_prepared')
        ]
        if not exportable:
            QMessageBox.information(self, '情報', '「疑いが強い」と人手確認された候補がありません。')
            return
        output_dir = self._resolve_local_path(self._report_output_input.text().strip())
        default_path = output_dir / f"scam_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
        path, _ = QFileDialog.getSaveFileName(
            self, 'Excelレポートを保存', str(default_path), 'Excel Files (*.xlsx)'
        )
        if not path:
            return
        if not path.lower().endswith('.xlsx'):
            path += '.xlsx'
        try:
            from reporter import ExcelReporter
            reporter = ExcelReporter(
                self._excel_path_input.text(),
                self._reporter_name_input.text().strip(),
                self._report_output_input.text().strip(),
            )
            for record in exportable:
                review_note = (
                    f"{record.get('features', '')}; 人手レビュー={record.get('review_reason', '')}; "
                    f"ルール={record.get('rules', '')}; 情報充足度={record.get('completeness_label', '')}"
                )
                reporter.append_record(
                    url=record.get('url', ''),
                    target_brand=record.get('target_brand', ''),
                    features=review_note,
                    detected_at=record.get('detected_at', ''),
                    category=record.get('category', ''),
                )
            saved_path = Path(reporter.save(path))
            self._last_excel_report_path = str(saved_path)
            self._write_evidence_manifest(saved_path, exportable)
            self._log_view.append_log('INFO', f'📊 Excelレポート保存完了: {path}')
            QMessageBox.information(self, '保存完了', f'Excelレポートを保存しました:\n{path}')
        except Exception as e:
            QMessageBox.critical(
                self, '保存エラー',
                f'Excelレポートを保存できませんでした。\n\n'
                f'テンプレート: {self._resolve_local_path(self._excel_path_input.text())}\n'
                f'保存先: {path}\n\n{e}'
            )

    def _export_csv(self) -> None:
        records = list(self._scam_records)
        if not records:
            QMessageBox.information(self, '情報', '出力対象の候補がありません。')
            return
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        default_name = f'scam_report_{timestamp}.csv'
        output_dir = self._resolve_local_path(self._report_output_input.text().strip())
        path, _ = QFileDialog.getSaveFileName(
            self, 'CSVレポートを保存', str(output_dir / default_name), 'CSV Files (*.csv)'
        )
        if not path:
            return
        if not path.lower().endswith('.csv'):
            path += '.csv'
        try:
            with open(path, 'w', newline='', encoding='utf-8-sig') as f:
                fieldnames = [
                    'detected_at', 'domain', 'target_brand', 'category',
                    'priority', 'risk_score', 'completeness', 'review_status',
                    'review_reason', 'reviewer', 'reviewed_at', 'url', 'features',
                    'rules', 'missing_evidence', 'learning_probability',
                    'learning_model_version', 'ip_address', 'scan_url'
                ]
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                for record in records:
                    writer.writerow({
                        key: self._neutralize_csv_formula(record.get(key, ''))
                        for key in fieldnames
                    })
            self._write_evidence_manifest(Path(path), records)
            self._log_view.append_log('INFO', f'📥 CSV エクスポート完了: {path}')
            QMessageBox.information(self, 'エクスポート完了', f'保存しました:\n{path}')
        except Exception as e:
            QMessageBox.critical(self, '保存エラー', str(e))

    def _export_url_logs_excel(self) -> None:
        output_dir = self._resolve_local_path(self._report_output_input.text().strip() or '検出結果')
        default_path = output_dir / f"URLログ_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
        path, _ = QFileDialog.getSaveFileName(
            self, 'URLログをExcelで保存', str(default_path), 'Excel Files (*.xlsx)'
        )
        if not path:
            return
        try:
            from url_audit_log import export_audit_logs_to_excel
            saved_path = export_audit_logs_to_excel(path)
            self._log_view.append_log('INFO', f'URLログのExcel保存完了: {saved_path}')
            QMessageBox.information(self, '保存完了', f'URLログを保存しました:\n{saved_path}')
        except Exception as exc:
            QMessageBox.critical(
                self, '保存エラー', f'URLログをExcelへ保存できませんでした。\n\n{exc}'
            )

    @staticmethod
    def _neutralize_csv_formula(value):
        text = str(value)
        if text.lstrip().startswith(('=', '+', '-', '@')):
            return "'" + text
        return text

    @staticmethod
    def _write_evidence_manifest(output_path: Path, records: list[dict]) -> Path:
        digest = hashlib.sha256(output_path.read_bytes()).hexdigest()
        manifest = {
            'schema_version': 'evidence-manifest-1',
            'created_at': datetime.now().astimezone().isoformat(timespec='seconds'),
            'notice': 'SHA-256は改変検知用であり、取得時刻の法的証明ではありません。',
            'file': {'name': output_path.name, 'sha256': digest},
            'reviewed_candidates': [
                {
                    'candidate_id': record.get('candidate_id', ''),
                    'review_status': record.get('review_status', ''),
                    'reviewed_at': record.get('reviewed_at', ''),
                    'reviewer': record.get('reviewer', ''),
                    'source': record.get('source', ''),
                    'rules': record.get('rules', ''),
                    'learning_probability': record.get('learning_probability'),
                    'learning_model_version': record.get('learning_model_version', ''),
                }
                for record in records
            ],
        }
        manifest_path = output_path.with_suffix(output_path.suffix + '.manifest.json')
        manifest_path.write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2), encoding='utf-8'
        )
        return manifest_path

    def _update_status(self, text: str, state: str) -> None:
        self._status_text.setText(f'状態: {text}')
        dot_obj = {'active': 'status_dot_active', 'warning': 'status_dot_warning', 'inactive': 'status_dot_inactive'}.get(state, 'status_dot_inactive')
        self._status_dot.setObjectName(dot_obj)
        self._status_dot.setStyleSheet(self.styleSheet())

    def closeEvent(self, event) -> None:
        if self._worker and self._worker.isRunning():
            reply = QMessageBox.question(self, '終了確認', '監視が実行中です。終了しますか？\n\n停止後、確認済みの候補は「Excelレポートを保存」から保存できます。', QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if reply == QMessageBox.StandardButton.No:
                event.ignore()
                return
            self._worker.request_stop()
            self._worker.wait(5000)
        event.accept()

def main() -> None:
    app = QApplication(sys.argv)
    app.setApplicationName('詐欺サイト自動検知システム')
    app.setOrganizationName('CYCOT')
    app.setHighDpiScaleFactorRoundingPolicy(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
if __name__ == '__main__':
    main()
