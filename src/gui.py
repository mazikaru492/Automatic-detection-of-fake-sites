import os
import sys
import csv
import shutil
import time
import webbrowser
from datetime import datetime
from pathlib import Path
from PyQt6.QtCore import Qt, QTimer, QThread, pyqtSlot, QPropertyAnimation, QEasingCurve, QSize
from PyQt6.QtGui import QColor, QFont, QFontDatabase, QIcon, QPalette, QTextCharFormat, QTextCursor, QPixmap
from PyQt6.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel, QPushButton, QLineEdit, QTextEdit, QTableWidget, QTableWidgetItem, QTabWidget, QFrame, QFileDialog, QMessageBox, QHeaderView, QScrollArea, QSplitter, QSizePolicy, QSpinBox, QGroupBox, QStatusBar, QProgressBar, QCheckBox
sys.path.insert(0, str(Path(__file__).parent))
from worker import PipelineWorker
from key_manager import save_api_key, get_api_key, load_all_keys, URLSCAN_KEY_NAME, GEMINI_KEY_NAME
COLORS = {'bg_dark': '#0a0e1a', 'bg_panel': '#0f1628', 'bg_card': '#151e35', 'bg_input': '#1a2545', 'accent_cyan': '#00d4ff', 'accent_blue': '#4d9fff', 'accent_green': '#00ff88', 'accent_red': '#ff4757', 'accent_orange': '#ffa502', 'text_primary': '#e8f4f8', 'text_secondary': '#7fa3c0', 'text_dim': '#3d5a78', 'border': '#1e3a5a', 'border_glow': '#00d4ff33'}
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
        self.setWindowTitle('詐欺サイト自動検知システム — CYCOT サイバーパトロール')
        self.setMinimumSize(1280, 800)
        self.resize(1400, 900)
        self.setStyleSheet(STYLE_SHEET)
        self._setup_ui()
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
        api_group = QGroupBox('🔑 API キー設定')
        api_layout = QVBoxLayout(api_group)
        api_layout.setSpacing(10)
        self._urlscan_input = ApiKeyInput('urlscan.io API キー', 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx', 'https://urlscan.io/user/signup')
        self._gemini_input = ApiKeyInput('Gemini API キー', 'AIzaSy...', 'https://aistudio.google.com/app/apikey')
        api_layout.addWidget(self._urlscan_input)
        api_layout.addWidget(self._gemini_input)
        save_btn = QPushButton('💾  キーを保存 (.env)')
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
        self._max_scan_spin.setValue(50)
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
        self._btn_save_report.setEnabled(False)
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
        return sidebar

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
        self._stat_scams = StatCard('詐欺判定', '0', COLORS['accent_red'])
        for card in [self._stat_processed, self._stat_detected, self._stat_scanned, self._stat_scams]:
            stats_row.addWidget(card)
        layout.addLayout(stats_row)
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
        tabs.addTab(log_tab, '📡  リアルタイムログ')
        result_tab = QWidget()
        result_layout = QVBoxLayout(result_tab)
        result_layout.setContentsMargins(8, 8, 8, 8)
        table_bar = QHBoxLayout()
        table_title = QLabel(f'🚨  詐欺サイト検出一覧')
        table_title.setStyleSheet(f"color: {COLORS['accent_red']}; font-weight: bold; font-size: 14px;")
        self._result_count_label = QLabel('0 件')
        self._result_count_label.setStyleSheet(f"color: {COLORS['text_secondary']};")
        export_csv_btn = QPushButton('📥  CSVエクスポート')
        export_csv_btn.setObjectName('btn_secondary')
        export_csv_btn.clicked.connect(self._export_csv)
        table_bar.addWidget(table_title)
        table_bar.addWidget(self._result_count_label)
        table_bar.addStretch()
        table_bar.addWidget(export_csv_btn)
        self._result_table = QTableWidget()
        self._result_table.setColumnCount(7)
        self._result_table.setHorizontalHeaderLabels(['検出日時', 'ドメイン', 'ブランド', '分類', 'URL', '特徴', 'urlscan レポート'])
        self._result_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self._result_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self._result_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._result_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._result_table.verticalHeader().setVisible(False)
        self._result_table.setShowGrid(False)
        self._result_table.setAlternatingRowColors(False)
        result_layout.addLayout(table_bar)
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

    def _load_env(self) -> None:
        saved_keys = load_all_keys()
        urlscan_val = saved_keys.get(URLSCAN_KEY_NAME, "")
        gemini_val = saved_keys.get(GEMINI_KEY_NAME, "")

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
        self._excel_path_input.setText(env_values.get('EXCEL_TEMPLATE_PATH', 'CYCOTサイパト実施結果（京都テック、氏名欄あり）_.xlsx'))
        self._reporter_name_input.setText(env_values.get('REPORTER_NAME', ''))
        max_scan = env_values.get('MAX_SCAN_COUNT', '50')
        try:
            self._max_scan_spin.setValue(int(max_scan))
        except ValueError:
            pass

    def _save_env(self) -> None:
        u_key = self._urlscan_input.value
        g_key = self._gemini_input.value

        if u_key:
            save_api_key(URLSCAN_KEY_NAME, u_key)
        if g_key:
            save_api_key(GEMINI_KEY_NAME, g_key)

        env_path = Path(__file__).parent.parent / '.env'
        content = f'URLSCAN_API_KEY={u_key}\nGEMINI_API_KEY={g_key}\nREPORTER_NAME={self._reporter_name_input.text().strip()}\nEXCEL_TEMPLATE_PATH={self._excel_path_input.text()}\nMAX_SCAN_COUNT={self._max_scan_spin.value()}\nQUEUE_SIZE=500\n'
        try:
            with open(env_path, 'w', encoding='utf-8') as f:
                f.write(content)
            self._log_view.append_log('INFO', '🔒 APIキーをセキュアストレージ (OS資格情報) および .env に保存しました')
            QMessageBox.information(self, '保存完了', 'APIキーをOSの安全な資格情報マネージャーに暗号化保存しました。\n次回から自動で読み込まれます。')
        except Exception as e:
            QMessageBox.critical(self, '保存エラー', str(e))

    def _browse_excel(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, 'Excelテンプレートを選択', str(Path.home()), 'Excel Files (*.xls *.xlsx)')
        if path:
            self._excel_path_input.setText(path)

    def _validate_inputs(self) -> bool:
        if not self._reporter_name_input.text().strip():
            QMessageBox.warning(self, '入力エラー', 'Excelレポートへ記載する氏名を入力してください。')
            self._reporter_name_input.setFocus()
            return False
        if not self._urlscan_input.value:
            QMessageBox.warning(self, '入力エラー', 'urlscan.io APIキーを入力してください。\n\n取得先: https://urlscan.io/user/signup')
            return False
        if not self._gemini_input.value:
            QMessageBox.warning(self, '入力エラー', 'Gemini APIキーを入力してください。\n\n取得先: https://aistudio.google.com/app/apikey')
            return False
        return True

    def _start_pipeline(self) -> None:
        if not self._validate_inputs():
            return

        self._last_excel_report_path = ''
        self._btn_save_report.setEnabled(False)
        save_api_key(URLSCAN_KEY_NAME, self._urlscan_input.value)
        save_api_key(GEMINI_KEY_NAME, self._gemini_input.value)

        self._scan_banner.show()
        self._scan_banner.raise_()
        self._scan_banner.setVisible(True)
        self._tabs.setCurrentIndex(0)
        self._log_view.clear()
        self._log_view.append_log('INFO', '=' * 60)
        self._log_view.append_log('INFO', '🛡️  詐欺サイト検知システム 起動')
        self._log_view.append_log('INFO', '=' * 60)
        self._worker = PipelineWorker(urlscan_api_key=self._urlscan_input.value, gemini_api_key=self._gemini_input.value, excel_template_path=self._excel_path_input.text(), max_scan_count=self._max_scan_spin.value(), reporter_name=self._reporter_name_input.text().strip())

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
        self._result_table.setItem(row, 0, make_item(data.get('detected_at', '')))
        self._result_table.setItem(row, 1, make_item(data.get('domain', ''), COLORS['accent_orange']))
        self._result_table.setItem(row, 2, make_item(data.get('target_brand', ''), COLORS['accent_red']))
        self._result_table.setItem(row, 3, make_item(data.get('category', ''), COLORS['accent_cyan']))
        url_item = make_item(data.get('url', ''), COLORS['text_secondary'])
        url_item.setToolTip('URLはセキュリティのためリンク化されていません')
        self._result_table.setItem(row, 4, url_item)
        self._result_table.setItem(row, 5, make_item(data.get('features', '')))
        self._result_table.setItem(row, 6, make_item(data.get('scan_url', ''), COLORS['accent_blue']))
        count = self._result_table.rowCount()
        self._tabs.setTabText(1, f'🚨  検出一覧 ({count})')
        self._result_count_label.setText(f'{count} 件')
        self._tabs.setCurrentIndex(1)

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
        if cooldown:
            self._urlscan_usage.set_usage(
                f'制限待機 {cooldown}秒', 'HTTP 429・リセット待ち', warning=True
            )
        elif urlscan:
            limit = urlscan.get('limit')
            remaining = urlscan.get('remaining')
            submissions = int(urlscan.get('successful_submissions') or 0)
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
                        f'{action}・{window}枠・{reset_text}・成功送信 {submissions:,}件',
                        percent,
                        remaining / limit <= 0.1,
                    )
            else:
                self._urlscan_usage.set_usage(
                    f'成功送信 {submissions:,}件', '制限値は最初のAPI応答後に表示'
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
            self._gemini_usage.set_usage(
                f'{requests_used:,}回 / {total_tokens:,} tokens',
                f"{gemini.get('model') or 'Gemini'}・入力 {prompt_tokens:,}・出力 {output_tokens:,}・上限はAI Studio",
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
            self._log_view.append_log('INFO', 'ℹ️  詐欺判定されたサイトはありませんでした')
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
        if not self._last_excel_report_path or not Path(self._last_excel_report_path).exists():
            QMessageBox.information(self, '情報', '保存できるExcelレポートがまだありません。')
            return
        source = Path(self._last_excel_report_path)
        path, _ = QFileDialog.getSaveFileName(self, 'Excelレポートを保存', source.name, 'Excel Files (*.xlsx)')
        if not path:
            return
        if not path.lower().endswith('.xlsx'):
            path += '.xlsx'
        try:
            shutil.copy2(source, path)
            self._log_view.append_log('INFO', f'📊 Excelレポート保存完了: {path}')
            QMessageBox.information(self, '保存完了', f'Excelレポートを保存しました:\n{path}')
        except Exception as e:
            QMessageBox.critical(self, '保存エラー', str(e))

    def _export_csv(self) -> None:
        if not self._scam_records:
            QMessageBox.information(self, '情報', 'エクスポートするデータがありません。')
            return
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        default_name = f'scam_report_{timestamp}.csv'
        path, _ = QFileDialog.getSaveFileName(self, 'CSVレポートを保存', default_name, 'CSV Files (*.csv)')
        if not path:
            return
        try:
            with open(path, 'w', newline='', encoding='utf-8-sig') as f:
                writer = csv.DictWriter(f, fieldnames=['detected_at', 'domain', 'target_brand', 'category', 'url', 'features', 'ip_address', 'scan_url'])
                writer.writeheader()
                writer.writerows(self._scam_records)
            self._log_view.append_log('INFO', f'📥 CSV エクスポート完了: {path}')
            QMessageBox.information(self, 'エクスポート完了', f'保存しました:\n{path}')
        except Exception as e:
            QMessageBox.critical(self, '保存エラー', str(e))

    def _update_status(self, text: str, state: str) -> None:
        self._status_text.setText(f'状態: {text}')
        dot_obj = {'active': 'status_dot_active', 'warning': 'status_dot_warning', 'inactive': 'status_dot_inactive'}.get(state, 'status_dot_inactive')
        self._status_dot.setObjectName(dot_obj)
        self._status_dot.setStyleSheet(self.styleSheet())

    def closeEvent(self, event) -> None:
        if self._worker and self._worker.isRunning():
            reply = QMessageBox.question(self, '終了確認', '監視が実行中です。終了しますか？\n\n（停止後、検出済みデータは Excel に自動保存されます）', QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
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
