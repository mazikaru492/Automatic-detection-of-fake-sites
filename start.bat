@echo off
:: 日本語 Windows では CP932 (Shift-JIS) を使う
chcp 932 > nul
setlocal EnableDelayedExpansion

echo ================================================================
echo   日本向け詐欺サイト自動検知システム — Windows セットアップ
echo ================================================================
echo.

:: ---------------------------------------------------------------
:: Python バージョン確認
:: ---------------------------------------------------------------
python --version > nul 2>&1
if %errorlevel% neq 0 (
    echo [エラー] Python が見つかりません。
    echo         https://www.python.org/downloads/ からインストールしてください。
    echo         インストール時に "Add Python to PATH" にチェックを入れてください。
    pause
    exit /b 1
)

for /f "tokens=2" %%v in ('python --version 2^>^&1') do set PYTHON_VER=%%v
echo [OK] Python %PYTHON_VER% を検出しました

:: ---------------------------------------------------------------
:: .env ファイルの確認
:: ---------------------------------------------------------------
if not exist ".env" (
    if exist ".env.example" (
        echo.
        echo [警告] .env ファイルが見つかりません。
        echo        .env.example をコピーして .env を作成します...
        copy ".env.example" ".env" > nul
        echo.
        echo ================================================================
        echo  ★ 重要: .env ファイルを開いてAPIキーを設定してください ★
        echo ================================================================
        echo.
        echo  1. URLSCAN_API_KEY  : https://urlscan.io/user/signup
        echo  2. GEMINI_API_KEY   : https://aistudio.google.com/app/apikey
        echo.
        echo  APIキーを設定後、再度 start.bat を実行してください。
        echo ================================================================
        start notepad .env
        pause
        exit /b 0
    ) else (
        echo [エラー] .env.example が見つかりません。リポジトリを正しくクローンしてください。
        pause
        exit /b 1
    )
)

:: ---------------------------------------------------------------
:: 仮想環境の作成（初回のみ）
:: ---------------------------------------------------------------
if not exist "venv\" (
    echo.
    echo [1/3] 仮想環境を作成中...
    python -m venv venv
    if %errorlevel% neq 0 (
        echo [エラー] 仮想環境の作成に失敗しました。
        pause
        exit /b 1
    )
    echo [OK] 仮想環境を作成しました
) else (
    echo [OK] 仮想環境が既に存在します
)

:: ---------------------------------------------------------------
:: pip でライブラリをインストール
:: ---------------------------------------------------------------
echo.
echo [2/3] 必要なライブラリをインストール中...
echo       （初回は数分かかる場合があります）
call venv\Scripts\activate.bat

python -m pip install --upgrade pip --quiet
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo [エラー] ライブラリのインストールに失敗しました。
    echo         インターネット接続を確認してください。
    pause
    exit /b 1
)
echo [OK] ライブラリのインストール完了

:: ---------------------------------------------------------------
:: main.py の実行
:: ---------------------------------------------------------------
echo.
echo [3/3] デスクトップGUIを起動します...
echo       ウィンドウを閉じると終了します。
echo.
echo ================================================================
echo.

cd src
python gui.py
cd ..

echo.
echo ================================================================
echo  システムが終了しました。
echo  検知レポートは Excel ファイルとして保存されています。
echo ================================================================

call venv\Scripts\deactivate.bat
pause
