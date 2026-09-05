#!/bin/bash
# ================================================================
#   日本向け詐欺サイト自動検知システム — Mac/Linux セットアップ
# ================================================================
# 使い方: chmod +x start.sh && ./start.sh

set -e  # エラー発生時に即座に終了

# カラー出力用エスケープコード
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}================================================================${NC}"
echo -e "${CYAN}  日本向け詐欺サイト自動検知システム — Mac/Linux セットアップ${NC}"
echo -e "${CYAN}================================================================${NC}"
echo ""

# ---------------------------------------------------------------
# Python バージョン確認（Python 3.9 以上を要求）
# ---------------------------------------------------------------
check_python() {
    local python_cmd=""
    if command -v python3 &> /dev/null; then
        python_cmd="python3"
    elif command -v python &> /dev/null; then
        python_cmd="python"
    else
        echo -e "${RED}[エラー] Python が見つかりません。${NC}"
        echo "        インストール方法:"
        echo "          Mac:   brew install python3"
        echo "          Ubuntu: sudo apt install python3"
        exit 1
    fi

    local version=$($python_cmd --version 2>&1 | awk '{print $2}')
    local major=$(echo "$version" | cut -d. -f1)
    local minor=$(echo "$version" | cut -d. -f2)

    if [ "$major" -lt 3 ] || ([ "$major" -eq 3 ] && [ "$minor" -lt 9 ]); then
        echo -e "${RED}[エラー] Python 3.9 以上が必要です（現在: $version）${NC}"
        exit 1
    fi

    echo -e "${GREEN}[OK] Python $version を検出しました${NC}"
    echo "$python_cmd"
}

PYTHON_CMD=$(check_python)

# ---------------------------------------------------------------
# .env ファイルの確認
# ---------------------------------------------------------------
if [ ! -f ".env" ]; then
    if [ -f ".env.example" ]; then
        echo ""
        echo -e "${YELLOW}[警告] .env ファイルが見つかりません。${NC}"
        echo "       .env.example から .env を作成します..."
        cp ".env.example" ".env"
        echo ""
        echo -e "${YELLOW}================================================================${NC}"
        echo -e "${YELLOW}  ★ 重要: .env ファイルにAPIキーを設定してください ★${NC}"
        echo -e "${YELLOW}================================================================${NC}"
        echo ""
        echo "  1. URLSCAN_API_KEY  : https://urlscan.io/user/signup"
        echo "  2. GEMINI_API_KEY   : https://aistudio.google.com/app/apikey"
        echo "  3. SUPABASE_*       : Project URL, anon key, user email/password"
        echo ""
        echo "  .env ファイルを開きます..."
        if command -v open &> /dev/null; then
            open ".env"      # Mac
        elif command -v xdg-open &> /dev/null; then
            xdg-open ".env"  # Linux
        else
            echo "  エディタで .env を手動で編集してください"
        fi
        echo ""
        echo "  APIキーを設定後、再度 ./start.sh を実行してください。"
        echo "================================================================"
        exit 0
    else
        echo -e "${RED}[エラー] .env.example が見つかりません。リポジトリを正しくクローンしてください。${NC}"
        exit 1
    fi
fi

# ---------------------------------------------------------------
# 仮想環境の作成（初回のみ）
# ---------------------------------------------------------------
echo ""
if [ ! -d "venv" ]; then
    echo -e "${BLUE}[1/3] 仮想環境を作成中...${NC}"
    $PYTHON_CMD -m venv venv
    echo -e "${GREEN}[OK] 仮想環境を作成しました${NC}"
else
    echo -e "${GREEN}[OK] 仮想環境が既に存在します${NC}"
fi

# 仮想環境をアクティベート
source venv/bin/activate

# ---------------------------------------------------------------
# pip でライブラリをインストール
# ---------------------------------------------------------------
echo ""
echo -e "${BLUE}[2/3] 必要なライブラリをインストール中...${NC}"
echo "      （初回は数分かかる場合があります）"

python -m pip install --upgrade pip --quiet
pip install -r requirements.txt

echo -e "${GREEN}[OK] ライブラリのインストール完了${NC}"

# ---------------------------------------------------------------
# gui.py の実行
# ---------------------------------------------------------------
echo ""
echo -e "${BLUE}[3/3] デスクトップGUIを起動します...ウィンドウを閉じると終了します。${NC}"
echo ""
echo -e "${CYAN}================================================================${NC}"
echo ""

cd src
python gui.py
cd ..

echo ""
echo -e "${CYAN}================================================================${NC}"
echo -e "${GREEN}  システムが終了しました。${NC}"
echo "  検知レポートは Excel ファイルとして保存されています。"
echo -e "${CYAN}================================================================${NC}"

deactivate
