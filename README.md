# 🛡️ 日本向け詐欺サイト自動検知システム

> **SSL証明書ログをリアルタイム監視し、AI（Google Gemini）が詐欺・フィッシングサイトを自動判定・警察提出用Excel/CSVレポートを生成するサイバーセキュリティ支援ツール**

---

## ⚡ クイックスタート

### Windows の場合（推奨）

1. **`start.bat` をダブルクリック**  
   （Pythonの存在確認、仮想環境の構築、必要ライブラリのインストールが自動で行われます）
2. デスクトップGUIが起動します。
3. 初回のみ左サイドバーで **APIキーを入力** し、**「💾 キーを保存」** をクリックします。
   - **🔒 安全設計**: APIキーはOSの暗号化資格情報マネージャー（Windows Credential Manager / DPAPI）に安全に保存されるため、**次回以降は自動入力され、毎回入力する必要はありません。**
4. **「▶ 監視開始」** をクリックすると、リアルタイム監視・AI検知がスタートします。

### Mac / Linux の場合

```bash
git clone https://github.com/yourname/fake-site-detector.git
cd fake-site-detector
chmod +x start.sh
./start.sh
```

---

## 🔑 API キーの取得方法（いずれも無料）

### 1. urlscan.io API キー（無料枠: 5,000 スキャン/日）

| 手順 | 操作 |
|:---:|:---|
| ① | [https://urlscan.io/user/signup](https://urlscan.io/user/signup) で無料アカウントを作成 |
| ② | ログイン後、右上のユーザーアイコン → **Settings** を開く |
| ③ | **API Keys** タブ → **Create New API Key** をクリック |
| ④ | 生成されたキーをアプリ画面の「urlscan.io API キー」欄に貼り付け |

---

### 2. Google Gemini API キー（無料枠: 15 リクエスト/分, 1,500 リクエスト/日）

| 手順 | 操作 |
|:---:|:---|
| ① | [https://aistudio.google.com/app/apikey](https://aistudio.google.com/app/apikey) に Google アカウントでログイン |
| ② | **Create API Key** をクリック |
| ③ | 生成されたキーをアプリ画面の「Gemini API キー」欄に貼り付け |

---

## 🖥️ デスクトップ GUI の機能

- **ダッシュボード**: 監視ドメイン数、フィルタ通過数、スキャン数、詐欺判定数をリアルタイム表示。
- **ターミナル風ログ**: 内部動作と検知ログをカラー別（INFO/WARN/ERROR）で表示。
- **検知結果テーブル**: 詐欺判定されたサイトの発生日時、ドメイン、偽装ブランド、不審な特徴、urlscan.io レポートURLを一覧表示。
- **ワンクリックエクスポート**: Excel 追記保存に加え、ワンクリックでの CSV エクスポートにも対応。
- **セキュアキー管理**: OSネイティブの暗号化ストレージにキーを自動保持。

---

## 📁 プロジェクト構造

```
fake-site-detector/
├── src/
│   ├── gui.py         # PyQt6 デスクトップ GUI アプリケーション
│   ├── worker.py      # GUI スレッドとパイプラインを結ぶ非同期ワーカー
│   ├── key_manager.py # OS資格情報マネージャー（keyring）暗号化キー管理
│   ├── main.py        # CLI 実行用オーケストレーター
│   ├── monitor.py     # certstream SSL証明書リアルタイム監視
│   ├── scanner.py     # urlscan.io API 連携（安全な証拠保全）
│   ├── analyzer.py    # Google Gemini AI マルチモーダル分析
│   └── reporter.py    # Excel レポート追記・自動生成
│
├── CYCOTサイパト実施結果（京都テック、氏名欄あり）_.xlsx  # 警察提出用Excelテンプレート
├── .env.example       # 環境変数テンプレート
├── .gitignore
├── requirements.txt   # 依存ライブラリ一覧
├── start.bat          # Windows 一発起動スクリプト
├── start.sh           # Mac/Linux 一発起動スクリプト
└── README.md
```

---

## 🔄 処理パイプライン

```
certstream (WebSocket)
        │
        ▼
 ┌─────────────┐
 │  monitor.py │  SSL証明書発行ログをリアルタイム監視
 │             │  著名ブランド名 / 不審TLDで高精度フィルタリング
 └──────┬──────┘
        │ 不審ドメイン
        ▼
 ┌─────────────┐
 │  scanner.py │  urlscan.io API 経由で安全にスキャン
 │             │  ← 不審サイトへの直接アクセス禁止（マルウェア感染防止）
 └──────┬──────┘
        │ スクリーンショット + DOMテキスト + IPアドレス
        ▼
 ┌─────────────┐
 │ analyzer.py │  Google Gemini AI によるマルチモーダル判定
 │             │  {"is_scam": true/false, "target_brand": "...", ...}
 └──────┬──────┘
        │ is_scam = true のみ
        ▼
 ┌─────────────┐
 │ reporter.py │  Excel (.xlsx) / CSV に自動追記
 │             │  （URLは誤クリック防止のためテキストセルとして安全化）
 └─────────────┘
```

---

## 📊 レポート出力仕様

AI が `"is_scam": true` と判定したドメインのみが自動記録されます。

| Excel 列 | 出力内容 | 備考 |
|---|---|---|
| 実施年月日 | 検出日（YYYY/MM/DD） | 自動記録 |
| ＳＮＳ別 | `サイト` | 固定値 |
| サイト名・ユーザー名 | AIが判定した偽装ブランド名 | 例: `Amazon`, `佐川急便` |
| ＵＲＬ | 生のURL | **テキストセル**（ハイパーリンク化なし） |
| 該当項目 | `偽ショッピングサイト` | 固定値 |
| 備考 | AIが検出した不審な特徴 | 不自然な日本語、偽警告文等 |

> ⚠️ **セキュリティ配慮**: Excel内のURLはハイパーリンク化されていません。レポート閲覧時の誤クリックによる不審サイトアクセスを防ぎます。

---

## 🔒 セキュリティ設計

| 項目 | 設計・実装内容 |
|---|---|
| **直接アクセス禁止** | ローカルPCから不審サイトへの直接HTTP通信は一切行いません。すべて urlscan.io のクラウドサンドボックスを経由します。 |
| **暗号化キー保管** | APIキーは Windows Credential Manager / macOS Keychain の暗号化領域（DPAPI）に保存されます。平文ファイル流出やGit誤コミットを防ぎます。 |
| **IPアドレス保護** | スキャン実行元は urlscan.io サーバーとなるため、自身のIPアドレスが攻撃者に露見しません。 |
| **URL無害化** | レポート出力時、URLはプレーンテキストとして出力され、不用意なクリックを防ぎます。 |

---

## 🎯 監視対象ブランドと不審TLD

- **主要監視ブランド**:  
  佐川急便、イオン、ヤマト運輸（クロネコヤマト）、Amazon、メルカリ、楽天、Yahoo! Japan、NTTドコモ、ソフトバンク、三井住友銀行（SMBC）、みずほ銀行、三菱UFJ銀行、日本郵便、PayPal、LINE、ZOZOTOWN など
- **不審TLD**:  
  `.top`, `.xyz`, `.shop`, `.club`, `.vip`, `.cn`, `.buzz`, `.icu`, `.fit`, `.surf`, `.space`, `.gdn`, `.win`, `.loan`, `.date`, `.accountant` など

---

## ❓ トラブルシューティング

- **Q: 起動時に「Python が見つかりません」と表示される**  
  A: [python.org](https://www.python.org/downloads/) から Python 3.10 以上をインストールしてください。インストール時は必ず **"Add Python to PATH"** にチェックを入れてください。

- **Q: APIキーが毎回消えてしまう**  
  A: GUI画面でAPIキーを入力後、「💾 キーを保存」ボタンを押すか、「▶ 監視開始」を押すとOSの安全な資格情報マネージャーに自動保存されます。

- **Q: certstream に接続できない**  
  A: インターネット接続を確認してください。WebSocket通信（`wss://certstream.calidog.io/`）がファイアウォールで遮断されていないか確認してください。

- **Q: Gemini の 429 Too Many Requests エラーが出る**  
  A: Gemini API の無料枠制限（15リクエスト/分）に達した場合、システムは自動的に指数バックオフで待機・再試行します。

---

## ⚖️ 法的免責事項

> 本ツールは**サイバーセキュリティ研究・教育および公的サイバーパトロール活動の支援**を目的として開発されています。  
> 不審サイトへの直接アクセスは行わず、公開サンドボックスサービスを経由して証拠保全を行います。  
> 収集した情報は適切な法執行機関・関係機関への通報のみに使用し、悪用や不正アクセス行為への転用は厳禁です。

---

## 📝 ライセンス

MIT License — 詳細は [LICENSE](LICENSE) ファイルを参照

---

*Developed for CYCOT サイバーパトロール — 京都テック*