# 🛡️ 日本向け詐欺サイト自動検知システム

> **SSL証明書ログをリアルタイム監視し、AIが詐欺サイトを自動判定・警察提出用Excelレポートを生成するサイバーセキュリティツール**

---

## ⚡ 3ステップで起動する

### Windows の場合（推奨）

1. `start.bat` をダブルクリック
2. `.env` ファイルが開くので API キーを貼り付けて保存
3. 再度 `start.bat` をダブルクリック → 検知開始！

### Mac / Linux の場合

```bash
git clone https://github.com/yourname/fake-site-detector.git
cd fake-site-detector
chmod +x start.sh
./start.sh
```

---

## 🔑 API キーの取得方法

### 1. urlscan.io API キー（無料）

| 手順 | 操作 |
|------|------|
| ① | [https://urlscan.io/user/signup](https://urlscan.io/user/signup) にアクセス |
| ② | 無料アカウントを作成（メールアドレスのみ） |
| ③ | ログイン後、右上のユーザーアイコン → **Settings** |
| ④ | **API Keys** タブ → **Create New API Key** |
| ⑤ | 生成されたキーを `.env` の `URLSCAN_API_KEY=` に貼り付け |

> 📊 無料枠: **5,000 スキャン/日**

---

### 2. Google Gemini API キー（無料）

| 手順 | 操作 |
|------|------|
| ① | [https://aistudio.google.com/app/apikey](https://aistudio.google.com/app/apikey) にアクセス |
| ② | Google アカウントでログイン |
| ③ | **Create API Key** をクリック |
| ④ | 生成されたキーを `.env` の `GEMINI_API_KEY=` に貼り付け |

> 📊 無料枠: **15 リクエスト/分**, **1,500 リクエスト/日**

---

## 📁 プロジェクト構造

```
fake-site-detector/
├── src/
│   ├── main.py        # パイプライン統括（エントリーポイント）
│   ├── monitor.py     # certstream SSL証明書監視
│   ├── scanner.py     # urlscan.io API 連携（証拠保全）
│   ├── analyzer.py    # Gemini AI マルチモーダル分析
│   └── reporter.py    # Excel レポート出力
│
├── CYCOTサイパト実施結果（京都テック、氏名欄あり）_.xls  ← テンプレート
├── .env.example       # 環境変数テンプレート
├── .gitignore
├── requirements.txt
├── start.bat          # Windows 一発起動
├── start.sh           # Mac/Linux 一発起動
└── README.md
```

---

## 🔄 処理パイプライン

```
certstream (WebSocket)
        │
        ▼
 ┌─────────────┐
 │  monitor.py │  SSL証明書ログを監視
 │             │  ブランド名/不審TLDでフィルタ
 └──────┬──────┘
        │ 不審ドメイン
        ▼
 ┌─────────────┐
 │  scanner.py │  urlscan.io API 経由でスキャン
 │             │  ← 直接アクセス禁止（セキュリティ要件）
 └──────┬──────┘
        │ スクリーンショット + DOM + IP
        ▼
 ┌─────────────┐
 │ analyzer.py │  Gemini AI マルチモーダル分析
 │             │  {"is_scam": true/false, ...}
 └──────┬──────┘
        │ is_scam = true のみ
        ▼
 ┌─────────────┐
 │ reporter.py │  Excel の末尾行に追記
 │             │  （URL はテキスト化、リンク化しない）
 └─────────────┘
```

---

## ⚙️ .env 設定ファイル

`.env.example` をコピーして `.env` を作成し、各値を設定してください。

```bash
# Windows
copy .env.example .env

# Mac/Linux
cp .env.example .env
```

```env
# 必須
URLSCAN_API_KEY=your_urlscan_api_key_here
GEMINI_API_KEY=your_gemini_api_key_here

# 任意（デフォルト値あり）
EXCEL_TEMPLATE_PATH=CYCOTサイパト実施結果（京都テック、氏名欄あり）_.xls
MAX_SCAN_COUNT=50     # 1回の実行でスキャンする最大数
QUEUE_SIZE=500        # 監視キューのサイズ
```

---

## 📊 Excel 出力仕様

AI が `"is_scam": true` と判定したドメインのみが追記されます。

| Excel 列 | 出力内容 |
|----------|----------|
| 実施年月日 | 検出日（YYYY/MM/DD） |
| ＳＮＳ別 | `サイト`（固定値） |
| サイト名・ユーザー名 | AIが判定した偽装ブランド名 |
| ＵＲＬ | 生のURL（**テキスト**、リンク化なし） |
| 該当項目 | `偽ショッピングサイト`（固定値） |
| 備考 | AIが検出した不審な特徴 |

> ⚠️ **セキュリティ注意**: URLはExcel上でリンク化されていません。誤クリックによる不審サイトへのアクセスを防ぐ設計です。

---

## 🔒 セキュリティ設計

| 原則 | 実装 |
|------|------|
| **直接アクセス禁止** | 不審URLへの HTTP リクエストは一切送らない。すべて urlscan.io 経由 |
| **シークレット管理** | APIキーは `.env` のみ。コード内にハードコードなし |
| **URL無害化** | ExcelのURLはテキストセル。`=HYPERLINK()` 等は使用しない |
| **IP保護** | スキャンは urlscan.io サーバーが実行。自分のIPは不審サイトに到達しない |

---

## 📈 API 制限と対策

| API | 無料枠 | 対策 |
|-----|--------|------|
| urlscan.io | 5,000 スキャン/日 | `time.sleep(2)` + 厳格なフィルタリング |
| Gemini API | 15 リクエスト/分 | `time.sleep(5)` + 指数バックオフリトライ |

---

## 🎯 監視対象ブランド

佐川急便、イオン、ヤマト運輸、Amazon、メルカリ、楽天、Yahoo! Japan、NTTドコモ、ソフトバンク、三井住友銀行、みずほ銀行、三菱UFJ銀行、日本郵便、PayPal、LINE、ZOZO など

**不審 TLD**: `.top`, `.xyz`, `.shop`, `.club`, `.vip`, `.cn`, `.buzz`, `.icu` など

---

## 🛑 システムの停止

実行中に **Ctrl+C** を押すと、安全に停止します。  
停止時点までの検知結果は自動的に Excel ファイルに保存されます。

```
^C
⏹️ 停止シグナルを受信しました

================================================================
📊 実行結果サマリー
================================================================
  スキャン実行数:        42
  詐欺判定数:            7
  Gemini リクエスト数:   42
  📄 Excel 保存先: CYCOTサイパト実施結果_20240101_123456.xlsx
================================================================
🏁 システムを正常終了しました
```

---

## ❓ トラブルシューティング

**Q: `certstream` に接続できない**  
A: インターネット接続を確認してください。WebSocket (wss://) が通る必要があります。

**Q: `429 Too Many Requests` エラーが出る**  
A: `.env` の `MAX_SCAN_COUNT` を減らしてください。または翌日に再実行してください。

**Q: Excel ファイルが見つからないエラー**  
A: `EXCEL_TEMPLATE_PATH` に正しいパスを設定してください。ファイルが見つからない場合は自動的に新規作成されます。

**Q: Gemini のレスポンスが JSON でない**  
A: まれに Gemini が指定外のフォーマットで返答します。システムは自動的に次のドメインに進みます。

---

## ⚖️ 法的免責事項

> このツールは**サイバーセキュリティ研究・教育目的**のために設計されています。  
> 不審サイトへの直接アクセスは行わず、すべてのスキャンは urlscan.io の公開サービスを経由します。  
> 収集した情報は適切な法執行機関への通報のみに使用し、第三者への漏洩や悪用は厳禁です。

---

## 📝 ライセンス

MIT License — 詳細は [LICENSE](LICENSE) ファイルを参照

---

*Developed for CYCOT サイバーパトロール — 京都テック*