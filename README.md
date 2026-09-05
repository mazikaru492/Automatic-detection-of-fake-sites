# 不審サイト収集・レビュー支援システム

公開情報から不審なURL候補を収集し、urlscan.ioの観測結果、決定的ルール、任意のGemini補助分析を組み合わせて、人が確認する候補を整理するデスクトップアプリです。

対象は主に次の3分類です。

- フィッシングサイト: `phishing`
- 詐欺通販・違法商品販売の疑いがあるサイト: `fraudulent_ec`
- コピー商品・偽ブランド商品販売の疑いがあるサイト: `suspected_counterfeit`

このシステムは候補を自動通報しません。ExcelまたはCSVへ出力できるのは、人が「疑いが強い」または「資料作成済み」と確認した候補だけです。

## 現在の主な機能

- OpenPhish公開フィードから候補を収集
- 任意でCertificate Transparencyログを監視
- ブランド偽装、詐欺通販、違法商品、コピー商品に関する候補を抽出
- 同種候補の連続取得を制限し、特定ブランドへの偏りを抑制
- Supabaseを使った永続的な重複排除、観測履歴、判定履歴、人手レビュー履歴の保存
- 既存のurlscan.io結果の再利用
- 明示的に有効化した場合だけ、新しいurlscan.ioスキャンを送信
- 決定的なルールによる優先度と情報充足度の計算
- 任意のGemini補助分析と、壊れたJSON応答に対する再生成・モデル切替
- API使用量、残量、クールダウン状態のGUI表示
- フィルタ通過URLとスキャン対象URLを別ファイルへ自動記録
- 人手レビュー結果だけを使った評価付き自動学習
- Excelテンプレートを維持したレポート作成とCSV出力
- テンプレートと検出結果の保存先を別フォルダーとして管理

## 必要な環境

- Python 3.10以上
- Windows、macOS、またはLinux
- urlscan.io APIキー
- Supabaseプロジェクトと、アプリ専用のAuthentication利用者
- Gemini補助分析を使う場合だけGemini APIキー

## 最初に行う設定

### 1. Supabaseプロジェクトを準備する

Supabaseでプロジェクトを作成し、SQL Editorから次のSQLを順番に実行してください。

1. `supabase/migrations/202609020001_detection_schema.sql`
2. `supabase/migrations/202609030001_spec_v11_history.sql`
3. `supabase/migrations/202609030002_online_learning.sql`

役割は次のとおりです。

| SQL | 内容 |
|---|---|
| `202609020001_detection_schema.sql` | 候補保存、重複排除、RLS、基本RPC |
| `202609030001_spec_v11_history.sql` | 発見・観測・自動評価・人手レビューの履歴、同時更新の競合防止 |
| `202609030002_online_learning.sql` | 学習例、モデル履歴、モデル切替、ロールバック |

続いて、Supabaseの「Authentication」からアプリ専用利用者を作成します。GUIへ入力するパスワードは、このAuthentication利用者のパスワードです。データベース作成時のDatabase Passwordではありません。

GUIへ入力するSupabase情報は次の4項目です。

- Project URL: `https://プロジェクトID.supabase.co`
- Publishable key: `sb_publishable_...`
- Authentication利用者のメールアドレス
- Authentication利用者のパスワード

Project URLに`/rest/v1/`を付けないでください。Secret keyとservice_roleキーは使用できず、アプリ側でも拒否されます。SupabaseのExposed schemasへ`private`を追加しないでください。

### 2. 外部サービスのキーを取得する

- urlscan.io: [APIキー取得ページ](https://urlscan.io/user/signup)
- Gemini: [Google AI Studio](https://aistudio.google.com/app/apikey)

urlscan.ioは必須です。Geminiは「Gemini補助分析」を有効にする場合だけ必要です。各サービスの利用枠や利用条件は変更されることがあるため、最新情報は各サービスの管理画面で確認してください。

### 3. Excelテンプレートと保存先を確認する

既定値は次のとおりです。

- テンプレート: `テンプレート/CYCOTサイパト実施結果（京都テック、氏名欄あり）_.xlsx`
- 検出結果: `検出結果/`

GUIではテンプレートファイルと検出結果フォルダーを別々に選択できます。元のテンプレートへ検出結果を上書きしません。

## 起動方法

### Windows

1. `start.bat`をダブルクリックします。
2. 初回は`.env.example`から`.env`が作成され、一度終了します。
3. `.env`の非秘密設定を確認して、再度`start.bat`を実行します。
4. GUIでAPIキー、Supabase情報、氏名、テンプレート、保存先を入力します。
5. 「認証情報を安全に保存」を押します。
6. 「監視開始」を押します。

APIキーとSupabaseパスワードは`.env`へ平文保存せず、OSの資格情報マネージャーへ保存されます。`.env`内の秘密情報欄は空欄のままで構いません。

### macOSまたはLinux

```bash
chmod +x start.sh
./start.sh
```

初回に`.env`が作成された場合は内容を確認し、もう一度`./start.sh`を実行してください。

### コマンドライン実行

仮想環境と設定が準備済みの場合は、プロジェクトルートから次のように実行できます。

Windows:

```powershell
.\venv\Scripts\python.exe src\main.py
```

macOSまたはLinux:

```bash
./venv/bin/python src/main.py
```

人手レビューとレポート出力はGUIから行ってください。

## 既定の動作

安全性と外部サービス消費を優先し、既定値は次のようになっています。

| 機能 | 既定値 | 説明 |
|---|---:|---|
| OpenPhish収集 | 有効 | 公開フィードから候補を取得 |
| CT監視 | 無効 | 有効化した場合だけ証明書ログを監視 |
| 新規urlscan送信 | 無効 | 既存結果の検索と再利用は行う |
| Gemini補助分析 | 無効 | 有効化した場合だけAPIを使用 |
| 自動学習 | 有効 | 人手で確定したレビューだけを使用 |
| 自動通報・自動確定 | 無効 | 設定で有効化することも禁止 |
| 最大スキャン数 | 50件 | GUIから変更可能 |
| スキャン並列数 | 4 | 環境変数では1から8まで指定可能 |

## 処理の流れ

1. OpenPhishまたはCTログからURL候補を取得します。
2. 公式ドメイン除外、候補分類、スコアリング、偏り抑制を行います。
3. フィルタを通過したURLを`logs/filter_passed_urls.log`へ記録します。
4. Supabaseで過去候補との重複を確認します。
5. 実際にスキャン処理へ渡すURLを`logs/scanned_urls.log`へ記録します。
6. urlscan.ioの既存結果を検索し、必要かつ許可されている場合だけ新規スキャンを送信します。
7. DNS、RDAP、ページ根拠、語彙、任意のGemini結果からレビュー優先度を計算します。
8. GUIへレビュー候補を表示します。
9. 人が根拠とURLを確認し、レビュー状態と理由を記録します。
10. 人が確認した対象だけをExcelまたはCSVへ出力します。
11. 自動学習が有効なら、確定レビューを学習例として保存してモデルを評価します。

## URL履歴ログ

監視を開始すると、`logs`フォルダーに次の2ファイルが作成されます。ファイルは上書きせず追記されます。

| ファイル | 記録する内容 |
|---|---|
| `logs/filter_passed_urls.log` | 収集フィルタと偏り抑制を通過したURL |
| `logs/scanned_urls.log` | Supabase重複排除後、スキャン処理へ渡したURL |

1行につき1件のJSONとして保存します。主な項目は、日時、実行セッションID、URL、ドメイン、収集元、候補分類、スコアです。

```json
{"timestamp":"2026-09-06T10:00:00+09:00","session_id":"...","event":"filter_passed","url":"https://example.test/login","domain":"example.test","source":"OpenPhish","candidate_kind":"known_phishing","score":9}
```

URLのパスは識別のため残します。クエリ文字列、フラグメント、URL内のユーザー名とパスワードは保存しません。例えば`https://example.test/login?token=secret#result`は`https://example.test/login`として記録されます。

フィルタ通過ログにだけ存在するURLは、永続的な重複排除やキュー制御などにより、今回のスキャン対象にならなかった候補です。

## 人手レビュー

検出一覧で1件以上の行を選択し、レビュー状態を選び、「状態を更新」を押します。レビュー理由は必須です。

| 状態 | 用途 | 自動学習 |
|---|---|---|
| 未レビュー | 初期状態 | 使用しない |
| 調査中 | 確認を継続する | 使用しない |
| 問題なし | 正常または対象外と確認した | 陰性例として使用 |
| 疑いが強い | 複数根拠により不審と確認した | 陽性例として使用 |
| 判定不能 | 根拠不足で確定できない | 使用しない |
| 資料作成済み | 提出資料を作成できる状態 | 陽性例として使用 |
| 対応確認済み | 対応結果を確認した状態 | 陽性例として使用 |

複数行をまとめて更新した場合、一部の候補で競合や通信エラーが発生しても、保存できたレビューは失われません。失敗した行の番号と理由はダイアログに表示されます。

## 自動学習の始め方

自動学習を使う前に、`202609030002_online_learning.sql`がSupabaseへ適用されていることを確認してください。

1. GUIの「自動学習」を有効にして監視します。既定では有効です。
2. 検出一覧の根拠を確認し、正しいレビュー状態と理由を入力します。
3. 正常な候補には「問題なし」、不審と確認できた候補には「疑いが強い」または「資料作成済み」を付けます。
4. 陽性例と陰性例が全体で各20件に達すると、レビュー保存後に自動学習と評価が始まります。
5. 新モデルが評価基準を満たすとSupabaseへ保存され、次回の監視開始時から読み込まれます。

### 学習条件

- モデル自身の予測を正解データとして再利用しません。
- 「調査中」と「判定不能」は学習に使用しません。
- 同じ候補を再レビューした場合は、最新のレビューだけを使用します。
- 各分類へモデルを適用するには、その分類にも陽性例と陰性例が必要です。
- ブランド名そのものは学習特徴に含めません。特定ブランドへの過学習を抑えます。
- 分類とラベルの組み合わせごとに重みを均衡化します。
- 学習用データとは別の新しい時系列部分で性能を評価します。
- 適合率80%以上で、再現率、F1、誤検知率が基準モデルより大きく悪化しない場合だけ採用します。
- 現行モデルがある場合、十分な追加レビューが集まるまで再学習を保留します。
- モデルは版管理され、過去モデルへロールバックできます。
- 学習モデルは決定的ルールで抽出された候補を削除しません。追加のレビュー候補抽出にだけ使用します。
- 学習モデルの結果だけで通報やレポート確定は行いません。

最初は「教師データ収集中」または「例待ち」と表示されます。これは異常ではありません。陽性例だけを増やすと誤検知を学習できないため、正常と確認できた候補も必ず「問題なし」として記録してください。

## レポート出力

ExcelとCSVの対象は、人が「疑いが強い」または「資料作成済み」と確認した候補だけです。

Excelではテンプレートの既存レイアウトと書式を維持し、最初の空き行へ追記します。URLは誤クリックを防ぐため、ハイパーリンクではなく文字列として保存します。

CSVには次の情報が含まれます。

- 検出日時、ドメイン、URL、対象ブランド
- 候補分類、ルールスコア、優先度、情報充足度
- 人手レビュー状態、理由、担当者、確認日時
- 適用ルール、不足している証拠、IPアドレス、urlscan.io参照URL
- 学習確率と学習モデルのバージョン

ExcelまたはCSVと同じ場所には、SHA-256を記録した`.manifest.json`も作成されます。これはファイルの改変検知用であり、取得時刻の法的証明ではありません。

## API制限とエラー時の動作

GUIにはurlscan.ioとGeminiの使用回数、トークン数、残量、リセット待ち時間など、API応答から取得できた情報が表示されます。

- HTTP 429では待機時間を読み取り、クールダウン状態を表示します。
- 一時的な通信エラーでは指数バックオフで再試行します。
- urlscan.ioの権限エラーでは、その送信元を停止して連続失敗を防ぎます。
- GeminiのJSONが壊れている場合は安全な修復を試し、失敗時は別モデルで再生成します。
- Geminiが最終的に失敗しても、取得済み証拠と決定的ルールでレビュー候補処理を継続します。
- 学習DBが未準備、またはモデルが壊れている場合は、学習モデルを使わず決定的ルールで監視を継続します。
- URL履歴ログを書き込めない場合も監視処理は停止せず、通常ログへ警告します。

## 主な環境変数

GUIで保存したAPIキーとパスワードはOSの資格情報マネージャーから読み込まれます。`.env`は主に非秘密設定に使用します。

| 変数 | 既定値 | 内容 |
|---|---|---|
| `SUPABASE_URL` | 空 | Supabase Project URL |
| `SUPABASE_EMAIL` | 空 | Authentication利用者のメール |
| `REPORTER_NAME` | 空 | レビュー担当者名 |
| `EXCEL_TEMPLATE_PATH` | `テンプレート/...xlsx` | Excelテンプレート |
| `REPORT_OUTPUT_DIR` | `検出結果` | レポート保存先 |
| `MAX_SCAN_COUNT` | `50` | 1回の最大スキャン数 |
| `QUEUE_SIZE` | `500` | 候補キュー上限 |
| `SCAN_WORKERS` | `4` | 並列数。1から8 |
| `PHISHING_FEED_ENABLED` | `true` | OpenPhish収集 |
| `CT_ENABLED` | `false` | CT監視 |
| `URLSCAN_SUBMISSION_ENABLED` | `false` | 新規urlscan送信 |
| `LLM_ENABLED` | `false` | Gemini補助分析 |
| `AUTOMATIC_LEARNING_ENABLED` | `true` | 自動学習 |
| `LEARNING_MINIMUM_PER_CLASS` | `20` | 陽性・陰性それぞれの最低件数 |
| `LEARNING_MAX_EXAMPLES` | `5000` | 1回の学習に使う最大件数 |
| `SIMILARITY_ENABLED` | `false` | 仕様上予約されている類似度機能 |
| `AUTOMATIC_REPORTING_ENABLED` | `false` | 常に無効。`true`は起動時に拒否 |

秘密情報用の変数名も`.env.example`にありますが、通常はGUIからOS資格情報マネージャーへ保存してください。

## セキュリティ設計

- ローカルPCから候補サイトへ直接アクセスせず、urlscan.ioの観測結果を使用します。
- URL内の認証情報とIPアドレス直接指定をスキャン対象として拒否します。
- 新規urlscan送信は既定で無効です。
- APIキーとパスワードはOSの資格情報マネージャーへ保存します。
- Supabaseは一般利用者認証、強制RLS、限定RPCを使用します。
- SupabaseへURLクエリ、DOM本文、スクリーンショット本体、APIキーを保存しません。
- ローカルURL履歴にもクエリ、フラグメント、URL認証情報を保存しません。
- 取得したページ本文は命令として扱わず、プロンプトインジェクション表現を除去してからGeminiへ渡します。
- ExcelとCSVでは数式として解釈される危険な文字列を無害化します。
- 自動判定と人手レビューを分離し、人手確認前の自動通報を行いません。

## プロジェクト構成

```text
Automatic-detection-of-fake-sites-main/
|-- src/
|   |-- gui.py                  デスクトップGUI
|   |-- worker.py               GUI用の収集・スキャン処理
|   |-- main.py                 CLI用パイプライン
|   |-- monitor.py              OpenPhish・CT候補収集
|   |-- scanner.py              urlscan.io連携と証拠抽出
|   |-- analyzer.py             Gemini補助分析と応答復旧
|   |-- verification.py         複数根拠による候補判定
|   |-- risk_scoring.py         決定的ルールと優先度
|   |-- scam_vocabulary.py      詐欺関連語彙の評価
|   |-- domain_metadata.py      DNS・RDAP情報取得
|   |-- url_normalization.py    URL正規化と安全化
|   |-- url_audit_log.py        URL履歴ログ
|   |-- online_learning.py      レビュー駆動の自動学習
|   |-- supabase_repository.py  Supabase認証とRPC
|   |-- reporter.py             Excelレポート
|   `-- key_manager.py          OS資格情報管理
|-- data/
|   `-- scam_words_dataset_expanded.json
|-- supabase/migrations/
|-- テンプレート/
|-- logs/
|-- 検出結果/
|-- tests/
|-- .env.example
|-- requirements.txt
|-- start.bat
`-- start.sh
```

## テスト

Windows:

```powershell
.\venv\Scripts\python.exe -m unittest discover -s tests -v
.\venv\Scripts\python.exe -m compileall -q src tests
```

macOSまたはLinux:

```bash
./venv/bin/python -m unittest discover -s tests -v
./venv/bin/python -m compileall -q src tests
```

テストには、複数分類の候補検出、誤検知防止、API制限表示、Gemini応答復旧、Excelテンプレート維持、Supabase RPC、URL安全化、URL履歴ログ、自動学習が含まれます。

## トラブルシューティング

### Supabaseへ接続できない

- Project URLが`https://プロジェクトID.supabase.co`形式か確認します。
- Authentication利用者のメールとパスワードを確認します。
- Database Passwordを入力していないか確認します。
- Publishable keyとProject URLが同じプロジェクトのものか確認します。
- 3本のマイグレーションSQLを順番に実行したか確認します。

### 自動学習が始まらない

- `202609030002_online_learning.sql`の適用を確認します。
- GUIの「自動学習」が有効か確認します。
- 陽性例と陰性例がそれぞれ最低件数に達しているか確認します。
- 同じ分類内にも陽性例と陰性例があるか確認します。
- 「調査中」と「判定不能」だけを登録していないか確認します。
- 評価基準未達の場合は、現行モデルが維持される正常な動作です。

### URLログに件数差がある

正常な場合があります。フィルタ通過後、Supabase重複排除、キュー制御、最大スキャン数、停止操作などにより、すべての候補がスキャンされるとは限りません。

### API制限エラーが表示される

GUIのAPI使用状況で残量と待機時間を確認してください。上限値は契約やサービス側の変更により異なるため、各サービスの管理画面も確認してください。

### Excelへ正しく書き込めない

- GUIで正しいテンプレートを選択したか確認します。
- テンプレートと検出結果の保存先が別になっているか確認します。
- 対象候補が「疑いが強い」または「資料作成済み」になっているか確認します。
- Excelで出力先ファイルを開いたままにしていないか確認します。

## 利用上の注意

本ツールは、サイバーセキュリティ研究、教育、公的なサイバーパトロール活動の支援を目的としています。

- 自動判定を犯罪や違法性の確定判断として扱わないでください。
- 通報前に証拠、対象組織、利用規約、適用法令を人が確認してください。
- 収集データ、APIキー、利用者情報を適切に管理してください。
- 不正アクセス、攻撃、購入、接触などの目的へ使用しないでください。
- 外部サービスの利用規約とレート制限を守ってください。

詳細な要件は`不審サイト収集システム_AI向け仕様書.md`を参照してください。
