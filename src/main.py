"""
main.py — オーケストレーター

4つのモジュール（monitor → scanner → analyzer → reporter）を
パイプラインとして統括する。

実行フロー:
1. DomainMonitor がバックグラウンドスレッドで certstream を購読
2. メインスレッドがキューからドメインを取り出す
3. UrlScanner で urlscan.io 経由の安全なスキャンを実行
4. ScamAnalyzer で Gemini マルチモーダル分析
5. ExcelReporter で詐欺判定（is_scam=True）のデータを追記

終了方法:
- Ctrl+C で安全に停止し、それまでの結果を Excel に保存する。
"""

import logging
import os
import queue
import signal
import sys
import time
from pathlib import Path

from dotenv import load_dotenv

# プロジェクトルートから実行されることを想定した相対インポート対策
sys.path.insert(0, str(Path(__file__).parent))

from monitor import DomainMonitor
from scanner import UrlScanner
from analyzer import ScamAnalyzer
from reporter import ExcelReporter

# -----------------------------------------------------------------------
# ロギング設定
# -----------------------------------------------------------------------

def setup_logging() -> None:
    """
    コンソール + ファイル二重出力のロギングを設定する。

    なぜファイル出力も設定するか:
    - 長時間実行中に画面が流れても、ログファイルで後から確認できるため。
    - 警察提出時の証拠ログとして機能するため。
    """
    log_format = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    log_date_format = "%Y-%m-%d %H:%M:%S"

    # ログディレクトリ作成
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)

    log_filename = log_dir / f"scan_{time.strftime('%Y%m%d_%H%M%S')}.log"

    logging.basicConfig(
        level=logging.INFO,
        format=log_format,
        datefmt=log_date_format,
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(str(log_filename), encoding="utf-8"),
        ],
    )

    # 外部ライブラリのノイジーなログを抑制
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("websocket").setLevel(logging.WARNING)
    logging.getLogger("certstream").setLevel(logging.WARNING)


logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------
# 設定読み込み
# -----------------------------------------------------------------------

def load_config() -> dict:
    """
    .env ファイルから設定を読み込み、検証する。

    なぜ早期失敗（fail-fast）か:
    - APIキーが欠如したまま長時間実行し、後で失敗するよりも
      起動時に即座にエラーを検出した方が運用コストが低いため。
    """
    load_dotenv()

    config = {
        "urlscan_api_key": os.getenv("URLSCAN_API_KEY", ""),
        "gemini_api_key": os.getenv("GEMINI_API_KEY", ""),
        "excel_template_path": os.getenv(
            "EXCEL_TEMPLATE_PATH",
            "CYCOTサイパト実施結果（京都テック、氏名欄あり）_.xls"
        ),
        "max_scan_count": int(os.getenv("MAX_SCAN_COUNT", "50")),
        "queue_size": int(os.getenv("QUEUE_SIZE", "500")),
    }

    # 必須設定のバリデーション
    missing = []
    if not config["urlscan_api_key"]:
        missing.append("URLSCAN_API_KEY")
    if not config["gemini_api_key"]:
        missing.append("GEMINI_API_KEY")

    if missing:
        logger.error(
            f"❌ 必須の環境変数が設定されていません: {', '.join(missing)}\n"
            f"   .env ファイルを確認してください（.env.example を参照）"
        )
        sys.exit(1)

    return config


# -----------------------------------------------------------------------
# パイプライン実行
# -----------------------------------------------------------------------

class Pipeline:
    """
    4モジュールを統合するパイプラインクラス。

    なぜクラスにするか:
    - シグナルハンドラ（Ctrl+C）から安全に終了処理を呼び出すために
      状態（reporter）への参照が必要なため。
    """

    def __init__(self, config: dict):
        self._config = config
        self._domain_queue: queue.Queue = queue.Queue(
            maxsize=config["queue_size"]
        )
        self._monitor: DomainMonitor = DomainMonitor(self._domain_queue)
        self._scanner: UrlScanner = UrlScanner(config["urlscan_api_key"])
        self._analyzer: ScamAnalyzer = ScamAnalyzer(config["gemini_api_key"])
        self._reporter: ExcelReporter = ExcelReporter(
            config["excel_template_path"]
        )
        self._running = True
        self._scan_count = 0
        self._scam_count = 0
        self._max_scan_count = config["max_scan_count"]

    def run(self) -> None:
        """
        メインループ。

        certstream を購読しながら、キューからドメインを取り出して
        順次処理する。

        なぜ同期ループか:
        - urlscan.io と Gemini API のレートリミット制御が同期的に
          必要なため、非同期化すると制御が複雑になる。
        - certstream のみスレッド分離すれば十分。
        """
        logger.info("=" * 60)
        logger.info("🛡️  日本向け詐欺サイト自動検知システム 起動")
        logger.info("=" * 60)
        logger.info(f"最大スキャン数: {self._max_scan_count}")
        logger.info("Ctrl+C で安全に停止し、Excel に結果を保存します")
        logger.info("=" * 60)

        # certstream 監視を開始（バックグラウンドスレッド）
        self._monitor.start()

        # certstream が接続を確立するまで少し待機
        time.sleep(3)

        try:
            self._process_loop()
        except KeyboardInterrupt:
            logger.info("\n⏹️  停止シグナルを受信しました")
        finally:
            self._shutdown()

    def _process_loop(self) -> None:
        """キューからドメインを取り出して処理するメインループ"""
        while self._running:
            # スキャン上限チェック
            if self._scan_count >= self._max_scan_count:
                logger.info(
                    f"✅ 最大スキャン数 ({self._max_scan_count}) に達しました。終了します。"
                )
                break

            # キューからドメインを取り出す（タイムアウト付き）
            try:
                domain_info = self._domain_queue.get(timeout=5)
            except queue.Empty:
                # キューが空の場合は待機してリトライ
                stats = self._monitor.stats
                logger.debug(
                    f"キュー待機中... (監視済: {stats['processed']}, "
                    f"検出: {stats['accepted']})"
                )
                continue

            self._process_domain(domain_info)

    def _process_domain(self, domain_info: dict) -> None:
        """
        単一のドメインを処理する。

        各ステップでエラーが発生しても次のドメインに進めるよう、
        例外をキャッチして処理を継続する（フォールトトレランス）。
        """
        url = domain_info["url"]
        domain = domain_info["domain"]
        detected_at = domain_info["detected_at"]

        logger.info(f"\n{'─' * 50}")
        logger.info(f"🔬 処理開始 [{self._scan_count + 1}/{self._max_scan_count}]: {domain}")

        # STEP 1: urlscan.io でスキャン（証拠保全）
        logger.info(f"  📡 [1/3] urlscan.io スキャン送信中...")
        scan_result = self._scanner.scan(url)

        if scan_result is None:
            logger.warning(f"  ⚠️  スキャン失敗。このドメインをスキップします: {domain}")
            return

        logger.info(
            f"  ✅ スキャン完了 — IP: {scan_result.get('ip_address', 'N/A')}, "
            f"レポート: {scan_result.get('scan_url', 'N/A')}"
        )

        # urlscan.io レートリミット対策
        time.sleep(2)
        self._scan_count += 1

        # STEP 2: Gemini AI で詐欺判定
        logger.info(f"  🤖 [2/3] Gemini AI 分析中...")
        analysis = self._analyzer.analyze(
            screenshot_url=scan_result["screenshot_url"],
            dom_text=scan_result["dom_text"],
        )

        if analysis is None:
            logger.warning(f"  ⚠️  AI 分析失敗。このドメインをスキップします: {domain}")
            return

        verdict = "🚨 詐欺" if analysis.is_scam else "✅ 正常"
        logger.info(
            f"  {verdict} — ブランド: {analysis.target_brand or 'N/A'}"
        )
        logger.info(f"  特徴: {analysis.features[:100]}..." if len(analysis.features) > 100 else f"  特徴: {analysis.features}")

        # STEP 3: 詐欺と判定された場合のみ Excel に追記
        if analysis.is_scam:
            logger.info(f"  📝 [3/3] Excel に追記中...")
            self._reporter.append_record(
                url=url,
                target_brand=analysis.target_brand or domain,
                features=analysis.features,
                detected_at=detected_at,
            )
            self._scam_count += 1
            logger.info(
                f"  ✅ 追記完了（累計詐欺件数: {self._scam_count}）"
            )
        else:
            logger.info(f"  ℹ️  [3/3] 詐欺ではないため記録をスキップ")

    def _shutdown(self) -> None:
        """
        安全なシャットダウン処理。

        なぜ finally ブロックで呼ぶか:
        - Ctrl+C や例外終了時でも Excel の保存を保証するため。
        - 中断した場合でも途中の成果が失われない。
        """
        self._running = False
        self._monitor.stop()

        logger.info("\n" + "=" * 60)
        logger.info("📊 実行結果サマリー")
        logger.info("=" * 60)
        logger.info(f"  スキャン実行数: {self._scan_count}")
        logger.info(f"  詐欺判定数:     {self._scam_count}")
        logger.info(f"  Gemini リクエスト数: {self._analyzer.request_count}")

        # Excel に結果を保存
        if self._reporter.appended_count > 0:
            saved_path = self._reporter.save()
            logger.info(f"  📄 Excel 保存先: {saved_path}")
        else:
            logger.info("  ℹ️  追記データがないため Excel は保存しませんでした")

        logger.info("=" * 60)
        logger.info("🏁 システムを正常終了しました")


# -----------------------------------------------------------------------
# エントリーポイント
# -----------------------------------------------------------------------

def main() -> None:
    setup_logging()
    config = load_config()
    pipeline = Pipeline(config)
    pipeline.run()


if __name__ == "__main__":
    main()
