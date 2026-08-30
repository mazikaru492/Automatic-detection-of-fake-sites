"""
analyzer.py — AI Analysis モジュール (判定と要約)

Gemini API を用いてスクリーンショット + HTML テキストをマルチモーダル入力とし、
詐欺サイトかどうかを JSON 形式で判定させる。

レートリミット対策:
- Gemini API 無料枠: 15 リクエスト/分
- リクエスト前後に time.sleep(5) を挿入
- 429 エラー時は指数バックオフで最大 3 回リトライ
"""

import json
import logging
import re
import time
from typing import Optional

import requests
from google import genai
from google.genai import types

logger = logging.getLogger(__name__)

# Gemini の安全設定（詐欺サイトコンテンツの分析に必要なため、
# HARM_BLOCK_THRESHOLD を緩和する必要はない — デフォルトで十分）
DEFAULT_GEMINI_MODEL = "gemini-2.0-flash"

# 詐欺判定プロンプト
ANALYSIS_PROMPT = """あなたはサイバーセキュリティの専門家です。
以下のWebサイトのスクリーンショット画像とHTMLテキストを分析し、
このサイトが日本のユーザーを狙った偽ショッピングサイトまたはフィッシングサイトかどうかを判定してください。

【判定基準】
- 日本の著名ブランド（佐川急便、イオン、ヤマト運輸、Amazon、メルカリ、楽天等）を偽装していないか
- 不自然または機械翻訳的な日本語が使用されていないか
- 極端な値引きや「在庫限り」などの偽の緊急性を煽る文言がないか
- 個人情報やクレジットカード情報を不正に収集しようとしていないか
- URLやドメインが正規のブランドと異なる偽物でないか

【出力形式】
以下のJSONのみを返してください。他のテキストは一切含めないでください。
{
  "is_scam": true または false,
  "target_brand": "偽装対象ブランド名（不明の場合は空文字）",
  "features": "不審な特徴の説明（200字以内）"
}

HTMLテキスト:
{html_text}
"""


class AnalysisResult:
    """AI 分析結果を格納するデータクラス"""

    def __init__(self, is_scam: bool, target_brand: str, features: str):
        self.is_scam = is_scam
        self.target_brand = target_brand
        self.features = features

    def to_dict(self) -> dict:
        return {
            "is_scam": self.is_scam,
            "target_brand": self.target_brand,
            "features": self.features,
        }

    def __repr__(self) -> str:
        return (
            f"AnalysisResult(is_scam={self.is_scam}, "
            f"target_brand='{self.target_brand}')"
        )


class ScamAnalyzer:
    """
    Gemini API を使った詐欺サイト分析クラス。

    なぜクラスにするか:
        Gemini クライアントを一度だけ初期化して再利用し、
        接続コストを削減するため。
    """

    def __init__(self, api_key: str, model: str = DEFAULT_GEMINI_MODEL):
        self._client = genai.Client(api_key=api_key)
        self._model = model
        self._request_count = 0

    def analyze(
        self,
        screenshot_url: str,
        dom_text: str,
        max_retries: int = 3,
    ) -> Optional[AnalysisResult]:
        """
        スクリーンショット URL と DOM テキストを分析し、詐欺判定を返す。

        Args:
            screenshot_url: urlscan.io のスクリーンショット画像 URL
            dom_text: urlscan.io から取得した HTML テキスト（先頭5000文字）
            max_retries: 429 エラー時の最大リトライ回数

        Returns:
            AnalysisResult または None（解析失敗時）
        """
        # レートリミット対策: リクエスト前に必ず sleep
        # なぜ5秒か: 15回/分 = 4秒/リクエスト。余裕を持って5秒とする。
        logger.debug(f"Gemini API リクエスト前スリープ (5秒)")
        time.sleep(5)

        for attempt in range(max_retries):
            try:
                result = self._call_gemini(screenshot_url, dom_text)
                if result:
                    # リクエスト後も sleep でレートリミット厳守
                    time.sleep(5)
                    self._request_count += 1
                    return result

            except Exception as e:
                error_str = str(e).lower()

                if "429" in error_str or "quota" in error_str or "rate" in error_str:
                    # 指数バックオフ: 1回目30秒, 2回目60秒, 3回目120秒
                    wait_time = 30 * (2 ** attempt)
                    logger.warning(
                        f"Gemini API レートリミット (試行 {attempt+1}/{max_retries}) — "
                        f"{wait_time}秒後にリトライ"
                    )
                    time.sleep(wait_time)
                    continue

                logger.error(f"Gemini API エラー (試行 {attempt+1}): {e}")
                if attempt == max_retries - 1:
                    return None
                time.sleep(10)

        return None

    def _call_gemini(
        self, screenshot_url: str, dom_text: str
    ) -> Optional[AnalysisResult]:
        """
        Gemini API を実際に呼び出す内部メソッド。

        マルチモーダル入力の構成:
        1. スクリーンショット画像 (URL から直接参照)
        2. HTML テキスト (プロンプトに埋め込み)
        3. 判定指示プロンプト

        なぜ画像を URL で渡すか:
        - Gemini 2.0 Flash は URL から直接画像を取得できる。
        - Base64 エンコードより効率的でトークン消費を抑えられる。
        - ただし urlscan.io の画像が公開されていることが前提（public scan）。
        """
        # スクリーンショット画像を URL 経由で取得して渡す
        image_part = self._fetch_image_as_part(screenshot_url)

        prompt_text = ANALYSIS_PROMPT.format(
            html_text=dom_text[:3000] if dom_text else "（HTML取得不可）"
        )

        # コンテンツパーツを構築
        parts: list = [prompt_text]
        if image_part:
            parts.insert(0, image_part)  # 画像を先に渡す（モデルのベストプラクティス）

        response = self._client.models.generate_content(
            model=self._model,
            contents=parts,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                temperature=0.1,  # 判定の一貫性を高めるため低い温度を設定
                max_output_tokens=512,
            ),
        )

        raw_text = response.text.strip()
        return self._parse_response(raw_text)

    def _fetch_image_as_part(self, image_url: str) -> Optional[types.Part]:
        """
        スクリーンショット URL から画像を取得して Gemini の Part オブジェクトにする。

        urlscan.io のスクリーンショットは公開 URL なので直接取得可能。
        なお、このアクセスは urlscan.io サーバーへのアクセスであり、
        不審サイトへの直接アクセスではないため安全。
        """
        try:
            response = requests.get(image_url, timeout=30)
            if response.status_code == 200:
                return types.Part.from_bytes(
                    data=response.content,
                    mime_type="image/png",
                )
        except Exception as e:
            logger.debug(f"スクリーンショット取得失敗: {e}")
        return None

    def _parse_response(self, raw_text: str) -> Optional[AnalysisResult]:
        """
        Gemini の出力テキストを AnalysisResult にパースする。

        なぜ専用パーサを作るか:
        - LLM の出力は常に完全な JSON とは限らない（マークダウンコードブロック等）。
        - 堅牢なパース処理を集中管理することでメンテナンス性を高めるため。
        """
        if not raw_text:
            logger.warning("Gemini から空のレスポンスを受け取りました")
            return None

        # JSON ブロックをマークダウンコードフェンスから抽出する試み
        # （例: ```json\n{...}\n```）
        json_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw_text, re.DOTALL)
        if json_match:
            raw_text = json_match.group(1)

        # JSON 部分のみを抽出（余分なテキストがある場合）
        brace_match = re.search(r"\{.*\}", raw_text, re.DOTALL)
        if brace_match:
            raw_text = brace_match.group(0)

        try:
            data = json.loads(raw_text)
            return AnalysisResult(
                is_scam=bool(data.get("is_scam", False)),
                target_brand=str(data.get("target_brand", "")),
                features=str(data.get("features", "")),
            )
        except (json.JSONDecodeError, TypeError, ValueError) as e:
            logger.error(f"Gemini レスポンスのパース失敗: {e}\n生テキスト: {raw_text[:200]}")
            return None

    @property
    def request_count(self) -> int:
        """総 API リクエスト数（監視用）"""
        return self._request_count
