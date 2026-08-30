import json
import logging
import re
import time
from typing import Optional
import requests
from google import genai
from google.genai import types
logger = logging.getLogger(__name__)
DEFAULT_GEMINI_MODEL = 'gemini-2.0-flash'
ANALYSIS_PROMPT = 'あなたはサイバーセキュリティの専門家です。\n以下のWebサイトのスクリーンショット画像とHTMLテキストを分析し、\nこのサイトが日本のユーザーを狙った偽ショッピングサイトまたはフィッシングサイトかどうかを判定してください。\n\n【判定基準】\n- 日本の著名ブランド（佐川急便、イオン、ヤマト運輸、Amazon、メルカリ、楽天等）を偽装していないか\n- 不自然または機械翻訳的な日本語が使用されていないか\n- 極端な値引きや「在庫限り」などの偽の緊急性を煽る文言がないか\n- 個人情報やクレジットカード情報を不正に収集しようとしていないか\n- URLやドメインが正規のブランドと異なる偽物でないか\n\n【出力形式】\n以下のJSONのみを返してください。他のテキストは一切含めないでください。\n{\n  "is_scam": true または false,\n  "target_brand": "偽装対象ブランド名（不明の場合は空文字）",\n  "features": "不審な特徴の説明（200字以内）"\n}\n\nHTMLテキスト:\n{html_text}\n'

class AnalysisResult:

    def __init__(self, is_scam: bool, target_brand: str, features: str):
        self.is_scam = is_scam
        self.target_brand = target_brand
        self.features = features

    def to_dict(self) -> dict:
        return {'is_scam': self.is_scam, 'target_brand': self.target_brand, 'features': self.features}

    def __repr__(self) -> str:
        return f"AnalysisResult(is_scam={self.is_scam}, target_brand='{self.target_brand}')"

class ScamAnalyzer:

    def __init__(self, api_key: str, model: str=DEFAULT_GEMINI_MODEL):
        self._client = genai.Client(api_key=api_key)
        self._model = model
        self._request_count = 0

    def analyze(self, screenshot_url: str, dom_text: str, max_retries: int=3) -> Optional[AnalysisResult]:
        logger.debug(f'Gemini API リクエスト前スリープ (5秒)')
        time.sleep(5)
        for attempt in range(max_retries):
            try:
                result = self._call_gemini(screenshot_url, dom_text)
                if result:
                    time.sleep(5)
                    self._request_count += 1
                    return result
            except Exception as e:
                error_str = str(e).lower()
                if '429' in error_str or 'quota' in error_str or 'rate' in error_str:
                    wait_time = 30 * 2 ** attempt
                    logger.warning(f'Gemini API レートリミット (試行 {attempt + 1}/{max_retries}) — {wait_time}秒後にリトライ')
                    time.sleep(wait_time)
                    continue
                logger.error(f'Gemini API エラー (試行 {attempt + 1}): {e}')
                if attempt == max_retries - 1:
                    return None
                time.sleep(10)
        return None

    def _call_gemini(self, screenshot_url: str, dom_text: str) -> Optional[AnalysisResult]:
        image_part = self._fetch_image_as_part(screenshot_url)
        prompt_text = ANALYSIS_PROMPT.format(html_text=dom_text[:3000] if dom_text else '（HTML取得不可）')
        parts: list = [prompt_text]
        if image_part:
            parts.insert(0, image_part)
        response = self._client.models.generate_content(model=self._model, contents=parts, config=types.GenerateContentConfig(response_mime_type='application/json', temperature=0.1, max_output_tokens=512))
        raw_text = response.text.strip()
        return self._parse_response(raw_text)

    def _fetch_image_as_part(self, image_url: str) -> Optional[types.Part]:
        try:
            response = requests.get(image_url, timeout=30)
            if response.status_code == 200:
                return types.Part.from_bytes(data=response.content, mime_type='image/png')
        except Exception as e:
            logger.debug(f'スクリーンショット取得失敗: {e}')
        return None

    def _parse_response(self, raw_text: str) -> Optional[AnalysisResult]:
        if not raw_text:
            logger.warning('Gemini から空のレスポンスを受け取りました')
            return None
        json_match = re.search('```(?:json)?\\s*(\\{.*?\\})\\s*```', raw_text, re.DOTALL)
        if json_match:
            raw_text = json_match.group(1)
        brace_match = re.search('\\{.*\\}', raw_text, re.DOTALL)
        if brace_match:
            raw_text = brace_match.group(0)
        try:
            data = json.loads(raw_text)
            return AnalysisResult(is_scam=bool(data.get('is_scam', False)), target_brand=str(data.get('target_brand', '')), features=str(data.get('features', '')))
        except (json.JSONDecodeError, TypeError, ValueError) as e:
            logger.error(f'Gemini レスポンスのパース失敗: {e}\n生テキスト: {raw_text[:200]}')
            return None

    @property
    def request_count(self) -> int:
        return self._request_count
