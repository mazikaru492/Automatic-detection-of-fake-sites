import os
import logging
from typing import Optional
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

SERVICE_NAME = "CYCOT_FakeSiteDetector"
URLSCAN_KEY_NAME = "urlscan_api_key"
GEMINI_KEY_NAME = "gemini_api_key"

def _get_keyring():
    try:
        import keyring
        return keyring
    except ImportError:
        logger.warning("keyring モジュールが利用できません")
        return None

def save_api_key(key_name: str, value: str) -> bool:
    if not value:
        return False
    kr = _get_keyring()
    if kr:
        try:
            kr.set_password(SERVICE_NAME, key_name, value)
            return True
        except Exception as e:
            logger.error(f"セキュアストレージへの保存に失敗しました: {e}")
    return False

def get_api_key(key_name: str) -> Optional[str]:
    kr = _get_keyring()
    if kr:
        try:
            val = kr.get_password(SERVICE_NAME, key_name)
            if val:
                return val
        except Exception as e:
            logger.debug(f"セキュアストレージからの取得エラー: {e}")
    
    load_dotenv()
    env_map = {
        URLSCAN_KEY_NAME: "URLSCAN_API_KEY",
        GEMINI_KEY_NAME: "GEMINI_API_KEY",
    }
    env_var = env_map.get(key_name, key_name.upper())
    return os.getenv(env_var, None)

def delete_api_key(key_name: str) -> bool:
    kr = _get_keyring()
    if kr:
        try:
            kr.delete_password(SERVICE_NAME, key_name)
            return True
        except Exception:
            return False
    return False

def load_all_keys() -> dict[str, str]:
    return {
        URLSCAN_KEY_NAME: get_api_key(URLSCAN_KEY_NAME) or "",
        GEMINI_KEY_NAME: get_api_key(GEMINI_KEY_NAME) or "",
    }
