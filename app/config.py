"""Environment configuration (prefix PII_). Masking behaviour itself lives in the settings the admin API manages."""
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parent.parent


class Config(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="PII_", env_file=(".env", ROOT / ".env"), extra="ignore")

    database_url: str = "sqlite:///./data/pii.db"
    master_key: str = ""                 # Fernet key(s), comma-separated, newest first; encrypts the vault
    bootstrap_admin_key: str = ""        # created as an admin key on start if no key with this value exists
    settings_file: str = ""              # optional JSON that seeds the settings on first start
    max_text_chars: int = 200_000
    max_upload_mb: int = 20
    default_rate_limit: int = 120        # requests per minute for a key created without its own limit
    warm_up: bool = True                 # load the detector at start-up instead of on the first request
    spacy_model: str = "en_core_web_sm"
    tessdata_dir: str = ""               # Tesseract language data for OCR (else TESSDATA_PREFIX or the usual places)
    log_level: str = "INFO"


config = Config()
