"""Environment configuration (prefix PII_). Masking behaviour itself lives in the settings the admin API manages."""
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parent.parent


class Config(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="PII_", env_file=(".env", ROOT / ".env"), extra="ignore")

    database_url: str = "sqlite:///./data/pii.db"
    admin_key: str = ""                  # protects the admin page and API; empty: they answer only from the server itself
    settings_file: str = ""              # optional JSON that seeds the settings on first start
    max_text_chars: int = 200_000
    max_upload_mb: int = 50
    job_ttl_minutes: int = 60           # how long a masked file waits for CMS to download it
    job_max_mb: int = 500               # total size of masked files held; the oldest go first
    warm_up: bool = True                 # load the detector at start-up instead of on the first request
    spacy_model: str = "en_core_web_sm"
    tessdata_dir: str = ""               # Tesseract language data for OCR (else TESSDATA_PREFIX or the usual places)
    log_level: str = "INFO"


config = Config()
