import os
from pathlib import Path
from typing import List
from dotenv import load_dotenv

# Base Directory Resolution
BASE_DIR = Path(__file__).resolve().parent.parent

# Load environment variables strictly from .env if present
env_file_path = BASE_DIR / ".env"
if env_file_path.exists():
    load_dotenv(dotenv_path=env_file_path)
else:
    load_dotenv()


class Settings:
    # Server network binding
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "8659"))

    # Environment
    DEBUG: bool = os.getenv("DEBUG", "false").lower() in ("true", "1", "yes")
    APP_ENV: str = os.getenv("APP_ENV", "production")

    # SQLite Database persistence
    # Default to /opt/hs_wss/data/scanner.db, fallback to local data dir if running in test
    _default_db_dir = BASE_DIR / "data"
    _default_db_path = str(_default_db_dir / "scanner.db")
    DB_PATH: str = os.getenv("DB_PATH", _default_db_path)
    PURGE_ON_STARTUP: bool = os.getenv("PURGE_ON_STARTUP", "true").lower() in ("true", "1", "yes")

    # Crawler & Scanner Limits
    MAX_CRAWL_DEPTH: int = int(os.getenv("MAX_CRAWL_DEPTH", "3"))
    MAX_CRAWL_PAGES: int = int(os.getenv("MAX_CRAWL_PAGES", "50"))
    PAGE_TIMEOUT_MS: int = int(os.getenv("PAGE_TIMEOUT_MS", "20000"))
    HEADLESS: bool = os.getenv("HEADLESS", "true").lower() in ("true", "1", "yes")
    CONCURRENT_PAGES: int = int(os.getenv("CONCURRENT_PAGES", "1"))

    # Network & SSRF Security Controls
    BLOCK_METADATA_IPS: bool = os.getenv("BLOCK_METADATA_IPS", "true").lower() in ("true", "1", "yes")
    ALLOWED_SCHEMES: List[str] = [
        s.strip().lower() for s in os.getenv("ALLOWED_SCHEMES", "http,https").split(",") if s.strip()
    ]

    # User Agent
    USER_AGENT: str = os.getenv(
        "USER_AGENT",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 HS-WSS/1.0"
    )

    # Custom rules file path
    CUSTOM_REGEX_FILE: str = os.getenv("CUSTOM_REGEX_FILE", str(BASE_DIR / "data" / "custom_rules.json"))


settings = Settings()
