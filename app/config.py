from pydantic_settings import BaseSettings
from pathlib import Path

class Settings(BaseSettings):
    # Paths
    data_dir: Path = Path("/data")
    db_path: Path = Path("/data/healer.db")

    # NPM container
    npm_container: str = "nginx-app-1"
    npm_db_path_in_container: str = "/data/database.sqlite"

    # Defaults
    default_grace_minutes: int = 10
    check_interval_seconds: int = 60
    scan_timeout_seconds: int = 30

    # UI
    host: str = "0.0.0.0"
    port: int = 8787

    class Config:
        env_file = ".env"

settings = Settings()
