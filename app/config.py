from pydantic_settings import BaseSettings
from pathlib import Path
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

class Settings(BaseSettings):
    # Paths
    data_dir: Path = Path("/data")
    db_path: Path = Path("/data/healer.db")

    # NPM container
    npm_container: str = "nginx-app-1"
    npm_db_path_in_container: str = "/data/database.sqlite"

    # Defaults
    default_grace_minutes: int = 10
    check_interval_seconds: int = 600
    scan_timeout_seconds: int = 30
    timezone: str = "America/New_York"

    # UI
    host: str = "0.0.0.0"
    port: int = 8787

    class Config:
        env_file = ".env"

settings = Settings()


def current_time() -> datetime:
    return datetime.now(ZoneInfo(settings.timezone))


def parse_timestamp(value: str) -> datetime:
    timestamp = datetime.fromisoformat(value)
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    return timestamp.astimezone(ZoneInfo(settings.timezone))


def format_timestamp(value: str) -> str:
    timestamp = parse_timestamp(value)
    time = timestamp.strftime("%I:%M %p").lstrip("0")
    return f"{timestamp.strftime('%b')} {timestamp.day}, {timestamp.year} at {time} {timestamp.tzname()}"


def time_ago(value: str) -> str:
    elapsed_seconds = max(0, (current_time() - parse_timestamp(value)).total_seconds())
    if elapsed_seconds < 60:
        return "0 minutes ago"
    if elapsed_seconds < 3600:
        minutes = int(elapsed_seconds // 60)
        return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
    if elapsed_seconds < 86400:
        hours = int(elapsed_seconds // 3600)
        return f"{hours} hour{'s' if hours != 1 else ''} ago"
    days = int(elapsed_seconds // 86400)
    return f"{days} day{'s' if days != 1 else ''} ago"
