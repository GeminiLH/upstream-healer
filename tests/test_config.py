"""Tests for app.config — Settings and time helpers."""
from __future__ import annotations

from datetime import timedelta, timezone
from pathlib import Path

from app.config import Settings, current_time, format_timestamp, parse_timestamp, time_ago


class TestSettings:
    def test_defaults(self):
        s = Settings()
        assert s.data_dir == Path("/data")
        assert s.db_path == Path("/data/healer.db")
        assert s.npm_container == "nginx-app-1"
        assert s.npm_db_path_in_container == "/data/database.sqlite"
        assert s.default_grace_minutes == 10
        assert s.check_interval_seconds == 600
        assert s.scan_timeout_seconds == 30
        assert s.timezone == "America/New_York"
        assert s.host == "0.0.0.0"
        assert s.port == 8787

    def test_npm_fallback_defaults(self):
        s = Settings()
        assert s.npm_db_host == "nginx-db-1"
        assert s.npm_db_port == 3306
        assert s.npm_db_user == ""
        assert s.npm_db_password == ""
        assert s.npm_db_name == "proxy_manager"

    def test_environment_overrides(self, monkeypatch):
        monkeypatch.setenv("NPM_CONTAINER", "custom-nginx-app")
        monkeypatch.setenv("NPM_DB_HOST", "10.0.0.99")
        monkeypatch.setenv("NPM_DB_PORT", "3307")
        monkeypatch.setenv("NPM_DB_USER", "npmuser")
        monkeypatch.setenv("NPM_DB_PASSWORD", "s3cret")
        monkeypatch.setenv("NPM_DB_NAME", "npmdb")
        s = Settings()
        assert s.npm_container == "custom-nginx-app"
        assert s.npm_db_host == "10.0.0.99"
        assert s.npm_db_port == 3307
        assert s.npm_db_user == "npmuser"
        assert s.npm_db_password == "s3cret"
        assert s.npm_db_name == "npmdb"


class TestTimeHelpers:
    def test_current_time_is_timezone_aware(self):
        now = current_time()
        assert now.tzinfo is not None
        assert now.utcoffset() is not None

    def test_parse_timestamp_naive_treated_as_utc(self):
        dt = parse_timestamp("2025-01-15T12:00:00")
        # naive input is treated as UTC, then rendered in the app's zone
        assert dt.astimezone(timezone.utc).hour == 12
        assert dt.tzname() == "EST"  # America/New_York in January

    def test_parse_timestamp_with_explicit_offset(self):
        dt = parse_timestamp("2025-01-15T12:00:00+05:00")
        assert dt.astimezone(timezone.utc).hour == 7  # 12:00+05:00 == 07:00 UTC

    def test_parse_timestamp_z_suffix(self):
        dt = parse_timestamp("2025-01-15T12:00:00Z")
        assert dt.tzinfo is not None

    def test_format_timestamp(self):
        assert format_timestamp("2025-01-15T12:30:00") == "Jan 15, 2025 at 7:30 AM EST"

    def test_time_ago_boundaries(self):
        now = current_time()

        def ago(delta: timedelta) -> str:
            return time_ago((now - delta).isoformat())

        assert ago(timedelta(seconds=30)) == "0 minutes ago"
        assert ago(timedelta(minutes=1)) == "1 minute ago"
        assert ago(timedelta(minutes=5)) == "5 minutes ago"
        assert ago(timedelta(hours=1)) == "1 hour ago"
        assert ago(timedelta(hours=2)) == "2 hours ago"
        assert ago(timedelta(days=3)) == "3 days ago"