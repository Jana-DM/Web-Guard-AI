from datetime import datetime, timezone
from typing import Optional


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_iso_datetime(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    normalized = value.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(normalized)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None
