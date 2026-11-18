"""Native playback DST metadata from the same IANA data used by the hub clock."""
from pathlib import Path
import re
from zoneinfo import TZPATH, ZoneInfo


def offset_seconds(value):
    sign = -1 if value.startswith("-") else 1
    parts = [int(part) for part in value.lstrip("+-").split(":")]
    return sign * sum(part * unit for part, unit in zip(parts, (3600, 60, 1)))


def clock_offset(seconds):
    sign = "-" if seconds < 0 else ""
    hours, remainder = divmod(abs(seconds), 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{sign}{hours:02}:{minutes:02}:{seconds:02}"


def dst_status(zone_id):
    ZoneInfo(zone_id)  # Validate before using the key as a filesystem path.
    for directory in TZPATH:
        path = Path(directory) / zone_id
        if path.is_file():
            footer = path.read_bytes().split(b"\n")[-2].decode("ascii")
            break
    else:
        raise ValueError("Timezone data unavailable")
    name = r"(?:[A-Za-z]{3,}|<[^>]+>)"
    offset = r"[+-]?\d{1,3}(?::\d{2}){0,2}"
    match = re.fullmatch(rf"{name}({offset})(?:{name}({offset})?,([^,]+),([^,]+))?", footer)
    if not match:
        raise ValueError("Unsupported timezone rule")
    standard, daylight, start, end = match.groups()
    result = {"enabled": "1", "synced": "1", "has_rule": "1" if start else "0"}
    if start:
        # Native rules express the daylight offset relative to standard time.
        delta = offset_seconds(daylight) - offset_seconds(standard) if daylight else -3600
        def transition(value):
            rule, _, hour = value.partition("/")
            return rule + "/" + clock_offset(offset_seconds(hour or "2"))
        relative_offset = ("-" if delta < 0 else "") + clock_offset(abs(delta))[:5]
        result["dst_rule"] = f"DST{relative_offset},{transition(start)},{transition(end)}"
    return result
