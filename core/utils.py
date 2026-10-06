import datetime
import logging
import subprocess
from pathlib import Path

from config.paths    import APP_LOG, ALERTS_FILE, RESULTS_FILE
from config.settings import LOG_FORMAT, LOG_DATE_FORMAT, LOG_LEVEL


# ── Logging ──────────────────────────────────────────────────────────────────

def setup_logging() -> None:
    APP_LOG.parent.mkdir(parents=True, exist_ok=True)

    logging.basicConfig(
        level       = getattr(logging, LOG_LEVEL, logging.INFO),
        format      = LOG_FORMAT,
        datefmt     = LOG_DATE_FORMAT,
        handlers    = [
            logging.StreamHandler(),
            logging.FileHandler(APP_LOG, encoding="utf-8"),
        ],
    )


# ── Output writers ────────────────────────────────────────────────────────────

def ensure_output_dirs() -> None:
    for p in (RESULTS_FILE, ALERTS_FILE):
        p.parent.mkdir(parents=True, exist_ok=True)


def append_jsonl(path: Path, data: str) -> None:
    with path.open("a", encoding="utf-8") as fh:
        fh.write(data + "\n")


# ── Network ───────────────────────────────────────────────────────────────────

def get_host_ip() -> str:
    try:
        result = subprocess.run(
            ["ip", "route"],
            capture_output=True,
            text=True,
            timeout=3,
        )
        for line in result.stdout.splitlines():
            if "default via" in line:
                parts = line.split()
                if "src" in parts:
                    return parts[parts.index("src") + 1]
                if len(parts) > 8:
                    return parts[8]
    except Exception:
        logging.getLogger(__name__).exception("Could not determine host IP")
    return ""


# ── Time ─────────────────────────────────────────────────────────────────────

_TS_FORMAT = "%Y-%m-%dT%H:%M:%S.%f%z"


def timestamp_diff(ts1: str, ts2: str) -> float:
    try:
        dt1 = datetime.datetime.strptime(ts1, _TS_FORMAT)
        dt2 = datetime.datetime.strptime(ts2, _TS_FORMAT)
        return (dt1 - dt2).total_seconds()
    except (ValueError, TypeError):
        return 0.0
