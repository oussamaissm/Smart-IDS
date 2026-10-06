"""
Runtime settings — tune these without touching core logic.
"""

import os

# ── Stats window ─────────────────────────────────────────────────────────────
# Suricata emits a 'stats' event on this interval (seconds).
STATS_INTERVAL_SECONDS: int = int(os.getenv("STATS_INTERVAL", "8"))

# ── Logging ──────────────────────────────────────────────────────────────────
LOG_LEVEL: str = os.getenv("IDS_LOG_LEVEL", "INFO").upper()
LOG_FORMAT: str = "%(asctime)s  %(levelname)-8s  %(name)s — %(message)s"
LOG_DATE_FORMAT: str = "%Y-%m-%dT%H:%M:%S"

# ── Prediction ───────────────────────────────────────────────────────────────
# Label that models return for benign traffic.
BENIGN_LABEL: str = os.getenv("BENIGN_LABEL", "Benign")

# ── Suricata ─────────────────────────────────────────────────────────────────
# How long (seconds) tail -f should wait between reads.
TAIL_SLEEP_SECONDS: float = 0.05
