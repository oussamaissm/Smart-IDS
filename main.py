"""
Entry point.

    python main.py

Environment variables (all optional):
    SURICATA_LOG    path to eve.json          (default /var/log/suricata/eve.json)
    IDS_MODEL_PATH  directory containing RF/, CNN/ … sub-dirs
    IDS_LOG_LEVEL   DEBUG | INFO | WARNING     (default INFO)
    BENIGN_LABEL    label string for normal traffic (default "Benign")
"""

import asyncio
import logging
import sys

from config.paths    import SURICATA_LOG
from config.settings import LOG_LEVEL
from core.predictor  import Predictor
from core.log_reader import LogReader
from core.utils      import setup_logging, ensure_output_dirs


def main() -> None:
    setup_logging()
    ensure_output_dirs()

    log = logging.getLogger(__name__)
    log.info("Starting IDS  (log_level=%s)", LOG_LEVEL)

    # ── Validate log file ─────────────────────────────────────────────────────
    if not SURICATA_LOG.exists():
        log.error("Suricata log not found: %s", SURICATA_LOG)
        sys.exit(1)

    # ── Load all models once ──────────────────────────────────────────────────
    try:
        predictor = Predictor()
    except RuntimeError:
        log.exception("Could not initialise Predictor — aborting.")
        sys.exit(1)

    # ── Start async reader ────────────────────────────────────────────────────
    reader = LogReader(SURICATA_LOG, predictor)

    try:
        asyncio.run(reader.run())
    except KeyboardInterrupt:
        log.info("Stopped by user.")


if __name__ == "__main__":
    main()
