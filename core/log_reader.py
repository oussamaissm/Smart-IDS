"""
Async log follower.

Reads Suricata's eve.json line by line and, on every 'stats' event,
hands the accumulated FlowState to the feature extractor and predictor.
"""

import asyncio
import json
import logging
from pathlib import Path

import pandas as pd

from config.paths    import RESULTS_FILE, ALERTS_FILE
from config.settings import BENIGN_LABEL
from core.feature_extractor import extract_features
from core.predictor          import Predictor
from core.state              import FlowState
from core.utils              import get_host_ip, append_jsonl

log = logging.getLogger(__name__)


class LogReader:
    """
    Parameters
    ----------
    log_file  : path to eve.json (or a local copy for testing)
    predictor : a fully-loaded Predictor instance
    """

    def __init__(self, log_file: Path, predictor: Predictor) -> None:
        self._log_file  = log_file
        self._predictor = predictor
        self._host_ip   = get_host_ip()          # resolved once at startup
        log.info("Host IP detected as '%s'", self._host_ip)

    # ── Public entry point ────────────────────────────────────────────────────

    async def run(self) -> None:
        log.info("Tailing '%s' …", self._log_file)
        proc = await asyncio.create_subprocess_exec(
            "tail", "-f", str(self._log_file),
            stdout=asyncio.subprocess.PIPE,
        )
        assert proc.stdout is not None

        state = FlowState()

        while True:
            raw = await proc.stdout.readline()
            line = raw.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            self._handle_line(line, state)

    # ── Line dispatcher ───────────────────────────────────────────────────────

    def _handle_line(self, line: str, state: FlowState) -> None:
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            log.warning("Skipping non-JSON line: %.120s", line)
            return

        event = entry.get("event_type")

        try:
            if event == "alert":
                self._on_alert(entry, state)
            elif event == "flow":
                self._on_flow(entry, state)
            elif event == "stats":
                self._on_stats(entry, state)
        except KeyError as exc:
            log.warning("Missing key %s in entry: %.200s", exc, line)
        except Exception:
            log.exception("Unexpected error handling event_type='%s'", event)

    # ── Event handlers ────────────────────────────────────────────────────────

    def _on_alert(self, entry: dict, state: FlowState) -> None:
        log.warning(
            "Suricata alert: %s",
            entry.get("alert", {}).get("signature", "(no signature)"),
        )
        # Mark window as tainted; skip the next stats event.
        state.alert_flag = True

    def _on_flow(self, entry: dict, state: FlowState) -> None:
        if state.alert_flag:
            return
        state.record_flow(
            src_ip   = entry.get("src_ip", ""),
            host_ip  = self._host_ip,
            log      = entry,
        )
        state.total_count += 1

    def _on_stats(self, entry: dict, state: FlowState) -> None:
        # ── Skip tainted windows ─────────────────────────────────────────────
        if state.alert_flag:
            log.info("Skipping stats window — alert was raised.")
            state.reset()
            return

        # ── Deduplicate repeated stats events ────────────────────────────────
        ts = entry.get("timestamp", "")
        if ts == state.last_stats_timestamp:
            return
        state.last_stats_timestamp = ts

        # ── Feature extraction ────────────────────────────────────────────────
        features = extract_features(entry, state)
        df       = pd.DataFrame([features])

        # ── Persist raw features ──────────────────────────────────────────────
        import json as _json
        append_jsonl(RESULTS_FILE, _json.dumps(features))

        # ── Predict ───────────────────────────────────────────────────────────
        predictions = self._predictor.predict(df)
        record = {"timestamp": ts, "features": features, "predictions": predictions}
        append_jsonl(RESULTS_FILE, _json.dumps(record))

        # ── Alert if any model flags malicious traffic ────────────────────────
        malicious = {
            model: label
            for model, label in predictions.items()
            if label != BENIGN_LABEL and label != "ERROR"
        }
        if malicious:
            log.warning("⚠  MALICIOUS TRAFFIC DETECTED: %s", malicious)
            append_jsonl(ALERTS_FILE, _json.dumps({"timestamp": ts, "detections": malicious}))
        else:
            log.info("Window %s — all models: Benign", ts)

        # ── Reset for next window ─────────────────────────────────────────────
        state.reset()
