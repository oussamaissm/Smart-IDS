"""
Centralized path configuration.
Override any path via environment variables.
"""

import os
from pathlib import Path

# ── Project root ────────────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parent.parent

# ── Suricata live log ────────────────────────────────────────────────────────
SURICATA_LOG = Path(os.getenv("SURICATA_LOG", "/var/log/suricata/eve.json"))

# ── Model base directory ─────────────────────────────────────────────────────
MODEL_BASE = Path(os.getenv("IDS_MODEL_PATH", ROOT / "models"))

MODEL_PATHS: dict[str, dict[str, Path]] = {
    "RF": {
        "model":         MODEL_BASE / "rff"  / "model_rf.sav",
        "scaler":        MODEL_BASE / "rff"  / "scaler_rf.bin",
        "label_encoder": MODEL_BASE / "rff"  / "label_encoder_rf.joblib",
    },
    "CNN": {
        "model":         MODEL_BASE / "CNN"  / "model_CNN.sav",
        "scaler":        MODEL_BASE / "CNN"  / "scaler_CNN.bin",
        "label_encoder": MODEL_BASE / "CNN"  / "label_encoder_CNN.joblib",
    },
    "DT": {
        "model":         MODEL_BASE / "DT"   / "model_dt.sav",
        "scaler":        MODEL_BASE / "DT"   / "scaler_dt.bin",
        "label_encoder": MODEL_BASE / "DT"   / "label_encoder_dt.joblib",
    },
    "LR": {
        "model":         MODEL_BASE / "LR"   / "model_lr.sav",
        "scaler":        MODEL_BASE / "LR"   / "scaler_lr.bin",
        "label_encoder": MODEL_BASE / "LR"   / "label_encoder_lr.joblib",
    },
    "NB": {
        "model":         MODEL_BASE / "NB"   / "model_nb.sav",
        "scaler":        MODEL_BASE / "NB"   / "scaler_nb.bin",
        "label_encoder": MODEL_BASE / "NB"   / "label_encoder_nb.joblib",
    },
}

# ── Output files ─────────────────────────────────────────────────────────────
DATA_DIR   = ROOT / "data"
ALERTS_DIR = ROOT / "alerts"

RESULTS_FILE = DATA_DIR   / "results.jsonl"   # one JSON object per line
ALERTS_FILE  = ALERTS_DIR / "alerts.jsonl"

# ── Logging ──────────────────────────────────────────────────────────────────
LOG_DIR  = ROOT / "logs"
APP_LOG  = LOG_DIR / "ids.log"
