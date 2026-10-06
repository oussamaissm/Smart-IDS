import os
from pathlib import Path

# ── Project root ────────────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parent.parent

# ── Suricata live log ────────────────────────────────────────────────────────
SURICATA_LOG = Path(os.getenv("SURICATA_LOG", "/var/log/suricata/eve.json"))

# ── Model base directory ─────────────────────────────────────────────────────
MODEL_BASE = Path(os.getenv("IDS_MODEL_PATH", ROOT / "models"))

MODEL_PATHS = {
    "RF": {
        "model": "models/rff/model_rf.sav",
        "scaler": "models/rff/scaler_rf.bin",
        "label_encoder": "models/rff/label_encoder_rf.joblib",
    },
    "CNN": {
        "model": "models/CNN/model_cnn.sav",
        "scaler": "models/CNN/scaler_cnn.bin",
        "label_encoder": "models/CNN/label_encoder_cnn.joblib",
    },
    "DT": {
        "model": "models/DT/model_dt.sav",
        "scaler": "models/DT/scaler_dt.bin",
        "label_encoder": "models/DT/label_encoder_dt.joblib",
    },
    "LR": {
        "model": "models/LR/model_lr.sav",
        "scaler": "models/LR/scaler_lr.bin",
        "label_encoder": "models/LR/label_encoder_lr.joblib",
    },
    "NB": {
        "model": "models/NB/model_nb.sav",
        "scaler": "models/NB/scaler_nb.bin",
        "label_encoder": "models/NB/label_encoder_nb.joblib",
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
