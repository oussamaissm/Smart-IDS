# IDS — Network Intrusion Detection System

Real-time ML-based IDS built on top of Suricata's `eve.json` log stream.

## How it works

```
eve.json  →  LogReader  →  FeatureExtractor  →  Predictor (RF, CNN, DT, LR, NB)
                                                      ↓
                                               data/results.jsonl
                                               alerts/alerts.jsonl
```

Each Suricata **stats** event (default: every 10 s) triggers one prediction window.

## Quick start

```bash
pip install -r requirements.txt

# Optional overrides (defaults shown)
export SURICATA_LOG=/var/log/suricata/eve.json
export IDS_MODEL_PATH=./models
export IDS_LOG_LEVEL=INFO
export BENIGN_LABEL=Benign

python main.py
```

## Project structure

```
ids-project/
├── main.py                  # entry point
├── config/
│   ├── paths.py             # all file paths, overrideable via env vars
│   └── settings.py          # runtime tunables
├── core/
│   ├── state.py             # FlowState dataclass
│   ├── feature_extractor.py # stats log → feature dict
│   ├── predictor.py         # loads models once, exposes predict()
│   ├── log_reader.py        # async tail -f loop
│   └── utils.py             # logging, IP detection, timestamp math
├── models/                  # RF/, CNN/, DT/, LR/, NB/ — not in git
├── data/results.jsonl       # one JSON record per stats window
├── alerts/alerts.jsonl      # only written when traffic is flagged
└── tests/
    └── test_features.py
```

## Running tests

```bash
python -m pytest tests/ -v
```

## Adding a new model

1. Drop the three artefacts (`model.sav`, `scaler.bin`, `label_encoder.joblib`) into `models/<NAME>/`.
2. Add one entry to `MODEL_PATHS` in `config/paths.py`.
3. Done — no other file changes required.
