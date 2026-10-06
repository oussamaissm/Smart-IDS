"""
Loads all five models exactly once at startup and exposes a single
predict(df) → dict[str, str] interface.

Adding a new model = add one entry to MODEL_PATHS in config/paths.py.
No other file needs to change.
"""

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd

from config.paths import MODEL_PATHS

log = logging.getLogger(__name__)


@dataclass
class _Bundle:
    """One model + its scaler + its label encoder."""
    name:          str
    model:         Any
    scaler:        Any
    label_encoder: Any


class Predictor:
    """
    Usage
    -----
    predictor = Predictor()                 # loads all models once
    results   = predictor.predict(df_row)   # fast from here on
    """

    def __init__(self) -> None:
        self._bundles: list[_Bundle] = []
        self._load_all()

    # ── Loading ───────────────────────────────────────────────────────────────

    def _load_all(self) -> None:
        for name, paths in MODEL_PATHS.items():
            try:
                bundle = self._load_bundle(name, paths)
                self._bundles.append(bundle)
                log.info("Loaded model '%s'", name)
            except Exception:
                log.exception("Failed to load model '%s' — it will be skipped", name)

        if not self._bundles:
            raise RuntimeError(
                "No models could be loaded. Check MODEL_PATHS in config/paths.py."
            )

    @staticmethod
    def _load_bundle(name: str, paths: dict[str, Path]) -> _Bundle:
        return _Bundle(
            name          = name,
            model         = joblib.load(paths["model"]),
            scaler        = joblib.load(paths["scaler"]),
            label_encoder = joblib.load(paths["label_encoder"]),
        )

    # ── Inference ─────────────────────────────────────────────────────────────

    def predict(self, df: pd.DataFrame) -> dict[str, str]:
        """
        Parameters
        ----------
        df : single-row DataFrame with extracted features

        Returns
        -------
        {"RF": "Benign", "CNN": "DDoS", ...}
        """
        results: dict[str, str] = {}

        for bundle in self._bundles:
            try:
                label = self._predict_one(bundle, df)
                results[bundle.name] = label
            except Exception:
                log.exception("Prediction failed for model '%s'", bundle.name)
                results[bundle.name] = "ERROR"

        log.debug("Predictions: %s", results)
        return results

    @staticmethod
    def _predict_one(bundle: _Bundle, df: pd.DataFrame) -> str:
    # Ensure features have exactly the same names and order
        # used when the scaler was fitted.
        if hasattr(bundle.scaler, "feature_names_in_"):
            expected_features = list(bundle.scaler.feature_names_in_)

            missing = [f for f in expected_features if f not in df.columns]
            extra = [f for f in df.columns if f not in expected_features]

            if missing:
                raise ValueError(f"Missing features: {missing}")

            if extra:
                log.warning("Ignoring extra features: %s", extra)

            df = df[expected_features]

        scaled = bundle.scaler.transform(df)
        raw = bundle.model.predict(scaled)

        # CNN may return softmax probabilities (2-D array)
        if isinstance(raw, np.ndarray) and raw.ndim == 2 and raw.shape[1] > 1:
            raw = raw.argmax(axis=-1)

        label: str = bundle.label_encoder.inverse_transform(raw)[0]
        return label
