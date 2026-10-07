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
    name: str
    model: Any
    scaler: Any
    label_encoder: Any


class Predictor:

    def __init__(self) -> None:
        self._bundles: list[_Bundle] = []
        self._load_all()

    # ── Loading ──────────────────────────────────────────────────────────────

    def _load_all(self) -> None:
        """
        Load all models defined in MODEL_PATHS.

        A model that fails to load is skipped so that one broken model
        does not prevent the other models from being used.
        """
        for name, paths in MODEL_PATHS.items():
            try:
                bundle = self._load_bundle(name, paths)
                self._bundles.append(bundle)

                log.info("Loaded model '%s'", name)

            except Exception:
                log.exception(
                    "Failed to load model '%s' — it will be skipped",
                    name,
                )

        if not self._bundles:
            raise RuntimeError(
                "No models could be loaded. "
                "Check MODEL_PATHS in config/paths.py."
            )

    @staticmethod
    def _load_bundle(
        name: str,
        paths: dict[str, Path],
    ) -> _Bundle:
        """
        Load model, scaler and label encoder from disk.
        """

        return _Bundle(
            name=name,
            model=joblib.load(paths["model"]),
            scaler=joblib.load(paths["scaler"]),
            label_encoder=joblib.load(paths["label_encoder"]),
        )

    # ── Inference ────────────────────────────────────────────────────────────

    def predict(self, df: pd.DataFrame) -> dict[str, str]:
        """
        Run inference using all loaded models.

        Returns:
            {
                "RF": "Benign",
                "CNN": "DDoS",
                "DT": "Benign",
                ...
            }
        """

        results: dict[str, str] = {}

        for bundle in self._bundles:
            try:
                label = self._predict_one(bundle, df)
                results[bundle.name] = label

            except Exception:
                log.exception(
                    "Prediction failed for model '%s'",
                    bundle.name,
                )

                results[bundle.name] = "ERROR"

        log.debug("Predictions: %s", results)

        return results

    # ── Single-model prediction ──────────────────────────────────────────────

    @staticmethod
    def _predict_one(
        bundle: _Bundle,
        df: pd.DataFrame,
    ) -> str:
        """
        Preprocess the input and perform prediction for one model.

        This supports:
        - Random Forest
        - Decision Tree
        - Logistic Regression
        - Naive Bayes
        - CNN implemented with a scikit-learn-compatible .predict()
          interface and saved using joblib.
        """

        # ---------------------------------------------------------------------
        # 1. Check feature names
        # ---------------------------------------------------------------------

        if hasattr(bundle.scaler, "feature_names_in_"):

            expected_features = list(
                bundle.scaler.feature_names_in_
            )

            missing = [
                feature
                for feature in expected_features
                if feature not in df.columns
            ]

            extra = [
                feature
                for feature in df.columns
                if feature not in expected_features
            ]

            if missing:
                raise ValueError(
                    f"Missing features for model "
                    f"'{bundle.name}': {missing}"
                )

            if extra:
                log.warning(
                    "Model '%s' ignoring extra features: %s",
                    bundle.name,
                    extra,
                )

            # Keep exactly the same feature order used during training.
            df = df[expected_features]

        # ---------------------------------------------------------------------
        # 2. Scale input
        # ---------------------------------------------------------------------

        scaled = bundle.scaler.transform(df)

        # ---------------------------------------------------------------------
        # 3. Model prediction
        # ---------------------------------------------------------------------

        raw = bundle.model.predict(scaled)

        # ---------------------------------------------------------------------
        # 4. Handle CNN / probability-style output
        # ---------------------------------------------------------------------
        #
        # Your original CNN code does:
        #
        # prediction_cnn = model_cnn.predict(df_scaled_cnn)
        #
        # if prediction_cnn.shape[1] != 1:
        #     prediction_cnn = prediction_cnn.argmax(axis=-1)
        #
        # Therefore, if CNN returns something like:
        #
        # [[0.01, 0.92, 0.07]]
        #
        # we convert it to:
        #
        # [1]
        #
        # which can then be passed to LabelEncoder.
        # ---------------------------------------------------------------------

        raw = np.asarray(raw)

        if raw.ndim == 2:

            if raw.shape[1] > 1:
                raw = raw.argmax(axis=1)

            elif raw.shape[1] == 1:
                raw = raw.ravel()

        # ---------------------------------------------------------------------
        # 5. Make sure the prediction is one-dimensional
        # ---------------------------------------------------------------------

        raw = np.asarray(raw).reshape(-1)

        if len(raw) == 0:
            raise ValueError(
                f"Model '{bundle.name}' returned an empty prediction."
            )

        # ---------------------------------------------------------------------
        # 6. Convert numerical class to original label
        # ---------------------------------------------------------------------

        label = bundle.label_encoder.inverse_transform(raw)[0]

        return str(label)