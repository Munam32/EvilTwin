"""Random Forest detector over the shared signals, including the DBSCAN ones.

The model is trained by `python -m twinwatch.evaluation.train` and saved with
the signal list it was trained on; loading fails if that list no longer
matches `features.SIGNALS`. Reasons are the fired signals, ordered by the
forest's feature importance.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from twinwatch.features import SIGNALS, fired

DEFAULT_MODEL = Path("models/twinwatch_rf.joblib")


class ModelError(RuntimeError):
    pass


@dataclass
class MLScorer:
    model: object
    importance: dict[str, float]
    info: dict

    @classmethod
    def load(cls, path: Path) -> MLScorer:
        import joblib

        if not path.exists():
            raise ModelError(f"no model at {path}; train one with `python -m twinwatch.evaluation.train`")
        bundle = joblib.load(path)
        if tuple(bundle["signals"]) != SIGNALS:
            raise ModelError(f"{path} was trained on other signals; retrain it")
        model = bundle["model"]
        return cls(model, dict(zip(SIGNALS, model.feature_importances_)), bundle.get("info", {}))

    def __call__(self, signals: dict[str, float]) -> tuple[float, tuple[str, ...]]:
        score = float(self.model.predict_proba([[signals[n] for n in SIGNALS]])[0][1])
        reasons = tuple(sorted(fired(signals), key=lambda n: -self.importance[n]))
        return score, reasons
