"""Random Forest detector over the shared signals, including the DBSCAN ones.

The model is trained by `python -m twinwatch.evaluation.train` and saved with
the signals it uses: all of `features.SIGNALS`, or fewer for an ablation.
Loading fails if a saved signal no longer exists. Reasons are the fired
signals the model uses, ordered by the forest's feature importance.
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
    columns: tuple[str, ...]
    importance: dict[str, float]
    info: dict

    @classmethod
    def load(cls, path: Path) -> MLScorer:
        import joblib

        if not path.exists():
            raise ModelError(f"no model at {path}; train one with `python -m twinwatch.evaluation.train`")
        bundle = joblib.load(path)
        columns = tuple(bundle["signals"])
        if not set(columns) <= set(SIGNALS) or getattr(bundle["model"], "n_features_in_", None) != len(columns):
            raise ModelError(f"{path} was trained on other signals; retrain it")
        model = bundle["model"]
        return cls(model, columns, dict(zip(columns, model.feature_importances_)), bundle.get("info", {}))

    def _reasons(self, signals: dict[str, float]) -> tuple[str, ...]:
        return tuple(sorted((n for n in fired(signals) if n in self.importance),
                            key=lambda n: -self.importance[n]))

    def __call__(self, signals: dict[str, float]) -> tuple[float, tuple[str, ...]]:
        return self.score_many([signals])[0]

    def score_many(self, rows: list[dict[str, float]]) -> list[tuple[float, tuple[str, ...]]]:
        """Score many APs in one model call; much faster than one call per AP."""
        if not rows:
            return []
        probs = self.model.predict_proba([[s[c] for c in self.columns] for s in rows])[:, 1]
        return [(float(p), self._reasons(s)) for p, s in zip(probs, rows)]
