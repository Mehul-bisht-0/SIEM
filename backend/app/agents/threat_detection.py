from pathlib import Path

import joblib
import numpy as np

from app.ml.features import vectorize_log
from app.ml.train_model import train_and_save
from app.schemas import LogEntry, ThreatResult


class ThreatDetectionAgent:
    """Runs an Isolation Forest model on each incoming log."""

    def __init__(self, model_path: str):
        self.model_path = Path(model_path)
        if not self.model_path.exists():
            train_and_save(self.model_path)
        self.model = joblib.load(self.model_path)

    def analyze(self, log: LogEntry) -> ThreatResult:
        vector = np.array([vectorize_log(log)])
        prediction = int(self.model.predict(vector)[0])
        model_score = float(self.model.decision_function(vector)[0])
        model_anomaly = prediction == -1

        heuristic_score = self._heuristic_score(log)
        model_confidence = self._confidence_from_score(model_score)
        confidence = max(model_confidence, heuristic_score)
        is_anomaly = model_anomaly or heuristic_score >= 0.74

        reason = "isolation_forest"
        if heuristic_score >= model_confidence:
            reason = "high_risk_event_pattern"

        return ThreatResult(
            is_anomaly=is_anomaly,
            confidence_score=round(float(confidence), 3),
            model_score=round(model_score, 5),
            reason=reason,
        )

    @staticmethod
    def _confidence_from_score(score: float) -> float:
        # Isolation Forest scores trend lower for outliers; sigmoid keeps output demo-friendly.
        return float(1 / (1 + np.exp(12 * score)))

    @staticmethod
    def _heuristic_score(log: LogEntry) -> float:
        if log.event_type.value in {"malware", "data_exfiltration"}:
            return 0.95
        if log.event_type.value == "privilege_escalation":
            return 0.9
        if log.event_type.value == "port_scan" and log.severity.value in {"high", "critical"}:
            return 0.82
        if log.event_type.value == "failed_login" and log.severity.value in {"high", "critical"}:
            return 0.76
        return 0.0
