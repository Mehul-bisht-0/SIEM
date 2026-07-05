from __future__ import annotations

import os
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder


FEATURE_COLUMNS = [
    "event_weight",
    "severity_weight",
    "hour",
    "source_private",
    "destination_private",
    "source_octet_sum",
    "destination_octet_sum",
    "risk_product",
]


def _synthetic_training_frame(rows: int = 800) -> pd.DataFrame:
    rng = np.random.default_rng(42)
    normal = pd.DataFrame(
        {
            "event_weight": rng.choice([0, 1, 2], rows, p=[0.55, 0.3, 0.15]),
            "severity_weight": rng.choice([1, 3], rows, p=[0.75, 0.25]),
            "hour": rng.integers(6, 22, rows),
            "source_private": rng.choice([0, 1], rows, p=[0.35, 0.65]),
            "destination_private": rng.choice([0, 1], rows, p=[0.25, 0.75]),
            "source_octet_sum": rng.normal(430, 80, rows).clip(15, 850),
            "destination_octet_sum": rng.normal(480, 90, rows).clip(15, 850),
        }
    )
    normal["risk_product"] = normal["event_weight"] * normal["severity_weight"]

    attack = pd.DataFrame(
        {
            "event_weight": rng.choice([5, 7, 9, 10], rows // 8),
            "severity_weight": rng.choice([6, 9], rows // 8),
            "hour": rng.integers(0, 24, rows // 8),
            "source_private": rng.choice([0, 1], rows // 8, p=[0.75, 0.25]),
            "destination_private": rng.choice([0, 1], rows // 8, p=[0.2, 0.8]),
            "source_octet_sum": rng.normal(520, 150, rows // 8).clip(15, 900),
            "destination_octet_sum": rng.normal(490, 120, rows // 8).clip(15, 900),
        }
    )
    attack["risk_product"] = attack["event_weight"] * attack["severity_weight"]
    return pd.concat([normal, attack], ignore_index=True)


def _frame_from_nsl_kdd(csv_path: Path) -> pd.DataFrame:
    raw = pd.read_csv(csv_path)
    frame = pd.DataFrame()

    service_col = "service" if "service" in raw.columns else raw.columns[min(2, len(raw.columns) - 1)]
    flag_col = "flag" if "flag" in raw.columns else raw.columns[min(3, len(raw.columns) - 1)]
    src_col = "src_bytes" if "src_bytes" in raw.columns else raw.select_dtypes(include="number").columns[0]
    dst_col = "dst_bytes" if "dst_bytes" in raw.columns else raw.select_dtypes(include="number").columns[1]
    failed_col = "num_failed_logins" if "num_failed_logins" in raw.columns else None
    root_col = "num_root" if "num_root" in raw.columns else None

    service_encoder = LabelEncoder()
    flag_encoder = LabelEncoder()
    frame["event_weight"] = service_encoder.fit_transform(raw[service_col].astype(str)) % 11
    frame["severity_weight"] = flag_encoder.fit_transform(raw[flag_col].astype(str)) % 10
    frame["hour"] = np.arange(len(raw)) % 24
    frame["source_private"] = 0
    frame["destination_private"] = 1
    frame["source_octet_sum"] = np.log1p(pd.to_numeric(raw[src_col], errors="coerce").fillna(0))
    frame["destination_octet_sum"] = np.log1p(pd.to_numeric(raw[dst_col], errors="coerce").fillna(0))
    frame["risk_product"] = frame["event_weight"] * frame["severity_weight"]

    if failed_col:
        frame["event_weight"] = frame["event_weight"] + pd.to_numeric(raw[failed_col], errors="coerce").fillna(0).clip(0, 5)
    if root_col:
        frame["severity_weight"] = frame["severity_weight"] + pd.to_numeric(raw[root_col], errors="coerce").fillna(0).clip(0, 5)

    return frame[FEATURE_COLUMNS]


def train_and_save(model_path: str | Path, csv_path: str | Path | None = None) -> Path:
    destination = Path(model_path)
    destination.parent.mkdir(parents=True, exist_ok=True)

    nsl_source = csv_path or os.getenv("NSL_KDD_CSV")
    nsl_path = Path(nsl_source) if nsl_source else None
    if nsl_path and nsl_path.exists():
        training = _frame_from_nsl_kdd(nsl_path)
    else:
        training = _synthetic_training_frame()

    model = IsolationForest(
        n_estimators=150,
        contamination=0.12,
        random_state=42,
    )
    model.fit(training[FEATURE_COLUMNS])
    joblib.dump(model, destination)
    return destination


if __name__ == "__main__":
    output = os.getenv("MODEL_PATH", "models/isolation_forest.pkl")
    source = os.getenv("NSL_KDD_CSV")
    saved_to = train_and_save(output, source)
    print(f"Saved Isolation Forest model to {saved_to}")
