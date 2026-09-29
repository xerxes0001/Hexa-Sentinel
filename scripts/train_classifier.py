"""
SnapShield — ONNX Anomaly Classifier Training

Trains a 3-class network anomaly classifier:

    0 = NORMAL
    1 = SUSPICIOUS
    2 = THREAT

The resulting ONNX model accepts:

    float32 [N, 80]

and produces:

    labels      [N]
    probabilities [N, 3]

The model is intended for consumption by the SnapShield Python
backend and eventual Qualcomm QNN / Hexagon NPU deployment.

Usage
-----

    pip install -r scripts/train_requirements.txt

    # Real CICIDS data
    python scripts/train_classifier.py

    # Offline / CI
    python scripts/train_classifier.py --synthetic

    # Force sklearn instead of XGBoost
    python scripts/train_classifier.py --no-xgb

    # Limit real dataset rows
    python scripts/train_classifier.py --rows 200000
"""

from __future__ import annotations

import argparse
import json
import time
import urllib.request
from pathlib import Path

import numpy as np


# ============================================================================
# PATHS
# ============================================================================

ROOT = Path(__file__).resolve().parent.parent

MODEL_DIR = ROOT / "backend" / "models"
MODEL_PATH = MODEL_DIR / "anomaly_classifier.onnx"
REPORT_PATH = MODEL_DIR / "classifier_report.txt"

RAW_DIR = ROOT / "scripts" / ".cicids_cache"

MODEL_DIR.mkdir(parents=True, exist_ok=True)
RAW_DIR.mkdir(parents=True, exist_ok=True)


# ============================================================================
# DATASET
# ============================================================================

# Thursday-15-02-2018 CICIDS-2018 flow data.
CICIDS_URL = (
    "https://iscxdownloads.cs.unb.ca/iscxdownloads/"
    "CIC-IDS-2018/"
    "Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv"
)

CICIDS_LOCAL = RAW_DIR / "cicids2018_thursday.csv"


# ============================================================================
# MODEL CONTRACT
# ============================================================================

FEATURE_COUNT = 80

CLASS_NAMES = [
    "NORMAL",
    "SUSPICIOUS",
    "THREAT",
]

CLASS_IDS = {
    "NORMAL": 0,
    "SUSPICIOUS": 1,
    "THREAT": 2,
}


# ============================================================================
# CICIDS -> SNAPSHIELD FEATURE MAP
# ============================================================================
#
# IMPORTANT:
#
# These indexes MUST remain synchronized with the 80-feature vector used by
# the runtime feature extractor in the SnapShield backend.
#
# Do not casually change these indexes without changing the runtime extractor.
#
# ============================================================================

FEATURE_MAP = {
    "Total Fwd Packets": 0,
    "Total Backward Packets": 1,
    "Total Length of Fwd Packets": 2,
    "Flow Bytes/s": 3,
    "Flow Packets/s": 4,

    "Protocol": 10,

    "Destination Port": 21,

    "SYN Flag Count": 22,
    "ACK Flag Count": 23,
    "RST Flag Count": 25,
    "FIN Flag Count": 26,

    "Flow IAT Mean": 40,
    "Flow IAT Std": 41,
    "Flow IAT Min": 42,
    "Flow IAT Max": 43,

    "Average Packet Size": 45,
    "Avg Fwd Segment Size": 50,
}


# ============================================================================
# LABEL MAP
# ============================================================================

LABEL_MAP = {
    "BENIGN": 0,

    "PortScan": 1,

    "FTP-Patator": 1,
    "SSH-Patator": 1,

    "Web Attack": 1,
    "Web Attack - Brute Force": 1,
    "Web Attack - XSS": 1,
    "Web Attack - Sql Injection": 1,

    "DoS Hulk": 2,
    "DDoS": 2,
    "Bot": 2,
    "DoS GoldenEye": 2,
    "DoS slowloris": 2,
    "DoS Slowhttptest": 2,
    "Heartbleed": 2,
    "Infiltration": 2,
}


# ============================================================================
# DOWNLOAD
# ============================================================================

def download_cicids() -> bool:
    if CICIDS_LOCAL.exists():
        print(f"[Data] Using cached CICIDS-2018:")
        print(f"       {CICIDS_LOCAL}")
        return True

    print("[Data] CICIDS-2018 dataset not found locally.")
    print("[Data] Downloading Thursday split...")
    print(f"[Data] URL: {CICIDS_URL}")

    try:
        def progress(block_count, block_size, total_size):
            if total_size <= 0:
                return

            downloaded = block_count * block_size
            percent = min(downloaded / total_size * 100.0, 100.0)

            print(
                f"\r       {percent:6.2f}%",
                end="",
                flush=True,
            )

        urllib.request.urlretrieve(
            CICIDS_URL,
            CICIDS_LOCAL,
            reporthook=progress,
        )

        print()
        print(f"[Data] Saved to {CICIDS_LOCAL}")

        return True

    except Exception as exc:
        print()
        print(f"[Data] Download failed: {exc}")

        if CICIDS_LOCAL.exists():
            CICIDS_LOCAL.unlink(missing_ok=True)

        return False


# ============================================================================
# DATA LOADING
# ============================================================================

def load_cicids(max_rows: int = 200_000):
    import pandas as pd

    print()
    print(f"[Data] Loading up to {max_rows:,} rows...")

    df = pd.read_csv(
        CICIDS_LOCAL,
        nrows=max_rows,
        low_memory=False,
        on_bad_lines="skip",
    )

    # Normalize column names once.
    df.columns = [str(c).strip() for c in df.columns]

    print(
        f"[Data] Loaded {len(df):,} rows "
        f"and {len(df.columns):,} columns"
    )

    # ------------------------------------------------------------------------
    # Feature matrix
    # ------------------------------------------------------------------------

    X = np.zeros(
        (len(df), FEATURE_COUNT),
        dtype=np.float32,
    )

    available = {
        str(column).strip(): column
        for column in df.columns
    }

    for source_name, feature_index in FEATURE_MAP.items():

        source_column = available.get(source_name.strip())

        if source_column is None:
            print(
                f"[Data] Warning: CICIDS column missing: "
                f"{source_name}"
            )
            continue

        values = pd.to_numeric(
            df[source_column],
            errors="coerce",
        ).fillna(0.0)

        X[:, feature_index] = values.to_numpy(
            dtype=np.float32,
        )

    # ------------------------------------------------------------------------
    # Destination-port derived feature
    # ------------------------------------------------------------------------

    destination_port_column = available.get("Destination Port")

    if destination_port_column is not None:
        ports = (
            pd.to_numeric(
                df[destination_port_column],
                errors="coerce",
            )
            .fillna(0)
            .astype(np.int64)
        )

        # Runtime-compatible bounded representation.
        X[:, 30] = (
            (ports % 1024).astype(np.float32) / 1024.0
        )

    # ------------------------------------------------------------------------
    # Labels
    # ------------------------------------------------------------------------

    label_column = available.get("Label")

    if label_column is None:
        raise RuntimeError(
            "CICIDS CSV does not contain a Label column."
        )

    raw_labels = (
        df[label_column]
        .astype(str)
        .str.strip()
    )

    y = np.array(
        [
            LABEL_MAP.get(label, 0)
            for label in raw_labels
        ],
        dtype=np.int64,
    )

    # ------------------------------------------------------------------------
    # Clean numerical values
    # ------------------------------------------------------------------------

    X = np.nan_to_num(
        X,
        nan=0.0,
        posinf=0.0,
        neginf=0.0,
    )

    X = np.clip(
        X,
        -1e6,
        1e6,
    )

    # ------------------------------------------------------------------------
    # Dataset statistics
    # ------------------------------------------------------------------------

    print()
    print("[Data] Class distribution:")

    for class_id, class_name in enumerate(CLASS_NAMES):
        count = int(np.sum(y == class_id))
        percent = (
            count / len(y) * 100
            if len(y)
            else 0
        )

        print(
            f"       {class_name:<12} "
            f"{count:>8,} "
            f"({percent:5.2f}%)"
        )

    return X, y


# ============================================================================
# SYNTHETIC DATA
# ============================================================================

def make_synthetic(
    n: int = 60_000,
    seed: int = 42,
):
    """
    Creates deterministic synthetic data for CI/offline development.

    The generated feature distribution intentionally mirrors the signals
    consumed by the SnapShield runtime:

        packet rate
        byte rate
        packet size
        SYN activity
        port entropy
        destination diversity
        destination port activity
    """

    rng = np.random.default_rng(seed)

    X = np.zeros(
        (n, FEATURE_COUNT),
        dtype=np.float32,
    )

    y = np.zeros(
        n,
        dtype=np.int64,
    )

    # ========================================================================
    # NORMAL
    # ========================================================================

    n_normal = int(n * 0.60)

    X[:n_normal, 0] = (
        rng.normal(15, 5, n_normal)
        .clip(1, 100)
    )

    X[:n_normal, 1] = (
        rng.normal(5000, 1500, n_normal)
        .clip(100, 30000)
    )

    X[:n_normal, 2] = (
        rng.normal(800, 200, n_normal)
        .clip(64, 1500)
    )

    X[:n_normal, 22] = rng.beta(
        1,
        10,
        n_normal,
    )

    X[:n_normal, 30] = rng.uniform(
        0.5,
        2.5,
        n_normal,
    )

    X[:n_normal, 20] = rng.integers(
        1,
        8,
        n_normal,
    ).astype(np.float32)

    y[:n_normal] = 0

    # ========================================================================
    # SUSPICIOUS
    # ========================================================================

    n_suspicious = int(n * 0.25)

    start = n_normal
    end = start + n_suspicious

    X[start:end, 0] = (
        rng.normal(60, 20, n_suspicious)
        .clip(10, 300)
    )

    X[start:end, 22] = rng.beta(
        4,
        4,
        n_suspicious,
    )

    X[start:end, 30] = rng.uniform(
        3.0,
        5.0,
        n_suspicious,
    )

    X[start:end, 20] = rng.integers(
        10,
        80,
        n_suspicious,
    ).astype(np.float32)

    X[start:end, 21] = rng.integers(
        50,
        400,
        n_suspicious,
    ).astype(np.float32)

    y[start:end] = 1

    # ========================================================================
    # THREAT
    # ========================================================================

    start = end
    n_threat = n - start

    X[start:, 0] = (
        rng.normal(900, 200, n_threat)
        .clip(200, 5000)
    )

    X[start:, 22] = rng.beta(
        9,
        1,
        n_threat,
    )

    X[start:, 24] = (
        rng.normal(15, 4, n_threat)
        .clip(5, 50)
    )

    X[start:, 30] = rng.uniform(
        0.1,
        1.5,
        n_threat,
    )

    X[start:, 20] = rng.integers(
        1,
        5,
        n_threat,
    ).astype(np.float32)

    y[start:] = 2

    # Shuffle dataset.
    indices = rng.permutation(n)

    return X[indices], y[indices]


# ============================================================================
# MODEL CREATION
# ============================================================================

def build_model(use_xgb: bool):
    """
    Creates the classifier.

    Both model types are genuinely 3-class classifiers.
    """

    if use_xgb:

        try:
            from xgboost import XGBClassifier

            model = XGBClassifier(
                objective="multi:softprob",
                num_class=3,

                n_estimators=250,
                max_depth=6,
                learning_rate=0.08,

                subsample=0.85,
                colsample_bytree=0.85,

                min_child_weight=2,
                reg_lambda=1.0,

                eval_metric="mlogloss",

                random_state=42,
                n_jobs=-1,

                tree_method="hist",
            )

            print("[Train] Using XGBoost 3-class classifier")

            return model, "XGBoost"

        except ImportError:
            print(
                "[Train] XGBoost unavailable."
            )
            print(
                "[Train] Falling back to sklearn GradientBoostingClassifier."
            )

    from sklearn.ensemble import GradientBoostingClassifier

    model = GradientBoostingClassifier(
        n_estimators=200,
        max_depth=5,
        learning_rate=0.08,
        subsample=0.85,
        random_state=42,
    )

    print(
        "[Train] Using sklearn "
        "GradientBoostingClassifier"
    )

    return model, "GradientBoostingClassifier"


# ============================================================================
# ONNX EXPORT
# ============================================================================

def export_onnx(pipe, model_name: str):
    """
    Converts the complete preprocessing + classifier pipeline to ONNX.

    Input:
        features: float32 [None, 80]

    Outputs:
        output_label
        output_probability
    """

    from skl2onnx import convert_sklearn
    from skl2onnx.common.data_types import FloatTensorType

    # XGBoost requires converter registration in some skl2onnx versions.
    if model_name == "XGBoost":

        try:
            from xgboost import XGBClassifier

            from onnxmltools.convert.xgboost.operator_converters.XGBoost import (
                convert_xgboost,
            )

            from skl2onnx.common.shape_calculator import (
                calculate_linear_classifier_output_shapes,
            )

            from skl2onnx import update_registered_converter

            update_registered_converter(
                XGBClassifier,
                "XGBoostXGBClassifier",
                calculate_linear_classifier_output_shapes,
                convert_xgboost,
                options={
                    "nocl": [True, False],
                    "zipmap": [True, False],
                },
            )

        except Exception as exc:
            print(
                "[ONNX] XGBoost converter registration warning:"
            )
            print(
                f"       {exc}"
            )

    initial_type = [
        (
            "features",
            FloatTensorType(
                [None, FEATURE_COUNT]
            ),
        )
    ]

    print(
        "[ONNX] Converting pipeline..."
    )

    onnx_model = convert_sklearn(
        pipe,
        initial_types=initial_type,
        name="SnapShieldAnomalyClassifier",

        options={
            id(pipe.named_steps["clf"]): {
                "zipmap": False,
                "nocl": True,
            }
        },

        target_opset=17,
    )

    with MODEL_PATH.open("wb") as output:
        output.write(
            onnx_model.SerializeToString()
        )

    size_kb = (
        MODEL_PATH.stat().st_size / 1024
    )

    print(
        f"[ONNX] Saved: {MODEL_PATH}"
    )

    print(
        f"[ONNX] Size: {size_kb:.1f} KB"
    )

    return size_kb


# ============================================================================
# TRAIN
# ============================================================================

def train_and_export(
    X,
    y,
    use_xgb=True,
    dataset_name="Unknown",
):
    from sklearn.metrics import (
        accuracy_score,
        classification_report,
        confusion_matrix,
        f1_score,
    )

    from sklearn.model_selection import train_test_split
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler

    # ------------------------------------------------------------------------
    # Validate labels
    # ------------------------------------------------------------------------

    unique_labels = sorted(
        np.unique(y).tolist()
    )

    if unique_labels != [0, 1, 2]:
        raise RuntimeError(
            "Training data must contain all three classes "
            f"[0, 1, 2], got {unique_labels}"
        )

    # ------------------------------------------------------------------------
    # Train/test split
    # ------------------------------------------------------------------------

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y,
    )

    print()
    print(
        f"[Train] Training rows: {len(X_train):,}"
    )

    print(
        f"[Train] Test rows:     {len(X_test):,}"
    )

    # ------------------------------------------------------------------------
    # Build pipeline
    # ------------------------------------------------------------------------

    classifier, model_name = build_model(
        use_xgb
    )

    pipe = Pipeline(
        [
            (
                "scaler",
                StandardScaler(),
            ),
            (
                "clf",
                classifier,
            ),
        ]
    )

    # ------------------------------------------------------------------------
    # Train
    # ------------------------------------------------------------------------

    print()
    print("[Train] Fitting model...")

    started = time.time()

    pipe.fit(
        X_train,
        y_train,
    )

    elapsed = time.time() - started

    print(
        f"[Train] Completed in {elapsed:.1f}s"
    )

    # ------------------------------------------------------------------------
    # Evaluate
    # ------------------------------------------------------------------------

    y_pred = pipe.predict(
        X_test
    )

    accuracy = accuracy_score(
        y_test,
        y_pred,
    )

    weighted_f1 = f1_score(
        y_test,
        y_pred,
        average="weighted",
    )

    macro_f1 = f1_score(
        y_test,
        y_pred,
        average="macro",
    )

    report = classification_report(
        y_test,
        y_pred,
        labels=[0, 1, 2],
        target_names=CLASS_NAMES,
        digits=4,
        zero_division=0,
    )

    matrix = confusion_matrix(
        y_test,
        y_pred,
        labels=[0, 1, 2],
    )

    print()
    print("[Eval]")
    print(
        f"       Accuracy   = {accuracy:.4f}"
    )
    print(
        f"       Weighted F1 = {weighted_f1:.4f}"
    )
    print(
        f"       Macro F1    = {macro_f1:.4f}"
    )

    print()
    print(report)

    print(
        "[Eval] Confusion matrix:"
    )

    print(matrix)

    # ------------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------------

    size_kb = export_onnx(
        pipe,
        model_name,
    )

    # ------------------------------------------------------------------------
    # Report
    # ------------------------------------------------------------------------

    metadata = {
        "project": "SnapShield",
        "model": model_name,

        "features": FEATURE_COUNT,

        "classes": CLASS_NAMES,

        "class_ids": CLASS_IDS,

        "dataset": dataset_name,

        "train_rows": int(len(X_train)),
        "test_rows": int(len(X_test)),

        "accuracy": round(
            float(accuracy),
            4,
        ),

        "weighted_f1": round(
            float(weighted_f1),
            4,
        ),

        "macro_f1": round(
            float(macro_f1),
            4,
        ),

        "onnx_opset": 17,

        "onnx_size_kb": round(
            float(size_kb),
            1,
        ),

        "input": {
            "name": "features",
            "dtype": "float32",
            "shape": [None, FEATURE_COUNT],
        },

        "outputs": {
            "label": "int64",
            "probabilities": "float32",
            "class_order": CLASS_NAMES,
        },
    }

    REPORT_PATH.write_text(
        json.dumps(
            metadata,
            indent=2,
        )
        + "\n\n"
        + report
    )

    print(
        f"[Report] Saved: {REPORT_PATH}"
    )

    return {
        "accuracy": accuracy,
        "weighted_f1": weighted_f1,
        "macro_f1": macro_f1,
        "model": model_name,
    }


# ============================================================================
# ONNX VERIFICATION
# ============================================================================

def verify_onnx():
    """
    Runs the exported ONNX model with ONNX Runtime.

    This verifies:

    1. The file is valid.
    2. Input name is correct.
    3. Input shape is correct.
    4. Output label exists.
    5. Probability vector contains 3 classes.
    """

    import onnxruntime as ort

    print()
    print(
        "[Verify] Loading ONNX model..."
    )

    session = ort.InferenceSession(
        str(MODEL_PATH),
        providers=[
            "CPUExecutionProvider"
        ],
    )

    inputs = session.get_inputs()
    outputs = session.get_outputs()

    print(
        f"[Verify] Inputs: "
        f"{[x.name for x in inputs]}"
    )

    print(
        f"[Verify] Outputs: "
        f"{[x.name for x in outputs]}"
    )

    if not inputs:
        raise RuntimeError(
            "ONNX model has no inputs."
        )

    input_name = inputs[0].name

    dummy = np.zeros(
        (1, FEATURE_COUNT),
        dtype=np.float32,
    )

    result = session.run(
        None,
        {
            input_name: dummy
        },
    )

    if len(result) < 2:
        raise RuntimeError(
            "Expected ONNX model to return "
            "label + probability outputs."
        )

    labels = np.asarray(
        result[0]
    )

    probabilities = np.asarray(
        result[1]
    )

    print(
        f"[Verify] Label shape: "
        f"{labels.shape}"
    )

    print(
        f"[Verify] Probability shape: "
        f"{probabilities.shape}"
    )

    print(
        f"[Verify] Label: "
        f"{labels[0]}"
    )

    print(
        "[Verify] Probabilities:",
        np.round(
            probabilities[0],
            4,
        ),
    )

    # Some converters return [N, 3].
    # Others may return [3] for one sample.
    probs = probabilities.reshape(-1)

    if len(probs) != 3:
        raise RuntimeError(
            "Expected 3-class probability output, "
            f"got {len(probs)} values."
        )

    if not np.isfinite(probs).all():
        raise RuntimeError(
            "ONNX model returned non-finite probabilities."
        )

    # Softmax-like probability sanity check.
    probability_sum = float(
        probs.sum()
    )

    if not np.isclose(
        probability_sum,
        1.0,
        atol=0.05,
    ):
        raise RuntimeError(
            "Probability output does not sum "
            f"approximately to 1.0: {probability_sum}"
        )

    predicted_class = int(
        np.argmax(probs)
    )

    print(
        f"[Verify] Prediction: "
        f"{CLASS_NAMES[predicted_class]}"
    )

    print(
        "[Verify] ONNX model is valid."
    )

    return True


# ============================================================================
# CLI
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description=(
            "Train SnapShield 3-class ONNX "
            "anomaly classifier."
        )
    )

    parser.add_argument(
        "--synthetic",
        action="store_true",
        help=(
            "Use synthetic data. "
            "No network download."
        ),
    )

    parser.add_argument(
        "--rows",
        type=int,
        default=200_000,
        help=(
            "Maximum CICIDS rows to load."
        ),
    )

    parser.add_argument(
        "--no-xgb",
        action="store_true",
        help=(
            "Use sklearn GradientBoosting "
            "instead of XGBoost."
        ),
    )

    args = parser.parse_args()

    print("=" * 70)
    print(
        "  SnapShield — ONNX Anomaly Classifier"
    )
    print(
        "  NORMAL / SUSPICIOUS / THREAT"
    )
    print("=" * 70)

    # ------------------------------------------------------------------------
    # Data
    # ------------------------------------------------------------------------

    if args.synthetic:

        print()
        print(
            "[Data] Synthetic mode enabled."
        )

        X, y = make_synthetic()

        dataset_name = (
            "Synthetic SnapShield dataset"
        )

    else:

        if download_cicids():

            try:
                X, y = load_cicids(
                    max_rows=args.rows
                )

                dataset_name = (
                    "CICIDS-2018 "
                    "Thursday split"
                )

            except Exception as exc:

                print()
                print(
                    "[Data] CICIDS loading failed:"
                )
                print(
                    f"       {exc}"
                )

                print(
                    "[Data] Falling back "
                    "to synthetic data."
                )

                X, y = make_synthetic()

                dataset_name = (
                    "Synthetic fallback"
                )

        else:

            print(
                "[Data] Using synthetic fallback."
            )

            X, y = make_synthetic()

            dataset_name = (
                "Synthetic fallback"
            )

    # ------------------------------------------------------------------------
    # Train
    # ------------------------------------------------------------------------

    result = train_and_export(
        X,
        y,
        use_xgb=not args.no_xgb,
        dataset_name=dataset_name,
    )

    # ------------------------------------------------------------------------
    # Verify
    # ------------------------------------------------------------------------

    verify_onnx()

    # ------------------------------------------------------------------------
    # Final status
    # ------------------------------------------------------------------------

    print()
    print("=" * 70)

    print(
        f"  Model: {result['model']}"
    )

    print(
        f"  Accuracy: {result['accuracy']:.4f}"
    )

    print(
        f"  Weighted F1: "
        f"{result['weighted_f1']:.4f}"
    )

    print(
        f"  Macro F1: "
        f"{result['macro_f1']:.4f}"
    )

    print()
    print(
        f"  ONNX: {MODEL_PATH}"
    )

    print(
        f"  Report: {REPORT_PATH}"
    )

    if result["weighted_f1"] >= 0.90:
        print()
        print(
            "  ✓ Training completed successfully."
        )
    else:
        print()
        print(
            "  ⚠ Weighted F1 is below 0.90."
        )
        print(
            "    Review the dataset/feature mapping "
            "before claiming production accuracy."
        )

    print("=" * 70)


if __name__ == "__main__":
    main()
