"""
Hexa Sentinel — ONNX Anomaly Classifier Training
=================================================
Trains a network anomaly classifier using CICIDS-2018 data
or synthetic data and exports the trained model to ONNX.

Output:
    backend/models/anomaly_classifier.onnx
    backend/models/classifier_report.txt

Usage:
    python scripts/train_classifier.py
    python scripts/train_classifier.py --synthetic
    python scripts/train_classifier.py --rows 200000
    python scripts/train_classifier.py --synthetic --no-xgb

The exported ONNX model expects an input tensor named:
    features

Shape:
    [batch_size, 80]

Classification:
    0 = NORMAL
    1 = ANOMALOUS

The Hexa Sentinel backend uses this model for the first-stage
network anomaly screening pipeline.
"""

import argparse
import json
import sys
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

CICIDS_URL = (
    "https://iscxdownloads.cs.unb.ca/iscxdownloads/CIC-IDS-2018/"
    "Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv"
)

CICIDS_LOCAL = RAW_DIR / "cicids2018_thursday.csv"


# ============================================================================
# FEATURE CONFIGURATION
# ============================================================================

N_FEATURES = 80


FEATURE_MAP = {
    # Flow statistics
    "Total Fwd Packets": 0,
    "Total Backward Packets": 1,
    "Total Length of Fwd Packets": 2,
    "Flow Bytes/s": 1,
    "Flow Packets/s": 0,

    # Protocol
    "Protocol": 10,

    # TCP flags
    "SYN Flag Count": 22,
    "ACK Flag Count": 23,
    "RST Flag Count": 25,
    "FIN Flag Count": 26,

    # Inter-arrival time
    "Flow IAT Mean": 40,
    "Flow IAT Std": 41,
    "Flow IAT Min": 42,
    "Flow IAT Max": 43,

    # Payload
    "Average Packet Size": 2,
    "Avg Fwd Segment Size": 50,

    # Destination port
    "Destination Port": 21,
}


# CICIDS labels are converted into a binary classification:
#
# 0 = NORMAL
# 1 = ANOMALOUS
#
# Suspicious and malicious traffic are therefore grouped together.
LABEL_MAP = {
    "BENIGN": 0,

    "DoS Hulk": 1,
    "DDoS": 1,
    "PortScan": 1,
    "Bot": 1,
    "DoS GoldenEye": 1,
    "FTP-Patator": 1,
    "SSH-Patator": 1,
    "DoS slowloris": 1,
    "DoS Slowhttptest": 1,
    "Heartbleed": 1,
    "Web Attack": 1,
    "Infiltration": 1,
}


# ============================================================================
# DOWNLOAD DATASET
# ============================================================================

def download_cicids() -> bool:
    """
    Download the CICIDS-2018 CSV if it does not already exist.
    """

    if CICIDS_LOCAL.exists():
        print(f"[Data] Using cached dataset:")
        print(f"       {CICIDS_LOCAL}")
        return True

    print("[Data] CICIDS-2018 dataset not found.")
    print("[Data] Downloading dataset...")
    print(f"[Data] Source: {CICIDS_URL}")

    try:

        def progress(block_count, block_size, total_size):
            if total_size <= 0:
                return

            downloaded = block_count * block_size
            percent = min(downloaded / total_size * 100, 100)

            print(
                f"\r       Download progress: {percent:5.1f}%",
                end="",
                flush=True,
            )

        urllib.request.urlretrieve(
            CICIDS_URL,
            CICIDS_LOCAL,
            reporthook=progress,
        )

        print()
        print("[Data] Dataset downloaded successfully.")

        return True

    except Exception as exc:

        print()
        print(f"[Data] Dataset download failed: {exc}")

        return False


# ============================================================================
# LOAD CICIDS DATA
# ============================================================================

def load_cicids(max_rows: int = 200_000):
    """
    Load CICIDS CSV and convert it into the Hexa Sentinel
    80-feature representation.
    """

    import pandas as pd

    print()
    print(f"[Data] Loading CICIDS-2018...")
    print(f"[Data] Maximum rows: {max_rows:,}")

    df = pd.read_csv(
        CICIDS_LOCAL,
        nrows=max_rows,
        low_memory=False,
        on_bad_lines="skip",
    )

    df.columns = df.columns.str.strip()

    print(
        f"[Data] Loaded {len(df):,} rows "
        f"and {len(df.columns):,} columns"
    )

    # ------------------------------------------------------------------------
    # Create feature matrix
    # ------------------------------------------------------------------------

    X = np.zeros(
        (len(df), N_FEATURES),
        dtype=np.float32,
    )

    # Map stripped column names to actual dataframe columns.
    column_lookup = {
        column.strip(): column
        for column in df.columns
    }

    def get_column(name):
        return column_lookup.get(name.strip())

    # ------------------------------------------------------------------------
    # Populate mapped features
    # ------------------------------------------------------------------------

    for column_name, feature_index in FEATURE_MAP.items():

        column = get_column(column_name)

        if column is None:
            continue

        values = (
            pd.to_numeric(
                df[column],
                errors="coerce",
            )
            .fillna(0)
            .to_numpy()
        )

        X[:, feature_index] = values.astype(
            np.float32,
            copy=False,
        )

    # ------------------------------------------------------------------------
    # Destination-port entropy approximation
    # ------------------------------------------------------------------------

    port_column = get_column("Destination Port")

    if port_column is not None:

        ports = (
            pd.to_numeric(
                df[port_column],
                errors="coerce",
            )
            .fillna(0)
            .astype(np.int32)
        )

        # This is only an approximation for training.
        X[:, 30] = (
            ports.to_numpy() % 1024
        ).astype(np.float32) / 1024.0

    # ------------------------------------------------------------------------
    # Labels
    # ------------------------------------------------------------------------

    label_column = get_column("Label")

    if label_column is not None:

        raw_labels = (
            df[label_column]
            .astype(str)
            .str.strip()
            .to_numpy()
        )

        y = np.array(
            [
                LABEL_MAP.get(label, 0)
                for label in raw_labels
            ],
            dtype=np.int64,
        )

    else:

        print(
            "[Data] WARNING: Label column not found. "
            "Treating all rows as NORMAL."
        )

        y = np.zeros(
            len(df),
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

    print()
    print("[Data] Class distribution:")
    print(
        f"       NORMAL    : {np.sum(y == 0):,}"
    )
    print(
        f"       ANOMALOUS : {np.sum(y == 1):,}"
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
    Generate synthetic network traffic for offline development,
    demonstrations and CI environments.

    The synthetic dataset contains:
        - Normal traffic
        - Port scanning
        - Elevated SYN traffic
        - SYN flood
        - C2-style low-volume beaconing
    """

    rng = np.random.default_rng(seed)

    X = np.zeros(
        (n, N_FEATURES),
        dtype=np.float32,
    )

    y = np.zeros(
        n,
        dtype=np.int64,
    )

    # =========================================================================
    # NORMAL TRAFFIC — 60%
    # =========================================================================

    n_normal = int(n * 0.60)

    X[:n_normal, 0] = rng.normal(
        15,
        5,
        n_normal,
    ).clip(1, 100)

    X[:n_normal, 1] = rng.normal(
        5000,
        1500,
        n_normal,
    ).clip(100, 30_000)

    X[:n_normal, 2] = rng.normal(
        800,
        200,
        n_normal,
    ).clip(64, 1500)

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
    )

    X[:n_normal, 21] = rng.integers(
        1,
        20,
        n_normal,
    )

    X[:n_normal, 52] = rng.beta(
        1,
        15,
        n_normal,
    )

    y[:n_normal] = 0

    # =========================================================================
    # PORT SCAN / SUSPICIOUS TRAFFIC — 20%
    # =========================================================================

    n_scan = int(n * 0.20)

    start = n_normal
    end = start + n_scan

    X[start:end, 0] = rng.normal(
        60,
        20,
        n_scan,
    ).clip(10, 300)

    X[start:end, 22] = rng.beta(
        4,
        4,
        n_scan,
    )

    X[start:end, 30] = rng.uniform(
        3.0,
        5.0,
        n_scan,
    )

    X[start:end, 20] = rng.integers(
        10,
        80,
        n_scan,
    )

    X[start:end, 21] = rng.integers(
        50,
        400,
        n_scan,
    )

    X[start:end, 52] = rng.beta(
        2,
        8,
        n_scan,
    )

    y[start:end] = 1

    # =========================================================================
    # SYN FLOOD — 10%
    # =========================================================================

    n_syn = int(n * 0.10)

    start = end
    end = start + n_syn

    X[start:end, 0] = rng.normal(
        900,
        200,
        n_syn,
    ).clip(200, 5000)

    X[start:end, 22] = rng.beta(
        9,
        1,
        n_syn,
    )

    X[start:end, 24] = rng.normal(
        15,
        4,
        n_syn,
    ).clip(5, 50)

    X[start:end, 30] = rng.uniform(
        0.1,
        1.5,
        n_syn,
    )

    X[start:end, 20] = rng.integers(
        1,
        5,
        n_syn,
    )

    X[start:end, 52] = rng.beta(
        8,
        2,
        n_syn,
    )

    y[start:end] = 1

    # =========================================================================
    # C2 BEACONING — 10%
    # =========================================================================

    n_c2 = n - end

    start = end

    X[start:, 0] = rng.normal(
        0.5,
        0.1,
        n_c2,
    ).clip(0.1, 2)

    X[start:, 1] = rng.normal(
        60,
        15,
        n_c2,
    ).clip(10, 200)

    X[start:, 20] = 1

    X[start:, 21] = 1

    X[start:, 30] = rng.uniform(
        0.05,
        0.3,
        n_c2,
    )

    X[start:, 52] = rng.beta(
        15,
        1,
        n_c2,
    )

    y[start:] = 1

    # =========================================================================
    # SHUFFLE
    # =========================================================================

    indices = rng.permutation(n)

    X = X[indices]
    y = y[indices]

    print()
    print("[Synthetic] Generated dataset:")
    print(f"             Samples   : {n:,}")
    print(f"             Features  : {N_FEATURES}")
    print(
        f"             Normal    : {np.sum(y == 0):,}"
    )
    print(
        f"             Anomalous : {np.sum(y == 1):,}"
    )

    return X, y


# ============================================================================
# TRAIN CLASSIFIER
# ============================================================================

def train_and_export(
    X,
    y,
    use_xgb: bool = True,
):
    """
    Train the classifier and export it to ONNX.
    """

    from sklearn.metrics import (
        classification_report,
        f1_score,
    )

    from sklearn.model_selection import (
        train_test_split,
    )

    from sklearn.pipeline import Pipeline

    from sklearn.preprocessing import StandardScaler

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
    print("[Train] Dataset split:")
    print(f"        Train: {len(X_train):,}")
    print(f"        Test : {len(X_test):,}")

    # ------------------------------------------------------------------------
    # Select classifier
    # ------------------------------------------------------------------------

    classifier_name = ""

    if use_xgb:

        try:

            from xgboost import XGBClassifier

            clf = XGBClassifier(
                n_estimators=300,
                max_depth=6,
                learning_rate=0.1,
                subsample=0.8,
                colsample_bytree=0.8,
                eval_metric="logloss",
                random_state=42,
                n_jobs=-1,
            )

            classifier_name = "XGBoost"

            print("[Train] Using XGBoost")

        except ImportError:

            print(
                "[Train] XGBoost not installed."
            )

            print(
                "[Train] Falling back to "
                "sklearn GradientBoostingClassifier."
            )

            use_xgb = False

    if not use_xgb:

        from sklearn.ensemble import (
            GradientBoostingClassifier,
        )

        clf = GradientBoostingClassifier(
            n_estimators=200,
            max_depth=5,
            learning_rate=0.1,
            subsample=0.8,
            random_state=42,
        )

        classifier_name = "GradientBoostingClassifier"

        print(
            "[Train] Using sklearn "
            "GradientBoostingClassifier"
        )

    # ------------------------------------------------------------------------
    # Pipeline
    # ------------------------------------------------------------------------

    pipeline = Pipeline(
        [
            (
                "scaler",
                StandardScaler(),
            ),
            (
                "classifier",
                clf,
            ),
        ]
    )

    # ------------------------------------------------------------------------
    # Train
    # ------------------------------------------------------------------------

    print()
    print("[Train] Training classifier...")

    start_time = time.perf_counter()

    pipeline.fit(
        X_train,
        y_train,
    )

    training_time = (
        time.perf_counter()
        - start_time
    )

    print(
        f"[Train] Training completed in "
        f"{training_time:.2f} seconds"
    )

    # ------------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------------

    y_pred = pipeline.predict(
        X_test
    )

    f1 = f1_score(
        y_test,
        y_pred,
        average="binary",
    )

    report = classification_report(
        y_test,
        y_pred,
        target_names=[
            "NORMAL",
            "ANOMALOUS",
        ],
        digits=4,
    )

    print()
    print("=" * 60)
    print("MODEL EVALUATION")
    print("=" * 60)
    print(
        f"Binary F1 Score: {f1:.4f}"
    )
    print()
    print(report)

    # ------------------------------------------------------------------------
    # Export to ONNX
    # ------------------------------------------------------------------------

    print(
        "[ONNX] Exporting trained model..."
    )

    from skl2onnx import convert_sklearn

    from skl2onnx.common.data_types import (
        FloatTensorType,
    )

    initial_type = [
        (
            "features",
            FloatTensorType(
                [None, N_FEATURES]
            ),
        )
    ]

    onnx_model = convert_sklearn(
        pipeline,
        name="HexaSentinelAnomalyClassifier",
        initial_types=initial_type,
        target_opset=17,
        options={
            "zipmap": False,
        },
    )

    MODEL_PATH.write_bytes(
        onnx_model.SerializeToString()
    )

    model_size_kb = (
        MODEL_PATH.stat().st_size
        / 1024
    )

    print(
        f"[ONNX] Model saved:"
    )

    print(
        f"       {MODEL_PATH}"
    )

    print(
        f"[ONNX] Size: "
        f"{model_size_kb:.1f} KB"
    )

    # ------------------------------------------------------------------------
    # Report
    # ------------------------------------------------------------------------

    metadata = {
        "project": "Hexa Sentinel",
        "model": classifier_name,
        "features": N_FEATURES,
        "classes": [
            "NORMAL",
            "ANOMALOUS",
        ],
        "binary_classification": True,
        "f1": round(float(f1), 4),
        "training_seconds": round(
            training_time,
            2,
        ),
        "dataset": (
            "CICIDS-2018"
            if CICIDS_LOCAL.exists()
            else "Synthetic"
        ),
        "onnx_opset": 17,
        "onnx_size_kb": round(
            model_size_kb,
            1,
        ),
    }

    REPORT_PATH.write_text(
        json.dumps(
            metadata,
            indent=2,
        )
        + "\n\n"
        + report,
        encoding="utf-8",
    )

    print(
        f"[ONNX] Report saved:"
    )

    print(
        f"       {REPORT_PATH}"
    )

    return f1


# ============================================================================
# VERIFY ONNX MODEL
# ============================================================================

def verify_onnx():
    """
    Verify that the exported ONNX model can be loaded and executed.
    """

    import onnxruntime as ort

    print()
    print("[Verify] Loading ONNX model...")

    session = ort.InferenceSession(
        str(MODEL_PATH),
        providers=[
            "CPUExecutionProvider"
        ],
    )

    # Check input
    input_name = (
        session
        .get_inputs()[0]
        .name
    )

    print(
        f"[Verify] Input name: {input_name}"
    )

    # Dummy inference
    dummy = np.zeros(
        (1, N_FEATURES),
        dtype=np.float32,
    )

    outputs = session.run(
        None,
        {
            input_name: dummy
        },
    )

    predicted_class = int(
        outputs[0][0]
    )

    probabilities = (
        np.asarray(outputs[1][0])
        if len(outputs) > 1
        else None
    )

    print(
        f"[Verify] Predicted class: "
        f"{predicted_class}"
    )

    if probabilities is not None:
        print(
            "[Verify] Probabilities: "
            f"{np.round(probabilities, 4)}"
        )

    print(
        "[Verify] ONNX model is valid."
    )


# ============================================================================
# COMMAND LINE
# ============================================================================

def main():

    parser = argparse.ArgumentParser(
        description=(
            "Train the Hexa Sentinel "
            "ONNX anomaly classifier."
        )
    )

    parser.add_argument(
        "--synthetic",
        action="store_true",
        help=(
            "Use synthetic data instead "
            "of downloading CICIDS-2018."
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

    # ------------------------------------------------------------------------
    # Header
    # ------------------------------------------------------------------------

    print()
    print("=" * 64)
    print(
        "  HEXA SENTINEL"
    )
    print(
        "  ONNX Anomaly Classifier Training"
    )
    print(
        "  Qualcomm Snapdragon / Hexagon Pipeline"
    )
    print("=" * 64)

    # ------------------------------------------------------------------------
    # Load data
    # ------------------------------------------------------------------------

    if args.synthetic:

        print()
        print(
            "[Data] Synthetic mode enabled."
        )

        X, y = make_synthetic()

    else:

        dataset_available = (
            download_cicids()
        )

        if dataset_available:

            try:

                X, y = load_cicids(
                    max_rows=args.rows
                )

            except Exception as exc:

                print()
                print(
                    "[Data] Error loading "
                    f"CICIDS dataset: {exc}"
                )

                print(
                    "[Data] Falling back "
                    "to synthetic data."
                )

                X, y = make_synthetic()

        else:

            print()
            print(
                "[Data] Falling back "
                "to synthetic data."
            )

            X, y = make_synthetic()

    # ------------------------------------------------------------------------
    # Train
    # ------------------------------------------------------------------------

    f1 = train_and_export(
        X,
        y,
        use_xgb=not args.no_xgb,
    )

    # ------------------------------------------------------------------------
    # Verify
    # ------------------------------------------------------------------------

    verify_onnx()

    # ------------------------------------------------------------------------
    # Final output
    # ------------------------------------------------------------------------

    print()
    print("=" * 64)

    print(
        f"  Hexa Sentinel training complete."
    )

    print(
        f"  F1 Score: {f1:.4f}"
    )

    print()
    print(
        "  Model:"
    )

    print(
        f"  {MODEL_PATH}"
    )

    print()
    print(
        "  Report:"
    )

    print(
        f"  {REPORT_PATH}"
    )

    print("=" * 64)
    print()


if __name__ == "__main__":
    main()
