"""
HexaSentinel — Synthetic ONNX Model Generator
==============================================

Generates a valid anomaly_classifier.onnx using
synthetic network-traffic data.

Useful for:
- Development
- Demonstrations
- CI/CD
- Testing without downloading CICIDS-2018

For production-quality evaluation, use a classifier
trained on a real network-security dataset.

Usage:

    pip install scikit-learn skl2onnx onnxruntime numpy
    python scripts/generate_synthetic_model.py
"""

import json
import sys
import time
from pathlib import Path


# ---------------------------------------------------------------------------
# Project paths
# ---------------------------------------------------------------------------

ROOT = Path(__file__).resolve().parent.parent

MODEL_DIR = ROOT / "backend" / "models"
MODEL_PATH = MODEL_DIR / "anomaly_classifier.onnx"
REPORT_PATH = MODEL_DIR / "classifier_report.txt"

MODEL_DIR.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():

    print("=" * 60)
    print("  HexaSentinel — Synthetic ONNX Model Generator")
    print("  Synthetic training data | No dataset download required")
    print("=" * 60)
    print()

    # -----------------------------------------------------------------------
    # Dependency check
    # -----------------------------------------------------------------------

    required_packages = {
        "sklearn": "scikit-learn",
        "skl2onnx": "skl2onnx",
        "onnxruntime": "onnxruntime",
        "numpy": "numpy",
    }

    missing = []

    for import_name, package_name in required_packages.items():

        try:
            __import__(import_name)

        except ImportError:
            missing.append(package_name)

    if missing:

        print(
            "Missing dependencies:\n"
            f"  pip install {' '.join(missing)}"
        )

        sys.exit(1)

    # -----------------------------------------------------------------------
    # Imports
    # -----------------------------------------------------------------------

    import numpy as np

    from sklearn.ensemble import GradientBoostingClassifier
    from sklearn.metrics import f1_score
    from sklearn.model_selection import train_test_split
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler

    from skl2onnx import convert_sklearn
    from skl2onnx.common.data_types import FloatTensorType

    import onnxruntime as ort

    # -----------------------------------------------------------------------
    # Configuration
    # -----------------------------------------------------------------------

    N_FEATURES = 80
    N_SAMPLES = 40_000

    RNG = np.random.default_rng(2026)

    # -----------------------------------------------------------------------
    # Generate synthetic network traffic
    # -----------------------------------------------------------------------

    print("[1/4] Generating synthetic network traffic...")

    X = np.zeros(
        (N_SAMPLES, N_FEATURES),
        dtype=np.float32,
    )

    y = np.zeros(
        N_SAMPLES,
        dtype=np.int64,
    )

    # =======================================================================
    # NORMAL TRAFFIC — 60%
    # =======================================================================

    n_normal = int(N_SAMPLES * 0.60)

    X[:n_normal, 0] = RNG.normal(
        15,
        6,
        n_normal,
    ).clip(0.5, 80)

    X[:n_normal, 1] = RNG.normal(
        5000,
        1800,
        n_normal,
    ).clip(100, 25000)

    X[:n_normal, 2] = RNG.normal(
        700,
        200,
        n_normal,
    ).clip(64, 1500)

    # SYN ratio
    X[:n_normal, 22] = RNG.beta(
        1,
        12,
        n_normal,
    )

    # Port entropy
    X[:n_normal, 30] = RNG.uniform(
        0.5,
        2.2,
        n_normal,
    )

    # Unique destinations
    X[:n_normal, 20] = RNG.integers(
        1,
        8,
        n_normal,
    )

    # Zero-payload ratio
    X[:n_normal, 52] = RNG.beta(
        1,
        15,
        n_normal,
    )

    y[:n_normal] = 0

    # =======================================================================
    # SUSPICIOUS TRAFFIC — 25%
    # =======================================================================

    n_suspicious = int(N_SAMPLES * 0.25)

    suspicious_start = n_normal
    suspicious_end = suspicious_start + n_suspicious

    X[suspicious_start:suspicious_end, 0] = RNG.normal(
        55,
        18,
        n_suspicious,
    ).clip(10, 250)

    X[suspicious_start:suspicious_end, 22] = RNG.beta(
        3,
        4,
        n_suspicious,
    )

    X[suspicious_start:suspicious_end, 30] = RNG.uniform(
        3.2,
        5.5,
        n_suspicious,
    )

    X[suspicious_start:suspicious_end, 20] = RNG.integers(
        15,
        80,
        n_suspicious,
    )

    X[suspicious_start:suspicious_end, 21] = RNG.integers(
        80,
        500,
        n_suspicious,
    )

    y[suspicious_start:suspicious_end] = 1

    # =======================================================================
    # THREAT TRAFFIC — 15%
    # =======================================================================

    n_threat = N_SAMPLES - n_normal - n_suspicious

    threat_start = suspicious_end

    # -----------------------------------------------------------------------
    # SYN FLOOD
    # -----------------------------------------------------------------------

    n_syn_flood = n_threat // 2

    X[
        threat_start:threat_start + n_syn_flood,
        0
    ] = RNG.normal(
        900,
        200,
        n_syn_flood,
    ).clip(300, 5000)

    X[
        threat_start:threat_start + n_syn_flood,
        22
    ] = RNG.beta(
        9,
        1,
        n_syn_flood,
    )

    X[
        threat_start:threat_start + n_syn_flood,
        24
    ] = RNG.normal(
        18,
        5,
        n_syn_flood,
    ).clip(5, 60)

    X[
        threat_start:threat_start + n_syn_flood,
        52
    ] = RNG.beta(
        8,
        2,
        n_syn_flood,
    )

    # -----------------------------------------------------------------------
    # C2 BEACONING
    # -----------------------------------------------------------------------

    c2_start = threat_start + n_syn_flood
    c2_count = n_threat - n_syn_flood

    X[c2_start:, 0] = RNG.normal(
        0.5,
        0.1,
        c2_count,
    ).clip(0.1, 2)

    X[c2_start:, 52] = RNG.beta(
        15,
        1,
        c2_count,
    )

    X[c2_start:, 30] = RNG.uniform(
        0.05,
        0.3,
        c2_count,
    )

    X[c2_start:, 20] = 1

    y[threat_start:] = 2

    # -----------------------------------------------------------------------
    # Shuffle
    # -----------------------------------------------------------------------

    indices = RNG.permutation(N_SAMPLES)

    X = X[indices]
    y = y[indices]

    # Binary classifier:
    #
    # 0 = NORMAL
    # 1 = SUSPICIOUS or THREAT
    #
    y_binary = (y >= 1).astype(np.int64)

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y_binary,
        test_size=0.20,
        random_state=42,
        stratify=y_binary,
    )

    print(
        f"    Samples: {N_SAMPLES:,}"
    )

    print(
        f"    Features: {N_FEATURES}"
    )

    print(
        f"    Normal: {(y_binary == 0).sum():,}"
    )

    print(
        f"    Suspicious/Threat: {(y_binary == 1).sum():,}"
    )

    # -----------------------------------------------------------------------
    # Train GBDT
    # -----------------------------------------------------------------------

    print()
    print("[2/4] Training Gradient Boosted Decision Tree...")

    start_time = time.time()

    classifier = Pipeline(
        [
            (
                "scaler",
                StandardScaler(),
            ),
            (
                "gbdt",
                GradientBoostingClassifier(
                    n_estimators=150,
                    max_depth=5,
                    learning_rate=0.12,
                    subsample=0.8,
                    random_state=42,
                ),
            ),
        ]
    )

    classifier.fit(
        X_train,
        y_train,
    )

    training_time = time.time() - start_time

    predictions = classifier.predict(
        X_test
    )

    f1 = f1_score(
        y_test,
        predictions,
        average="binary",
    )

    print(
        f"    Training complete in {training_time:.1f}s"
    )

    print(
        f"    F1 score: {f1:.4f}"
    )

    # -----------------------------------------------------------------------
    # Export to ONNX
    # -----------------------------------------------------------------------

    print()
    print("[3/4] Exporting classifier to ONNX...")

    onnx_model = convert_sklearn(
        classifier,
        name="HexaSentinelGBDTClassifier",
        initial_types=[
            (
                "features",
                FloatTensorType(
                    [None, N_FEATURES]
                ),
            )
        ],
        options={
            "zipmap": False
        },
        target_opset=17,
    )

    MODEL_PATH.write_bytes(
        onnx_model.SerializeToString()
    )

    model_size_kb = (
        MODEL_PATH.stat().st_size / 1024
    )

    print(
        f"    Saved: {MODEL_PATH}"
    )

    print(
        f"    Size: {model_size_kb:.1f} KB"
    )

    # -----------------------------------------------------------------------
    # Verify ONNX model
    # -----------------------------------------------------------------------

    print()
    print("[4/4] Verifying ONNX model...")

    session = ort.InferenceSession(
        str(MODEL_PATH),
        providers=[
            "CPUExecutionProvider"
        ],
    )

    dummy_input = np.zeros(
        (1, N_FEATURES),
        dtype=np.float32,
    )

    input_name = session.get_inputs()[0].name

    outputs = session.run(
        None,
        {
            input_name: dummy_input
        },
    )

    print(
        f"    ONNX inputs: {len(outputs)} outputs returned"
    )

    # -----------------------------------------------------------------------
    # Write classifier report
    # -----------------------------------------------------------------------

    report = {
        "project": "HexaSentinel",
        "model": "GBDT (synthetic)",
        "samples": N_SAMPLES,
        "features": N_FEATURES,
        "f1": round(float(f1), 4),
        "onnx_kb": round(float(model_size_kb), 1),
        "classes": {
            "0": "NORMAL",
            "1": "SUSPICIOUS_OR_THREAT",
        },
        "runtime": {
            "format": "ONNX",
            "preferred": "Qualcomm QNN / Hexagon NPU",
            "fallback": "CPUExecutionProvider",
        },
    }

    REPORT_PATH.write_text(
        json.dumps(
            report,
            indent=2,
        ),
        encoding="utf-8",
    )

    # -----------------------------------------------------------------------
    # Done
    # -----------------------------------------------------------------------

    print()
    print("=" * 60)
    print(
        f"  Model ready — F1={f1:.4f}"
    )
    print(
        f"  ONNX: {MODEL_PATH}"
    )
    print(
        f"  Report: {REPORT_PATH}"
    )
    print(
        "  HexaSentinel can now load the classifier."
    )
    print("=" * 60)


if __name__ == "__main__":
    main()
