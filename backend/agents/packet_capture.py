"""
HexaSentinel — Packet Capture Agent
====================================

Implements the five-stage HexaSentinel security pipeline:

    Stage 1 — Passive Ingestion
        Scapy / Npcap packet capture
        Rolling 30-second in-memory window

    Stage 2 — Feature Extraction
        Converts traffic into an 80-feature vector

    Stage 3 — NPU Screening
        ONNX anomaly classifier
        Qualcomm QNN / Hexagon NPU when available
        CPU fallback when NPU is unavailable

    Stage 4 — Deep Reasoning
        Llama 3.2 3B through LLMAnalyst
        Activated only for suspicious/threat traffic

    Stage 5 — SOC Triage
        Sends structured events to the FastAPI/WebSocket layer

Privacy:
    - Packet payload contents are never stored
    - Only traffic metadata and statistical features are retained
    - Traffic windows exist only in memory
    - No packet data is written to disk

Simulation mode:
    Automatically activates when Scapy/Npcap/live capture is unavailable.
"""

import datetime
import json
import random
import threading
import time
from typing import Optional, Callable

from .feature_extractor import FeatureExtractor
from .anomaly_detector import AnomalyDetector
from .llm_analyst import LLMAnalyst


# ============================================================================
# Configuration
# ============================================================================

WINDOW_SEC = 30

# Stage 3 threshold.
# Scores below this value are treated as normal.
THREAT_THRESHOLD = 0.85


class PacketCapture:
    """
    HexaSentinel network packet capture and analysis pipeline.

    Pipeline:

        Packet Capture
             ↓
        Feature Extraction
             ↓
        ONNX Classification
             ↓
        Llama Analysis
             ↓
        WebSocket Event
    """

    def __init__(
        self,
        on_threat_callback: Callable,
        on_normal_callback: Optional[Callable] = None,
        analyst: Optional[LLMAnalyst] = None,
    ) -> None:

        # ====================================================================
        # AI components
        # ====================================================================

        self.extractor = FeatureExtractor()

        self.detector = AnomalyDetector()

        # The orchestrator passes the shared LLMAnalyst instance.
        # This prevents loading the Llama model multiple times.
        self.analyst = (
            analyst
            if analyst is not None
            else LLMAnalyst()
        )

        # ====================================================================
        # Event callbacks
        # ====================================================================

        self.on_threat = on_threat_callback
        self.on_normal = on_normal_callback

        # ====================================================================
        # Rolling packet window
        # ====================================================================

        self._window: list = []

        self._window_start: Optional[float] = None

        # ====================================================================
        # Thread control
        # ====================================================================

        self._running = False

        self._lock = threading.Lock()

        self._capture_thread: Optional[threading.Thread] = None

        # Simulation mode indicator
        self.simulation_mode = False

    # ========================================================================
    # Lifecycle
    # ========================================================================

    def start(
        self,
        iface: Optional[str] = None
    ) -> None:
        """
        Start network monitoring.

        Args:
            iface:
                Optional network interface.

                Example:
                    "Wi-Fi"
                    "Ethernet"

                If None, Scapy chooses the default interface.
        """

        if self._running:
            print(
                "[HexaSentinel] Packet capture is already running."
            )
            return

        self._running = True
        self.simulation_mode = False

        self._capture_thread = threading.Thread(
            target=self._stage1_capture,
            args=(iface,),
            daemon=True,
            name="HexaSentinel-PacketCapture",
        )

        self._capture_thread.start()

        print(
            "[HexaSentinel] Packet monitoring started."
        )

    def stop(self) -> None:
        """
        Stop packet monitoring.
        """

        self._running = False

        with self._lock:
            self._window.clear()
            self._window_start = None

        print(
            "[HexaSentinel] Packet monitoring stopped."
        )

    # ========================================================================
    # Stage 1 — Passive Packet Ingestion
    # ========================================================================

    def _stage1_capture(
        self,
        iface: Optional[str]
    ) -> None:
        """
        Stage 1:

        Capture packets using Scapy/Npcap.

        Payload contents are immediately discarded.
        Only statistical metadata is retained.
        """

        try:

            from scapy.all import sniff

            print(
                "[Stage 1] HexaSentinel packet capture started."
            )

            print(
                f"[Stage 1] Interface: {iface or 'default'}"
            )

            sniff(
                iface=iface,
                store=False,
                prn=self._ingest_packet,
                stop_filter=lambda _: not self._running,
            )

        except ImportError:

            print(
                "[Stage 1] Scapy is not installed."
            )

            self._simulation_mode()

        except Exception as exc:

            print(
                f"[Stage 1] Live capture unavailable: {exc}"
            )

            print(
                "[Stage 1] Switching to HexaSentinel simulation mode."
            )

            self._simulation_mode()

    # ========================================================================
    # Packet ingestion
    # ========================================================================

    def _ingest_packet(
        self,
        pkt
    ) -> None:
        """
        Convert a raw packet into privacy-safe metadata.

        IMPORTANT:

        Packet payload contents are never stored.

        Only:
            timestamp
            packet size
            protocol
            source IP
            destination IP
            source port
            destination port
            TCP flags
            payload length

        are retained.
        """

        try:

            from scapy.all import IP, TCP, UDP

            # Ignore packets that do not contain IPv4.
            if IP not in pkt:
                return

            now = time.time()

            # ---------------------------------------------------------------
            # Determine ports
            # ---------------------------------------------------------------

            source_port = 0
            destination_port = 0

            if TCP in pkt:

                source_port = int(
                    pkt[TCP].sport
                )

                destination_port = int(
                    pkt[TCP].dport
                )

            elif UDP in pkt:

                source_port = int(
                    pkt[UDP].sport
                )

                destination_port = int(
                    pkt[UDP].dport
                )

            # ---------------------------------------------------------------
            # TCP flags
            # ---------------------------------------------------------------

            tcp_flags = ""

            if TCP in pkt:

                tcp_flags = str(
                    pkt[TCP].flags
                )

            # ---------------------------------------------------------------
            # Payload length only
            # ---------------------------------------------------------------

            payload_length = 0

            try:

                if pkt[IP].payload:

                    payload_length = len(
                        bytes(pkt[IP].payload)
                    )

            except Exception:

                payload_length = 0

            # ---------------------------------------------------------------
            # Privacy-safe packet record
            # ---------------------------------------------------------------

            row = {
                "ts": now,

                "size": len(pkt),

                "proto": int(
                    pkt[IP].proto
                ),

                "src": pkt[IP].src,

                "dst": pkt[IP].dst,

                "sport": source_port,

                "dport": destination_port,

                "flags": tcp_flags,

                "payload_len": payload_length,
            }

            # IMPORTANT:
            # No packet payload/content is stored.

            with self._lock:

                # Start a new 30-second window.
                if self._window_start is None:

                    self._window_start = now

                self._window.append(row)

                # -----------------------------------------------------------
                # Process completed window
                # -----------------------------------------------------------

                if (
                    now - self._window_start
                    >= WINDOW_SEC
                ):

                    window_copy = list(
                        self._window
                    )

                    self._window.clear()

                    self._window_start = now

                    # Stage 2 runs independently so packet capture
                    # does not block while AI inference occurs.
                    threading.Thread(
                        target=self._stage2_extract,
                        args=(window_copy,),
                        daemon=True,
                        name="HexaSentinel-FeatureExtraction",
                    ).start()

        except Exception as exc:

            # Never allow one malformed packet to stop capture.
            print(
                f"[Stage 1] Packet processing error: {exc}"
            )

    # ========================================================================
    # Stage 2 — Feature Extraction
    # ========================================================================

    def _stage2_extract(
        self,
        window: list
    ) -> None:
        """
        Convert a packet window into the 80-feature model input.
        """

        if not window:
            return

        start_time = time.perf_counter()

        try:

            features = self.extractor.extract(
                window
            )

        except Exception as exc:

            print(
                f"[Stage 2] Feature extraction failed: {exc}"
            )

            return

        elapsed_ms = (
            time.perf_counter()
            - start_time
        ) * 1000.0

        print(
            f"[Stage 2] Extracted 80 features "
            f"in {elapsed_ms:.2f} ms"
        )

        self._stage3_screen(
            features,
            window,
            elapsed_ms,
        )

    # ========================================================================
    # Stage 3 — ONNX / NPU Screening
    # ========================================================================

    def _stage3_screen(
        self,
        features,
        window: list,
        stage2_ms: float
    ) -> None:
        """
        Run anomaly detection.

        The AnomalyDetector supports:

            Qualcomm QNN / Hexagon NPU
                    ↓
            CPUExecutionProvider
                    ↓
            Heuristic fallback

        Only suspicious traffic proceeds to Stage 4.
        """

        start_time = time.perf_counter()

        try:

            label, confidence, detector_ms = (
                self.detector.classify(
                    features,
                    metrics=self._build_metrics(features),
                )
            )

        except Exception as exc:

            print(
                f"[Stage 3] Classifier error: {exc}"
            )

            return

        stage3_ms = (
            time.perf_counter()
            - start_time
        ) * 1000.0

        # Use the classifier confidence as the score.
        score = float(
            max(
                0.0,
                min(
                    confidence,
                    1.0
                )
            )
        )

        timestamp = (
            datetime.datetime.now(
                datetime.timezone.utc
            ).isoformat()
        )

        print(
            f"[Stage 3] "
            f"Classification={label} "
            f"score={score:.4f} "
            f"latency={stage3_ms:.2f} ms"
        )

        # ====================================================================
        # Threat branch
        # ====================================================================

        if (
            label in ("SUSPICIOUS", "THREAT")
            or score >= THREAT_THRESHOLD
        ):

            context = self._build_threat_context(
                features,
                score,
                label,
                len(window),
            )

            self._stage4_reason(
                context,
                score,
                label,
                features,
                timestamp,
                stage2_ms,
                stage3_ms,
            )

            return

        # ====================================================================
        # Normal branch
        # ====================================================================

        if self.on_normal:

            self.on_normal(
                {
                    "label": "NORMAL",

                    "score": round(
                        score,
                        4
                    ),

                    "threshold": THREAT_THRESHOLD,

                    "window_pkts": len(
                        window
                    ),

                    "stage2_ms": round(
                        stage2_ms,
                        2
                    ),

                    "stage3_ms": round(
                        stage3_ms,
                        2
                    ),

                    "execution_provider":
                        self.detector.get_execution_provider(),

                    "timestamp": timestamp,
                }
            )

    # ========================================================================
    # Stage 4 — LLM Deep Reasoning
    # ========================================================================

    def _stage4_reason(
        self,
        context_json: str,
        score: float,
        label: str,
        features,
        timestamp: str,
        stage2_ms: float,
        stage3_ms: float,
    ) -> None:
        """
        Send suspicious traffic to the local Llama analyst.

        The LLM is not invoked for normal traffic.
        """

        start_time = time.perf_counter()

        try:

            report = self.analyst.analyze(
                context_json
            )

        except Exception as exc:

            print(
                f"[Stage 4] LLM analysis failed: {exc}"
            )

            report = (
                "HexaSentinel detected suspicious "
                "network traffic, but detailed AI "
                "analysis was unavailable."
            )

        stage4_sec = (
            time.perf_counter()
            - start_time
        )

        # ====================================================================
        # Determine final severity
        # ====================================================================

        if score >= 0.92:

            final_label = "THREAT"

        else:

            final_label = "SUSPICIOUS"

        # ====================================================================
        # Stage 5 — SOC event
        # ====================================================================

        event = {
            "label": final_label,

            "score": round(
                score,
                4
            ),

            "threshold": THREAT_THRESHOLD,

            "report": report,

            "features": {
                "pkt_rate": round(
                    float(features[0]),
                    2
                ),

                "byte_rate": round(
                    float(features[1]),
                    2
                ),

                "unique_dsts": int(
                    features[20]
                ),

                "unique_ports": int(
                    features[21]
                ),

                "syn_ratio": round(
                    float(features[22]),
                    3
                ),

                "port_entropy": round(
                    float(features[30]),
                    3
                ),

                "zero_payload": round(
                    float(features[52]),
                    3
                ),
            },

            "latency": {
                "stage2_feature_ms": round(
                    stage2_ms,
                    2
                ),

                "stage3_onnx_ms": round(
                    stage3_ms,
                    2
                ),

                "stage4_llm_sec": round(
                    stage4_sec,
                    2
                ),
            },

            "execution_provider":
                self.detector.get_execution_provider(),

            "energy_wh": 0.015,

            "simulated": False,

            "timestamp": timestamp,
        }

        if self.on_threat:

            self.on_threat(
                event
            )

    # ========================================================================
    # Threat context builder
    # ========================================================================

    def _build_threat_context(
        self,
        features,
        score: float,
        label: str,
        packet_count: int,
    ) -> str:
        """
        Build the compact JSON context passed to LLMAnalyst.
        """

        context = {
            "project": "HexaSentinel",

            "label": label,

            "score": round(
                score,
                4
            ),

            "threshold": THREAT_THRESHOLD,

            "pkt_rate": round(
                float(features[0]),
                2
            ),

            "byte_rate": round(
                float(features[1]),
                2
            ),

            "unique_dsts": int(
                features[20]
            ),

            "unique_ports": int(
                features[21]
            ),

            "syn_ratio": round(
                float(features[22]),
                3
            ),

            "syn_ack_ratio": round(
                float(features[24]),
                3
            ),

            "rst_ratio": round(
                float(features[25]),
                3
            ),

            "port_entropy": round(
                float(features[30]),
                3
            ),

            "zero_payload": round(
                float(features[52]),
                3
            ),

            "window_pkts": packet_count,

            "execution_provider":
                self.detector.get_execution_provider(),
        }

        return json.dumps(
            context
        )

    # ========================================================================
    # Feature metrics for heuristic fallback
    # ========================================================================

    def _build_metrics(
        self,
        features
    ) -> dict:
        """
        Convert selected features into the metric names expected
        by AnomalyDetector's heuristic fallback.
        """

        return {
            "packets_per_sec": float(
                features[0]
            ),

            "port_entropy": float(
                features[30]
            ),

            "syn_ack_ratio": float(
                features[24]
            ),

            "zero_payload_ratio": float(
                features[52]
            ),
        }

    # ========================================================================
    # Stage 1 Simulation Mode
    # ========================================================================

    def _simulation_mode(self) -> None:
        """
        Generate synthetic traffic events when live packet capture
        is unavailable.

        Useful for:
            - Development
            - Demo
            - CI
            - Machines without Npcap
            - Machines without administrator privileges
        """

        self.simulation_mode = True

        print(
            "[HexaSentinel] Simulation mode active."
        )

        print(
            "[HexaSentinel] "
            f"Synthetic events generated every {WINDOW_SEC} seconds."
        )

        scenarios = [

            # ---------------------------------------------------------------
            # Normal traffic
            # ---------------------------------------------------------------

            (
                0.12,
                "NORMAL",
                {
                    "pkt_rate": 12.4,
                    "byte_rate": 4820,
                    "unique_dsts": 4,
                    "unique_ports": 6,
                    "syn_ratio": 0.07,
                    "port_entropy": 1.1,
                    "zero_payload": 0.02,
                },
            ),

            (
                0.08,
                "NORMAL",
                {
                    "pkt_rate": 8.1,
                    "byte_rate": 2100,
                    "unique_dsts": 3,
                    "unique_ports": 5,
                    "syn_ratio": 0.05,
                    "port_entropy": 0.9,
                    "zero_payload": 0.01,
                },
            ),

            (
                0.23,
                "NORMAL",
                {
                    "pkt_rate": 18.2,
                    "byte_rate": 6400,
                    "unique_dsts": 6,
                    "unique_ports": 9,
                    "syn_ratio": 0.09,
                    "port_entropy": 1.8,
                    "zero_payload": 0.04,
                },
            ),

            # ---------------------------------------------------------------
            # C2 beaconing simulation
            # ---------------------------------------------------------------

            (
                0.94,
                "THREAT",
                {
                    "pkt_rate": 0.5,
                    "byte_rate": 60,
                    "unique_dsts": 1,
                    "unique_ports": 1,
                    "syn_ratio": 0.10,
                    "port_entropy": 0.1,
                    "zero_payload": 0.98,
                },
            ),

            # ---------------------------------------------------------------
            # SYN flood
            # ---------------------------------------------------------------

            (
                0.91,
                "THREAT",
                {
                    "pkt_rate": 847.0,
                    "byte_rate": 48000,
                    "unique_dsts": 1,
                    "unique_ports": 3,
                    "syn_ratio": 0.95,
                    "port_entropy": 0.4,
                    "zero_payload": 0.88,
                },
            ),

            # ---------------------------------------------------------------
            # Port scan
            # ---------------------------------------------------------------

            (
                0.87,
                "SUSPICIOUS",
                {
                    "pkt_rate": 48.2,
                    "byte_rate": 9100,
                    "unique_dsts": 22,
                    "unique_ports": 420,
                    "syn_ratio": 0.41,
                    "port_entropy": 6.1,
                    "zero_payload": 0.12,
                },
            ),

            # ---------------------------------------------------------------
            # Elevated SYN traffic
            # ---------------------------------------------------------------

            (
                0.76,
                "SUSPICIOUS",
                {
                    "pkt_rate": 32.0,
                    "byte_rate": 3200,
                    "unique_dsts": 8,
                    "unique_ports": 12,
                    "syn_ratio": 0.52,
                    "port_entropy": 2.9,
                    "zero_payload": 0.05,
                },
            ),
        ]

        # Normal traffic should appear more frequently during demos.
        weights = [
            30,
            25,
            20,
            5,
            6,
            8,
            6,
        ]

        while self._running:

            time.sleep(
                WINDOW_SEC
            )

            if not self._running:
                break

            score, label, feature_data = random.choices(
                scenarios,
                weights=weights,
                k=1,
            )[0]

            timestamp = (
                datetime.datetime.now(
                    datetime.timezone.utc
                ).isoformat()
            )

            # ================================================================
            # Threat / suspicious simulation
            # ================================================================

            if (
                score >= THREAT_THRESHOLD
                or label in (
                    "THREAT",
                    "SUSPICIOUS",
                )
            ):

                context = {
                    "project": "HexaSentinel",
                    "label": label,
                    "score": score,
                    "threshold": THREAT_THRESHOLD,
                    **feature_data,
                }

                try:

                    report = self.analyst.analyze(
                        json.dumps(
                            context
                        )
                    )

                except Exception:

                    report = (
                        "HexaSentinel simulation detected "
                        f"{label.lower()} network activity."
                    )

                if self.on_threat:

                    self.on_threat(
                        {
                            "label": label,

                            "score": score,

                            "threshold":
                                THREAT_THRESHOLD,

                            "report": report,

                            "features":
                                feature_data,

                            "latency": {
                                "stage2_feature_ms": 12.1,
                                "stage3_onnx_ms": 2.8,
                                "stage4_llm_sec": 9.4,
                            },

                            "energy_wh": 0.015,

                            "simulated": True,

                            "execution_provider":
                                self.detector.get_execution_provider(),

                            "timestamp": timestamp,
                        }
                    )

            # ================================================================
            # Normal simulation
            # ================================================================

            else:

                if self.on_normal:

                    self.on_normal(
                        {
                            "label": "NORMAL",

                            "score": score,

                            "threshold":
                                THREAT_THRESHOLD,

                            "window_pkts":
                                random.randint(
                                    200,
                                    800,
                                ),

                            "features":
                                feature_data,

                            "simulated": True,

                            "timestamp": timestamp,
                        }
                    )
