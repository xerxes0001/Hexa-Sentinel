"""
HexaSentinel — Orchestrator
===========================

Coordinates the complete HexaSentinel on-device security pipeline:

PacketCapture
      ↓
FeatureExtractor
      ↓
AnomalyDetector
      ↓
LLMAnalyst
      ↓
React Dashboard / WebSocket

The orchestrator acts as the central coordinator for the backend.

A module-level singleton is used so FastAPI endpoints and the
WebSocket handler share:
- One PacketCapture instance
- One LLMAnalyst instance
- One model loaded in memory
- One capture pipeline
- One subscriber list
"""

import json
import threading
from typing import Callable, Optional

from .packet_capture import PacketCapture
from .llm_analyst import LLMAnalyst


class HexaSentinelOrchestrator:
    """
    Central coordinator for the HexaSentinel backend pipeline.
    """

    def __init__(self) -> None:

        # ====================================================================
        # Shared AI analyst
        # ====================================================================

        # Only one LLMAnalyst instance is created.
        # This prevents loading the Llama model multiple times.
        self._analyst = LLMAnalyst()

        # ====================================================================
        # WebSocket subscribers
        # ====================================================================

        self._subscribers: list[Callable[[str], None]] = []

        self._sub_lock = threading.Lock()

        # ====================================================================
        # Runtime statistics
        # ====================================================================

        self._stats = {
            "windows_processed": 0,
            "threats_detected": 0,
            "suspicious": 0,
            "normal": 0,
            "simulated": 0,
        }

        # ====================================================================
        # Packet capture pipeline
        # ====================================================================

        self._capture = PacketCapture(
            on_threat_callback=self._on_threat,
            on_normal_callback=self._on_normal,
            analyst=self._analyst,
        )

    # ========================================================================
    # Lifecycle
    # ========================================================================

    def start(
        self,
        iface: Optional[str] = None
    ) -> None:
        """
        Start the HexaSentinel packet-monitoring pipeline.

        Args:
            iface:
                Optional network interface name.
                If None, PacketCapture chooses the appropriate interface.
        """

        self._capture.start(iface)

        print(
            "[HexaSentinel] On-device security pipeline started."
        )

    def stop(self) -> None:
        """
        Stop packet capture and the monitoring pipeline.
        """

        self._capture.stop()

        print(
            "[HexaSentinel] Security pipeline stopped."
        )

    # ========================================================================
    # WebSocket subscriber management
    # ========================================================================

    def subscribe(
        self,
        callback: Callable[[str], None]
    ) -> None:
        """
        Register a WebSocket/event subscriber.
        """

        with self._sub_lock:

            if callback not in self._subscribers:
                self._subscribers.append(callback)

    def unsubscribe(
        self,
        callback: Callable[[str], None]
    ) -> None:
        """
        Remove a WebSocket/event subscriber.
        """

        with self._sub_lock:

            self._subscribers = [
                subscriber
                for subscriber in self._subscribers
                if subscriber is not callback
            ]

    def _broadcast(
        self,
        payload: str
    ) -> None:
        """
        Broadcast an event to all connected subscribers.

        Failed/dead subscribers are automatically removed.
        """

        with self._sub_lock:

            dead_subscribers = []

            for callback in list(self._subscribers):

                try:
                    callback(payload)

                except Exception as exc:

                    print(
                        "[HexaSentinel] WebSocket subscriber error:",
                        exc
                    )

                    dead_subscribers.append(callback)

            for callback in dead_subscribers:

                if callback in self._subscribers:
                    self._subscribers.remove(callback)

    # ========================================================================
    # Threat pipeline callbacks
    # ========================================================================

    def _on_threat(
        self,
        event: dict
    ) -> None:
        """
        Called by PacketCapture when a suspicious or malicious
        traffic window is detected.
        """

        score = float(
            event.get(
                "score",
                event.get(
                    "confidence",
                    0.0
                )
            )
        )

        # ------------------------------------------------------------
        # Update threat statistics
        # ------------------------------------------------------------

        if score >= 0.92:

            self._stats["threats_detected"] += 1

        else:

            self._stats["suspicious"] += 1

        self._stats["windows_processed"] += 1

        # ------------------------------------------------------------
        # Simulation-mode statistics
        # ------------------------------------------------------------

        if event.get("simulated", False):

            self._stats["simulated"] += 1

        # ------------------------------------------------------------
        # Broadcast event to React dashboard
        # ------------------------------------------------------------

        payload = {
            "type": "threat",
            **event,
        }

        self._broadcast(
            json.dumps(
                payload,
                default=str
            )
        )

    def _on_normal(
        self,
        event: dict
    ) -> None:
        """
        Called by PacketCapture when a traffic window is classified
        as normal.
        """

        self._stats["normal"] += 1
        self._stats["windows_processed"] += 1

        # ------------------------------------------------------------
        # Do not broadcast every normal packet window.
        #
        # Every fifth window is sent as a heartbeat to keep the
        # dashboard informed without flooding the WebSocket.
        # ------------------------------------------------------------

        if self._stats["windows_processed"] % 5 == 0:

            payload = {
                "type": "heartbeat",
                **event,
            }

            self._broadcast(
                json.dumps(
                    payload,
                    default=str
                )
            )

    # ========================================================================
    # AI / analysis endpoints
    # ========================================================================

    def analyze_incident(
        self,
        context: dict | str
    ) -> str:
        """
        Analyse a network incident using the HexaSentinel LLM analyst.

        Used by:
            POST /api/analyze

        Supports both dictionary and JSON-string input.
        """

        if isinstance(context, dict):

            context = json.dumps(
                context,
                default=str
            )

        return self._analyst.analyze(
            context
        )

    def chat(
        self,
        system_context: str,
        user_message: str
    ) -> str:
        """
        Send a user question to the HexaSentinel local AI analyst.

        Used by:
            POST /api/chat
        """

        return self._analyst.chat(
            system_context,
            user_message
        )

    def generate_certin_report(
        self,
        incident: dict,
        analysis: str
    ) -> str:
        """
        Generate a CERT-In-style incident report.
        """

        return self._analyst.generate_certin_report(
            incident,
            analysis
        )

    def generate_isp_notification(
        self,
        incident: dict
    ) -> str:
        """
        Generate an ISP/NOC notification.
        """

        return self._analyst.generate_isp_notification(
            incident
        )

    # ========================================================================
    # Runtime status
    # ========================================================================

    def get_stats(self) -> dict:
        """
        Return current HexaSentinel pipeline statistics.
        """

        stats = dict(
            self._stats
        )

        total = max(
            stats["windows_processed"],
            1
        )

        stats["simulated_ratio"] = round(
            stats["simulated"] / total,
            3
        )

        return stats

    def get_ai_status(self) -> dict:
        """
        Return the current LLM/model status.

        This can be exposed through /api/health.
        """

        return self._analyst.get_status()

    def get_status(self) -> dict:
        """
        Return combined orchestrator status.
        """

        return {
            "project": "HexaSentinel",
            "pipeline": "PacketCapture → FeatureExtractor → AnomalyDetector → LLMAnalyst",
            "statistics": self.get_stats(),
            "ai": self.get_ai_status(),
        }


# ============================================================================
# Module-level singleton
# ============================================================================

# FastAPI routes, WebSocket handlers, and other backend modules should
# import this instance instead of creating another orchestrator.

orchestrator = HexaSentinelOrchestrator()
