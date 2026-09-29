


"""
HexaSentinel — LLM Analyst
==========================

Llama 3.2 3B Instruct sourced from Qualcomm AI Hub.

Designed for local inference on Qualcomm Snapdragon hardware.
No cloud API calls are required during normal inference.

If the Qualcomm AI Hub model is unavailable, HexaSentinel uses
a deterministic fallback so the backend remains functional during
development and testing.
"""

import datetime
import json
import threading
from typing import Any, Dict, Optional

# ============================================================================
# System prompts
# ============================================================================

SYSTEM_PROMPT = (
    "You are HexaSentinel, an on-device network security analyst "
    "running on a Qualcomm Snapdragon X Elite AI PC. "
    "You analyse network traffic anomalies detected by the local "
    "ONNX classifier and produce concise, technically accurate threat reports.\n\n"

    "For every threat context provided, generate exactly this structure:\n"
    "SEVERITY: <INFO|WARNING|CRITICAL>\n"
    "WHAT HAPPENED: <1-2 sentences, plain English>\n"
    "ATTACK VECTOR: <likely attack type and affected services>\n"
    "ACTIONS:\n"
    "1. <specific immediate action>\n"
    "2. <specific immediate action>\n"
    "3. <specific immediate action>\n\n"

    "Be specific, actionable, technically accurate, and under 200 words. "
    "Do not use markdown."
)

CHAT_SYSTEM_PROMPT = (
    "You are HexaSentinel, an on-device network security analyst. "
    "You have access to local network traffic analysis and threat "
    "intelligence processed by the Hexagon NPU. "
    "Answer questions about network security, BGP incidents, RPKI, "
    "CERT-In procedures, and Indian internet infrastructure. "
    "Be concise, technically accurate, and clear. "
    "Do not use markdown formatting."
)

class LLMAnalyst:
    """
    Thread-safe wrapper around Llama 3.2 3B Instruct.

    A single instance can be shared by the FastAPI backend through
    the HexaSentinel orchestrator.

    The lock prevents multiple simultaneous model generations from
    competing for the same model instance.
    """

    def __init__(self) -> None:
        self._model: Optional[Any] = None
        self._lock = threading.Lock()

        self._model_loaded = False
        self._load_error: Optional[str] = None

        self._load()

    # ========================================================================
    # Model loading
    # ========================================================================

    def _load(self) -> None:
        """
        Load Llama 3.2 3B from Qualcomm AI Hub.

        If the Qualcomm package or model is unavailable, the analyst
        remains operational through the deterministic fallback.
        """

        try:
            from qai_hub_models.models.llama_v3_2_3b_chat_quantized import (
                Model
            )

            print(
                "[LLMAnalyst] Loading Llama 3.2 3B "
                "from Qualcomm AI Hub..."
            )

            self._model = Model.from_pretrained()

            self._model_loaded = True
            self._load_error = None

            print(
                "[LLMAnalyst] Llama 3.2 3B loaded successfully."
            )

            print(
                "[LLMAnalyst] HexaSentinel AI analyst is ready."
            )

        except ImportError:
            self._load_error = (
                "qai-hub-models is not installed."
            )

            print(
                "[LLMAnalyst] qai-hub-models is not installed."
            )

            print(
                "[LLMAnalyst] The deterministic fallback will be used."
            )

        except Exception as exc:
            self._load_error = str(exc)

            print(
                "[LLMAnalyst] Llama 3.2 3B model loading failed:"
            )

            print(
                f"[LLMAnalyst] {exc}"
            )

            print(
                "[LLMAnalyst] Using deterministic fallback."
            )

    # ========================================================================
    # Public API
    # ========================================================================

    def analyze(
        self,
        threat_context_json: Any
    ) -> str:
        """
        Analyse a network threat context.

        BGP incidents are routed to the specialised BGP prompt.
        Other incidents use the standard network-threat prompt.
        """

        try:

            if isinstance(threat_context_json, str):
                context = json.loads(
                    threat_context_json
                )

            else:
                context = threat_context_json

            if (
                isinstance(context, dict)
                and context.get("type") == "bgp_incident"
            ):
                return self._analyze_bgp(context)

        except (
            TypeError,
            ValueError,
            json.JSONDecodeError,
        ):
            pass

        prompt = (
            f"{SYSTEM_PROMPT}\n\n"
            "Threat Context (JSON):\n"
            f"{self._serialize_context(threat_context_json)}"
        )

        return self._run(prompt)

    # ========================================================================
    # BGP analysis
    # ========================================================================

    def _analyze_bgp(
        self,
        context: Dict[str, Any]
    ) -> str:
        """
        Generate analysis specifically for a BGP routing incident.
        """

        repeat_attack = (
            f"Yes ({context.get('repeat_count')} attacks)"
            if context.get("is_repeat")
            else "No"
        )

        coordinated_attack = (
            "Yes — BGP + TLS certificate"
            if context.get("coordinated")
            else "No"
        )

        bgp_prompt = (
            "You are HexaSentinel, an on-device BGP and "
            "network security analyst.\n\n"

            "Analyse this BGP routing incident detected by "
            "HexaSentinel:\n\n"

            f"PREFIX HIJACKED: "
            f"{context.get('prefix', 'unknown')}\n"

            f"ATTACKER ASN: "
            f"{context.get('attacker_asn', 'unknown')} "
            f"({context.get('attacker_name', 'unknown')}, "
            f"{context.get('attacker_country', 'unknown')})\n"

            f"VICTIM ASN: "
            f"{context.get('victim_asn', 'unknown')} "
            f"({context.get('victim_name', 'unknown')}, "
            f"sector: {context.get('victim_sector', 'unknown')})\n"

            f"SEVERITY: "
            f"{context.get('severity', 'unknown')}\n"

            f"CONFIDENCE: "
            f"{context.get('confidence', 'unknown')}%\n"

            f"PATH ANOMALY: "
            f"{context.get('path_anomaly', 'none')}\n"

            f"RPKI STATE: "
            f"{context.get('rpki_state', 'unknown')}\n"

            f"REPEAT ATTACKER: "
            f"{repeat_attack}\n"

            f"COORDINATED ATTACK: "
            f"{coordinated_attack}\n\n"

            "Generate exactly:\n"
            "SEVERITY: <INFO|WARNING|CRITICAL>\n"
            "WHAT HAPPENED: <2 sentences explaining the routing "
            "incident in plain English>\n"
            "ATTACK VECTOR: <technical description of the BGP "
            "manipulation technique>\n"
            "INDIAN IMPACT: <which Indian services/users may be affected>\n"
            "ACTIONS:\n"
            "1. <immediate NOC action>\n"
            "2. <RPKI/routing action>\n"
            "3. <CERT-In notification or escalation step>\n\n"

            "Be specific about BGP routing, RPKI, and Indian "
            "internet infrastructure. Under 220 words."
        )

        return self._run(
            bgp_prompt,
            max_new_tokens=280
        )

    # ========================================================================
    # Chat
    # ========================================================================

    def chat(
        self,
        system_context: str,
        user_message: str
    ) -> str:
        """
        Single-turn security Q&A for the HexaSentinel dashboard.
        """

        full_system = (
            f"{CHAT_SYSTEM_PROMPT}\n\n"
            f"Current HexaSentinel State:\n"
            f"{system_context}"
        )

        prompt = (
            f"{full_system}\n\n"
            f"User: {user_message}\n"
            "HexaSentinel:"
        )

        return self._run(
            prompt,
            max_new_tokens=300
        )

    # ========================================================================
    # CERT-In report
    # ========================================================================

    def generate_certin_report(
        self,
        incident: Dict[str, Any],
        analysis: str
    ) -> str:
        """
        Generate a formal CERT-In-style network incident report.
        """

        timestamp = datetime.datetime.now()

        incident_id = (
            "CERT-IN-NW-"
            f"{timestamp.strftime('%Y%m%d-%H%M')}"
        )

        prompt = (
            "You are a cybersecurity incident-reporting specialist.\n\n"

            "Generate a formal CERT-In-style network incident report.\n\n"

            f"Incident ID: {incident_id}\n"
            f"Date/Time: {timestamp.isoformat()}\n"
            f"Detection: {incident.get('label', 'THREAT')} "
            f"at {incident.get('confidence', 0)}% confidence\n\n"

            f"Prior Analysis:\n"
            f"{analysis}\n\n"

            "Include these sections:\n"
            "Executive Summary\n"
            "Incident Classification\n"
            "Technical Timeline\n"
            "Network Analysis\n"
            "Impact Assessment\n"
            "Indicators of Compromise\n"
            "Immediate Actions\n"
            "Recommendations\n\n"

            "Return plain text only. Do not use markdown."
        )

        return self._run(
            prompt,
            max_new_tokens=600
        )

    # ========================================================================
    # ISP notification
    # ========================================================================

    def generate_isp_notification(
        self,
        incident: Dict[str, Any]
    ) -> str:
        """
        Generate an ISP/NOC notification draft.
        """

        prompt = (
            "You are a senior network security engineer.\n\n"

            "Draft an urgent ISP NOC notification for a "
            "detected network threat.\n\n"

            f"Detection: {incident.get('label', 'THREAT')} "
            f"at {incident.get('confidence', 0)}% confidence\n\n"

            "Include:\n"
            "TO field\n"
            "SUBJECT line\n"
            "Technical incident description\n"
            "Affected services\n"
            "Attack indicators\n"
            "Immediate actions required\n"
            "Requested response timeline\n\n"

            "Plain text only."
        )

        return self._run(
            prompt,
            max_new_tokens=400
        )

    # ========================================================================
    # Inference
    # ========================================================================

    def _run(
        self,
        prompt: str,
        max_new_tokens: int = 250
    ) -> str:
        """
        Perform thread-safe local model inference.

        Falls back to deterministic output if the model is unavailable
        or inference fails.
        """

        if self._model is not None:

            with self._lock:

                try:

                    result = self._model.generate(
                        prompt,
                        max_new_tokens=max_new_tokens
                    )

                    if result:
                        return str(result).strip()

                except Exception as exc:

                    print(
                        f"[LLMAnalyst] Inference error: {exc}"
                    )

        return self._fallback(prompt)

    # ========================================================================
    # Deterministic fallback
    # ========================================================================

    def _fallback(
        self,
        prompt: str
    ) -> str:
        """
        Deterministic fallback used during development, CI, or when
        the local Llama model cannot be loaded.
        """

        # --------------------------------------------------------------------
        # CERT-In fallback
        # --------------------------------------------------------------------

        if (
            "CERT-In" in prompt
            or "CERT-IN" in prompt
        ):

            return (
                "CERT-IN INCIDENT REPORT\n"
                "========================\n"
                "EXECUTIVE SUMMARY: Anomalous network traffic was "
                "detected by the HexaSentinel on-device classifier.\n\n"
                "STATUS: Template response — local Llama model "
                "is unavailable.\n\n"
                "ACTION: Verify the Qualcomm AI Hub model installation "
                "and local model setup."
            )

        # --------------------------------------------------------------------
        # ISP / NOC fallback
        # --------------------------------------------------------------------

        if (
            "NOC" in prompt
            or "ISP" in prompt
        ):

            return (
                "TO: ISP NOC\n"
                "SUBJECT: URGENT — HexaSentinel Network Anomaly Detected\n\n"
                "HexaSentinel detected anomalous network traffic. "
                "The local Llama model is currently unavailable, "
                "so manual investigation is recommended.\n\n"
                "Please review firewall, endpoint, and network logs "
                "and investigate the reported indicators."
            )

        # --------------------------------------------------------------------
        # Generic threat fallback
        # --------------------------------------------------------------------

        label = "SUSPICIOUS"
        confidence = 70.0
        packet_rate = 0.0
        port_entropy = 0.0

        try:

            marker = "Threat Context (JSON):"

            if marker in prompt:

                raw_context = prompt.split(
                    marker,
                    1
                )[1].strip()

                context = json.loads(
                    raw_context
                )

                if isinstance(context, dict):

                    label = str(
                        context.get(
                            "label",
                            label
                        )
                    )

                    confidence = float(
                        context.get(
                            "confidence",
                            confidence
                        )
                    )

                    packet_rate = float(
                        context.get(
                            "pkt_rate",
                            0
                        )
                    )

                    port_entropy = float(
                        context.get(
                            "port_entropy",
                            0
                        )
                    )

        except (
            TypeError,
            ValueError,
            json.JSONDecodeError
        ):
            pass

        # Determine fallback severity.
        normalized_label = label.upper()

        if normalized_label == "THREAT":
            severity = "CRITICAL"

        elif normalized_label == "SUSPICIOUS":
            severity = "WARNING"

        else:
            severity = "INFO"

        return (
            f"SEVERITY: {severity}\n"

            f"WHAT HAPPENED: HexaSentinel detected anomalous "
            f"network traffic using its on-device classifier "
            f"({label} at {confidence:.1f}% confidence). "
            f"Observed packet rate: {packet_rate:.1f}/s and "
            f"destination-port entropy: {port_entropy:.2f}.\n"

            "ATTACK VECTOR: The traffic pattern may be consistent "
            "with scanning, connection flooding, or beacon-like "
            "network behaviour and requires further investigation.\n"

            "ACTIONS:\n"

            "1. Review active connections and recent firewall logs.\n"

            "2. Investigate repeated connections to unusual "
            "destinations or ports.\n"

            "3. If the incident is confirmed as critical, "
            "isolate the affected endpoint and notify the "
            "network administrator.\n\n"

            "[HexaSentinel fallback: local Llama 3.2 3B model "
            "is currently unavailable.]"
        )

    # ========================================================================
    # Status helpers
    # ========================================================================

    def is_model_loaded(self) -> bool:
        """
        Return True when the local Llama model is loaded.
        """

        return self._model_loaded

    def get_status(self) -> Dict[str, Any]:
        """
        Return model status information for the API/dashboard.
        """

        return {
            "model": "Llama 3.2 3B Instruct",
            "provider": "Qualcomm AI Hub",
            "local_inference": True,
            "model_loaded": self._model_loaded,
            "fallback_active": not self._model_loaded,
            "load_error": self._load_error,
        }

    # ========================================================================
    # Utility
    # ========================================================================

    @staticmethod
    def _serialize_context(
        context: Any
    ) -> str:
        """
        Safely convert a threat context to readable JSON.
        """

        try:

            return json.dumps(
                context,
                indent=2,
                default=str
            )

        except (
            TypeError,
            ValueError
        ):

            return str(context)


