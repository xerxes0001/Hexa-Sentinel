"""
HexaSentinel — Whisper Voice Agent

Whisper-Base-En from Qualcomm AI Hub, compiled for QNN Runtime on the
Snapdragon X Elite Hexagon NPU.

Transcribes a raw PCM / WAV audio buffer to text, then passes the
transcript to the HexaSentinel orchestrator's chat() method so voice
queries receive the same Llama-powered answers as typed queries.

Usage:
    agent = WhisperAgent()
    transcript = agent.transcribe(audio_bytes, sample_rate=16000)
    answer = orchestrator.chat(system_ctx, transcript)
"""

import io
import threading

import numpy as np


class WhisperAgent:
    """
    Thread-safe Whisper-Base-En wrapper.

    Falls back to a stub when Qualcomm AI Hub or
    NPU hardware is unavailable.
    """

    def __init__(self):
        self._model = None
        self._lock = threading.Lock()
        self._load()

    def _load(self):
        try:
            from qai_hub_models.models.whisper_base_en import Model

            print(
                "[WhisperAgent] Loading Whisper-Base-En "
                "from Qualcomm AI Hub..."
            )

            self._model = Model.from_pretrained()

            print(
                "[WhisperAgent] Whisper-Base-En loaded "
                "on Hexagon NPU"
            )

        except ImportError:
            print(
                "[WhisperAgent] qai-hub-models not installed "
                "— voice query unavailable"
            )

        except Exception as exc:
            print(
                f"[WhisperAgent] Load failed: {exc} "
                "— using stub transcription"
            )

    def is_available(self) -> bool:
        return self._model is not None

    def transcribe(
        self,
        audio_bytes: bytes,
        sample_rate: int = 16_000
    ) -> str:
        """
        Transcribe raw PCM16 or WAV audio bytes to text.

        Returns an empty string on invalid audio.
        """

        if not audio_bytes:
            return ""

        try:
            audio_array = self._decode_audio(
                audio_bytes,
                sample_rate
            )

        except Exception as exc:
            print(
                f"[WhisperAgent] Audio decode error: {exc}"
            )
            return ""

        if self._model is not None:

            with self._lock:

                try:
                    result = self._model.transcribe(
                        audio_array,
                        sample_rate=sample_rate
                    )

                    text = result.get(
                        "text",
                        ""
                    ).strip()

                    print(
                        f"[WhisperAgent] Transcribed: '{text}'"
                    )

                    return text

                except Exception as exc:
                    print(
                        f"[WhisperAgent] Transcription error: {exc}"
                    )

        return (
            "[Voice transcription unavailable — "
            "Whisper NPU model not loaded]"
        )

    def _decode_audio(
        self,
        audio_bytes: bytes,
        sample_rate: int
    ) -> np.ndarray:
        """
        Accept WAV files or raw PCM16 little-endian bytes.

        Returns float32 audio normalized to [-1.0, 1.0].
        """

        # WAV input
        if audio_bytes[:4] == b"RIFF":

            import wave

            with wave.open(
                io.BytesIO(audio_bytes)
            ) as wf:

                frames = wf.readframes(
                    wf.getnframes()
                )

                return (
                    np.frombuffer(
                        frames,
                        dtype=np.int16
                    )
                    .astype(np.float32)
                    / 32768.0
                )

        # Raw PCM16 input
        return (
            np.frombuffer(
                audio_bytes,
                dtype=np.int16
            )
            .astype(np.float32)
            / 32768.0
        )


# Module-level singleton
whisper_agent = WhisperAgent()
