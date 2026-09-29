"""
HexaSentinel — Voice Query Endpoint
POST /api/voice — accepts audio and returns transcription + AI answer.

Powered by Whisper-Base-En + Llama 3.2 3B,
running on the Snapdragon Hexagon NPU.
"""

from fastapi import APIRouter, UploadFile, File, Form

from ..agents.whisper_agent import whisper_agent
from ..agents.orchestrator import orchestrator


router = APIRouter()


@router.post("/voice")
async def voice_query(
    audio: UploadFile = File(
        ...,
        description="WAV or raw PCM16 audio, 16 kHz mono",
    ),
    context: str = Form(
        default="",
        description="Current dashboard context for the AI",
    ),
):
    """
    Process a voice query.

    1. Transcribe audio using Whisper-Base-En.
    2. Send the transcript to Llama 3.2 3B.
    3. Return the transcript and AI response.
    """

    audio_bytes = await audio.read()

    if not audio_bytes:
        return {
            "error": "No audio received",
            "transcript": "",
            "answer": "",
        }

    # Step 1 — Speech-to-text
    transcript = whisper_agent.transcribe(
        audio_bytes,
        sample_rate=16_000,
    )

    if not transcript or transcript.startswith(
        "[Voice transcription"
    ):
        return {
            "transcript": transcript,
            "answer": (
                "Voice transcription is unavailable. "
                "Please ensure the Whisper-Base-En model "
                "is installed and available."
            ),
            "model": "whisper-base-en (unavailable)",
        }

    # Step 2 — Send transcript to Llama
    answer = orchestrator.chat(
        system_context=(
            context
            or "You are HexaSentinel, an on-device "
               "network security analyst."
        ),
        user_message=transcript,
    )

    # Step 3 — Return result
    return {
        "transcript": transcript,
        "answer": answer,
        "model": (
            "whisper-base-en + llama-3.2-3b "
            "(Qualcomm AI Hub — Hexagon NPU)"
        ),
    }


@router.get("/voice/status")
async def voice_status():
    """Return the current Whisper/NPU status."""

    return {
        "whisper_available": whisper_agent.is_available(),
        "model": "whisper-base-en (Qualcomm AI Hub)",
        "npu": "Hexagon NPU (QNN Runtime)",
        "project": "HexaSentinel",
    }
