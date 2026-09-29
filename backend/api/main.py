"""
HexaSentinel — FastAPI Application
===================================

Localhost-only API server that bridges the HexaSentinel on-device
AI pipeline with the React dashboard.

Pipeline:
    Scapy → Feature Extraction → ONNX/QNN → Llama 3.2 3B → React

Run:
    uvicorn backend.api.main:app --host 127.0.0.1 --port 8000 --reload

Runtime:
    100% local / on-device
    No cloud API dependency
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .websocket import router as ws_router
from .reports import router as report_router
from .voice import router as voice_router
from ..agents.orchestrator import orchestrator


# ---------------------------------------------------------------------------
# Application lifecycle
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Start the HexaSentinel network monitoring pipeline when the
    FastAPI server starts and stop it during shutdown.
    """

    print("[HexaSentinel] Starting on-device security pipeline...")

    try:
        orchestrator.start()
        print("[HexaSentinel] Pipeline started successfully.")
        yield

    finally:
        print("[HexaSentinel] Stopping security pipeline...")
        orchestrator.stop()
        print("[HexaSentinel] Pipeline stopped.")


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="HexaSentinel On-Device Security API",
    version="1.0.0",
    description=(
        "Privacy-first, on-device network threat intelligence system "
        "powered by Llama 3.2 3B and an ONNX anomaly classifier "
        "running on Qualcomm Snapdragon Hexagon NPU."
    ),
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:4173",
        "http://127.0.0.1:4173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------

app.include_router(ws_router)
app.include_router(report_router)
app.include_router(voice_router, prefix="/api")


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class ChatRequest(BaseModel):
    """
    Request body for the /api/chat endpoint.
    """

    messages: list[dict] = Field(default_factory=list)
    context: str = ""


class AnalyzeRequest(BaseModel):
    """
    Request body for the /api/analyze endpoint.
    """

    context: dict | str = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Chat endpoint
# ---------------------------------------------------------------------------

@app.post("/api/chat")
async def chat(body: ChatRequest):
    """
    Send a security question to the local Llama 3.2 3B analyst.

    Used by:
        - AdminChat.jsx
        - ConversationalQuery.jsx

    No request is sent to a cloud AI provider.
    """

    user_message = ""

    if body.messages:
        last_message = body.messages[-1]

        if isinstance(last_message, dict):
            user_message = str(
                last_message.get("content", "")
            )

    reply = orchestrator.chat(
        body.context,
        user_message,
    )

    return {
        "reply": reply,
        "model": "llama-3.2-3b-instruct-qnn",
        "provider": "Qualcomm AI Hub — Hexagon NPU",
        "system": "HexaSentinel",
        "cloud": False,
    }


# ---------------------------------------------------------------------------
# Incident analysis endpoint
# ---------------------------------------------------------------------------

@app.post("/api/analyze")
async def analyze(body: AnalyzeRequest):
    """
    Perform on-demand analysis of a network or BGP incident.

    Used by the frontend incident-analysis panels.
    """

    result = orchestrator.analyze_incident(
        body.context
    )

    return {
        "analysis": result,
        "model": "llama-3.2-3b-instruct-qnn",
        "provider": "Qualcomm AI Hub — Hexagon NPU",
        "system": "HexaSentinel",
        "cloud": False,
    }


# ---------------------------------------------------------------------------
# Health endpoint
# ---------------------------------------------------------------------------

@app.get("/api/health")
async def health():
    """
    Return the current HexaSentinel pipeline status.
    """

    return {
        "status": "ok",
        "system": "HexaSentinel",
        "pipeline": "on-device",
        "llm": "llama-3.2-3b-instruct",
        "llm_provider": "Qualcomm AI Hub",
        "classifier": "onnx-anomaly-classifier",
        "accelerator": "Qualcomm Hexagon NPU",
        "cloud": False,
        "stats": orchestrator.get_stats(),
    }


# ---------------------------------------------------------------------------
# Root endpoint
# ---------------------------------------------------------------------------

@app.get("/")
async def root():
    """
    Basic API information.
    """

    return {
        "name": "HexaSentinel",
        "description": (
            "On-device network threat intelligence "
            "and anomaly detection system."
        ),
        "status": "running",
        "docs": "/docs",
        "health": "/api/health",
    }
