"""
HexaSentinel — WebSocket Endpoint

Streams real-time network threat events from the on-device
security pipeline to the React dashboard.
"""

import asyncio

from fastapi import (
    APIRouter,
    WebSocket,
    WebSocketDisconnect,
)

from ..agents.orchestrator import orchestrator


router = APIRouter()


@router.websocket("/ws")
async def threat_stream(ws: WebSocket):
    """Stream real-time HexaSentinel events to the dashboard."""

    await ws.accept()

    loop = asyncio.get_running_loop()

    def send_to_ws(payload: str):
        """
        Called by the background packet-capture thread.

        Schedules the WebSocket send on FastAPI's event loop.
        """
        try:
            asyncio.run_coroutine_threadsafe(
                ws.send_text(payload),
                loop,
            )
        except Exception:
            pass

    orchestrator.subscribe(send_to_ws)

    try:
        while True:
            data = await ws.receive_text()

            if data == "ping":
                await ws.send_text(
                    '{"type":"pong"}'
                )

    except WebSocketDisconnect:
        pass

    finally:
        orchestrator.unsubscribe(send_to_ws)
