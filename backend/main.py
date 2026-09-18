"""
Cerberus Backend API & WebSocket Server
FastAPI application handling file uploads, sandbox session orchestration,
and real-time WebSocket telemetry event streaming to the frontend cockpit.
"""

from pathlib import Path
from fastapi import FastAPI, UploadFile, File, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import uvicorn
import logging

from .sandbox_launcher import SandboxLauncher
from .monitor_bridge import MonitorBridge

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("cerberus")

app = FastAPI(
    title="Cerberus Sandbox API",
    description="Windows-Native Behavioral Sandbox with Real-Time ETW Telemetry and Instant Threat Containment",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Core subsystems
launcher = SandboxLauncher()
monitor = MonitorBridge()

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"


@app.get("/api/system/status")
async def get_system_status():
    """Retrieve host system capability and Windows Sandbox availability status."""
    return launcher.support_info


@app.post("/api/upload")
async def upload_payload(file: UploadFile = File(...)):
    """
    Accepts an uploaded file/script, creates an isolated sandbox session,
    stages the payload, launches Windows Sandbox (or activates host fallback),
    and returns session coordinates for WebSocket streaming.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename missing")

    content = await file.read()
    session = launcher.create_session(filename=file.filename, content=content)
    launcher.generate_wsb_config(session)
    launcher.launch_sandbox(session)

    logger.info(
        f"Created session {session.session_id} for target '{session.filename}' ({len(content)} bytes), "
        f"PID: {session.target_pid}, FallbackHostMode: {session.fallback_host_mode}"
    )

    return {
        "session_id": session.session_id,
        "filename": session.filename,
        "filesize": session.filesize,
        "target_pid": session.target_pid,
        "status": session.status,
        "fallback_host_mode": session.fallback_host_mode,
        "ws_url": f"/ws/analysis/{session.session_id}",
    }


@app.get("/api/session/{session_id}")
async def get_session_info(session_id: str):
    """Retrieve metadata and current status for a given session."""
    session = launcher.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    return {
        "session_id": session.session_id,
        "filename": session.filename,
        "filesize": session.filesize,
        "target_pid": session.target_pid,
        "status": session.status,
        "contained": session.contained,
    }


@app.websocket("/ws/analysis/{session_id}")
async def websocket_analysis_stream(websocket: WebSocket, session_id: str):
    """
    WebSocket endpoint that streams real-time behavioral telemetry,
    policy violation alerts, and freeze/sever actions to the client.
    """
    await websocket.accept()
    session = launcher.get_session(session_id)

    if not session:
        await websocket.send_json({
            "type": "ERROR",
            "title": "Invalid Session",
            "description": f"Session '{session_id}' not found.",
            "severity": "critical",
        })
        await websocket.close()
        return

    logger.info(f"WebSocket client connected for session {session_id}")

    try:
        # Await client ready signal or start immediately
        async for event in monitor.stream_events(session):
            if event.get("type") == "VERDICT":
                if event.get("verdict_state") == "FROZEN":
                    launcher.freeze_session(session_id)
                session.status = event.get("verdict_state", "COMPLETED")

            await websocket.send_json(event)

        logger.info(f"Finished telemetry stream for session {session_id}. Verdict: {session.status}")
    except WebSocketDisconnect:
        logger.warning(f"Client disconnected early from session {session_id}")
    except Exception as e:
        logger.error(f"Error during WebSocket stream: {e}", exc_info=True)
        try:
            await websocket.send_json({"type": "ERROR", "description": str(e), "severity": "critical"})
        except Exception:
            pass


# Mount frontend static files
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

    @app.get("/")
    async def serve_index():
        return FileResponse(FRONTEND_DIR / "index.html")

    @app.get("/timeline")
    @app.get("/timeline.html")
    async def serve_timeline():
        return FileResponse(FRONTEND_DIR / "timeline.html")

    @app.get("/report")
    @app.get("/report.html")
    async def serve_report():
        return FileResponse(FRONTEND_DIR / "report.html")

    @app.get("/architecture")
    @app.get("/architecture.html")
    async def serve_architecture():
        return FileResponse(FRONTEND_DIR / "architecture.html")


if __name__ == "__main__":
    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=True)
