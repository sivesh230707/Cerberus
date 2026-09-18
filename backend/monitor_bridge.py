"""
Cerberus Monitor Bridge (Live Subprocess IPC)
Spawns and manages the compiled C# Windows Host Agent (CerberusAgent.exe).
Streams real-time Win32 / ETW telemetry events and containment actions
directly from the agent's unbuffered stdout over WebSocket to the cockpit.
"""

import asyncio
import json
import logging
import subprocess
from pathlib import Path
from typing import AsyncGenerator, Dict, Any, Optional

from .sandbox_launcher import SandboxSession

logger = logging.getLogger("cerberus.monitor")


class MonitorBridge:
    """
    Interfaces directly with the native CerberusAgent.exe via asynchronous
    standard I/O subprocess streaming. Reads live ETW events, rule violations,
    thread suspension actions, and WFP containment states in real time.
    """

    def __init__(self, agent_bin_path: Optional[Path] = None):
        if agent_bin_path:
            self.agent_exe = agent_bin_path
        else:
            base_dir = Path(__file__).resolve().parent.parent
            self.agent_exe = base_dir / "windows-agent" / "bin" / "CerberusAgent.exe"

        self._ensure_agent_binary()

    def _ensure_agent_binary(self) -> None:
        """Verifies that the compiled C# agent binary exists. If missing, compiles it."""
        if not self.agent_exe.exists():
            logger.info("CerberusAgent.exe not found. Triggering automated build via build.ps1...")
            script_dir = self.agent_exe.parent.parent
            build_script = script_dir / "build.ps1"
            if build_script.exists():
                try:
                    result = subprocess.run(
                        ["powershell.exe", "-ExecutionPolicy", "Bypass", "-File", str(build_script)],
                        capture_output=True,
                        text=True,
                        check=True
                    )
                    logger.info("CerberusAgent.exe compiled successfully:\n%s", result.stdout)
                except subprocess.CalledProcessError as e:
                    logger.error("Failed to build CerberusAgent.exe: %s\nStderr: %s", e, e.stderr)
            else:
                logger.warning("build.ps1 not found at %s", build_script)

    async def stream_events(self, session: SandboxSession) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Launches the target file through CerberusAgent.exe as an asynchronous subprocess.
        Streams real unbuffered JSON-lines telemetry output directly to the WebSocket client.
        """
        self._ensure_agent_binary()

        if not self.agent_exe.exists():
            yield {
                "timestamp": session.created_at.strftime("%H:%M:%S.%f")[:-3],
                "type": "ERROR",
                "category": "system",
                "severity": "critical",
                "title": "Agent Binary Missing",
                "description": f"Could not find compiled CerberusAgent.exe at '{self.agent_exe}'. Please run build.ps1.",
                "details": {"agent_path": str(self.agent_exe)},
                "session_id": session.session_id,
            }
            return

        cmd = [
            str(self.agent_exe),
            "launch",
            "--file", str(session.filepath.resolve()),
            "--mem-mb", str(session.memory_limit_mb),
        ]

        logger.info("Spawning native agent for session %s: %s", session.session_id, " ".join(cmd))

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        try:
            while True:
                line_bytes = await proc.stdout.readline()
                if not line_bytes:
                    break

                line = line_bytes.decode("utf-8", errors="replace").strip()
                if not line:
                    continue

                if line.startswith("{") and line.endswith("}"):
                    try:
                        event = json.loads(line)
                        event["session_id"] = session.session_id
                        if "target_pid" in event and event["target_pid"]:
                            session.target_pid = int(event["target_pid"])

                        yield event
                    except json.JSONDecodeError as json_err:
                        logger.warning("Malformed JSON from agent: %s (%s)", line, json_err)
                else:
                    # Non-JSON diagnostics from agent
                    logger.debug("[Agent stdout] %s", line)

            await proc.wait()
            logger.info("Agent process for session %s exited with code %s", session.session_id, proc.returncode)

        except asyncio.CancelledError:
            logger.warning("Stream cancelled for session %s. Terminating agent subprocess...", session.session_id)
            try:
                proc.terminate()
                await proc.wait()
            except Exception:
                pass
            raise
        except Exception as e:
            logger.error("Error during agent event streaming: %s", e, exc_info=True)
            yield {
                "type": "ERROR",
                "category": "system",
                "severity": "critical",
                "title": "Stream Error",
                "description": str(e),
                "details": {},
                "session_id": session.session_id,
            }
