"""
Cerberus Monitor Bridge (Live Subprocess & Sandbox File IPC)
Streams real-time Win32 / ETW telemetry events and containment actions
from either Windows Sandbox (via shared events.jsonl) or Host execution (via stdout / events.jsonl).
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
    Interfaces with the compiled C# Windows Agent (CerberusAgent.exe).
    Supports dual-channel ingestion:
    1. Windows Sandbox isolation mode: Reads live events appended to events.jsonl in mapped staging directory.
    2. Host mode (Job Object): Reads directly from subprocess stdout with automatic UAC RunAs fallback.
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
        Streams events for the given session.
        If running inside Windows Sandbox, streams from events.jsonl in the staging folder.
        If running in Host fallback mode, launches the agent on host and streams stdout / events.jsonl.
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

        staging_dir = session.filepath.parent.resolve()
        events_jsonl = staging_dir / "events.jsonl"

        # If sandbox mode is active, tail events.jsonl
        if not session.fallback_host_mode:
            logger.info("Session %s running in Windows Sandbox mode. Monitoring events file: %s", session.session_id, events_jsonl)
            yield {
                "timestamp": session.created_at.strftime("%H:%M:%S.%f")[:-3],
                "type": "SANDBOX_ATTACH",
                "category": "isolation",
                "severity": "info",
                "title": "Windows Sandbox Isolation Active",
                "description": "Target payload executing inside disposable Windows Sandbox VM container.",
                "details": {"wsb_config": session.details.get("wsb_config_path", "")},
                "session_id": session.session_id,
            }
            async for evt in self._tail_events_file(events_jsonl, session):
                yield evt
            return

        # Host Fallback Mode
        logger.info("Session %s running in Host Job-Object mode.", session.session_id)
        yield {
            "timestamp": session.created_at.strftime("%H:%M:%S.%f")[:-3],
            "type": "SANDBOX_MODE_NOTICE",
            "category": "isolation",
            "severity": "info",
            "title": "Host Job-Object Mode Active",
            "description": "Windows Sandbox is unavailable on this system edition. Executing with Win32 Job Object containment on host.",
            "details": {"reason": session.details.get("fallback_reason", "")},
            "session_id": session.session_id,
        }

        cmd = [
            str(self.agent_exe),
            "launch",
            "--file", str(session.filepath.resolve()),
            "--mem-mb", str(session.memory_limit_mb),
            "--out-file", str(events_jsonl),
        ]

        logger.info("Spawning native agent for session %s: %s", session.session_id, " ".join(cmd))

        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
        except OSError as e:
            # WinError 740: Elevation Required
            if getattr(e, "winerror", None) == 740 or "elevation" in str(e).lower():
                logger.info("Elevation required. Spawning elevated CerberusAgent via PowerShell RunAs...")
                ps_cmd = [
                    "powershell.exe",
                    "-Command",
                    f"Start-Process -FilePath '{self.agent_exe}' -ArgumentList 'launch --file \"{session.filepath.resolve()}\" --mem-mb {session.memory_limit_mb} --out-file \"{events_jsonl}\"' -Verb RunAs -Wait"
                ]
                try:
                    ps_proc = await asyncio.create_subprocess_exec(
                        *ps_cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    # Give RunAs a moment to trigger prompt or fail if non-interactive
                    await asyncio.sleep(0.5)
                    if ps_proc.returncode is not None and ps_proc.returncode != 0:
                        stderr_bytes = await ps_proc.stderr.read()
                        err_msg = stderr_bytes.decode("utf-8", errors="replace").strip()
                        yield {
                            "type": "ERROR",
                            "category": "system",
                            "severity": "critical",
                            "title": "UAC Elevation Required",
                            "description": (
                                "CerberusAgent.exe requires Administrator elevation (requireAdministrator). "
                                f"UAC prompt could not be displayed: {err_msg}. "
                                "Please launch the backend or terminal as Administrator."
                            ),
                            "details": {"agent_path": str(self.agent_exe), "error": err_msg},
                            "session_id": session.session_id,
                        }
                        return
                except Exception as runas_err:
                    logger.warning("PowerShell RunAs spawn error: %s", runas_err)

                async for evt in self._tail_events_file(events_jsonl, session):
                    yield evt
                return
            else:
                logger.error("Failed to start agent process: %s", e)
                yield {
                    "type": "ERROR",
                    "category": "system",
                    "severity": "critical",
                    "title": "Process Spawn Error",
                    "description": str(e),
                    "details": {},
                    "session_id": session.session_id,
                }
                return

        # Direct stdout streaming
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
                    logger.debug("[Agent stdout] %s", line)

            await proc.wait()
            logger.info("Agent process for session %s exited with code %s", session.session_id, proc.returncode)

        except asyncio.CancelledError:
            logger.warning("Stream cancelled for session %s. Terminating agent subprocess...", session.session_id)
            if proc:
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

    async def _run_process_async(self, cmd: list) -> None:
        try:
            proc = await asyncio.create_subprocess_exec(*cmd)
            await proc.wait()
        except Exception as e:
            logger.warning("Background elevated process error: %s", e)

    async def _tail_events_file(self, events_path: Path, session: SandboxSession, timeout: float = 60.0) -> AsyncGenerator[Dict[str, Any], None]:
        """Tails events.jsonl asynchronously as the agent writes to it."""
        loop = asyncio.get_event_loop()
        start_time = loop.time()

        # Wait up to 20 seconds for the file to be created
        while not events_path.exists():
            if loop.time() - start_time > 20.0:
                logger.warning("Timed out waiting for events.jsonl at %s", events_path)
                yield {
                    "type": "ERROR",
                    "category": "system",
                    "severity": "critical",
                    "title": "Timeout",
                    "description": "Timed out waiting for agent telemetry file to initialize.",
                    "details": {"path": str(events_path)},
                    "session_id": session.session_id,
                }
                return
            await asyncio.sleep(0.2)

        with open(events_path, "r", encoding="utf-8", errors="replace") as f:
            last_activity = loop.time()
            while True:
                line = f.readline()
                if line:
                    last_activity = loop.time()
                    line = line.strip()
                    if line.startswith("{") and line.endswith("}"):
                        try:
                            event = json.loads(line)
                            event["session_id"] = session.session_id
                            if "target_pid" in event and event["target_pid"]:
                                session.target_pid = int(event["target_pid"])
                            yield event
                            if event.get("type") == "VERDICT":
                                break
                        except json.JSONDecodeError:
                            pass
                else:
                    if loop.time() - last_activity > timeout:
                        logger.warning("Events file idle for %s seconds. Concluding stream.", timeout)
                        break
                    await asyncio.sleep(0.1)
