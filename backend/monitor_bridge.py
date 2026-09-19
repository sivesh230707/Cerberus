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

    @staticmethod
    def check_file_integrity(filepath: Path) -> Optional[str]:
        """
        Inspects file before execution to detect syntax errors, empty files, or corrupted headers.
        Returns a string describing the issue if corrupted, otherwise None.
        """
        try:
            if not filepath.exists():
                return "File does not exist"
            
            size = filepath.stat().st_size
            if size == 0:
                return "Zero-byte file (empty payload)"

            suffix = filepath.suffix.lower()

            # 1. Python Syntax / AST check
            if suffix == ".py":
                try:
                    content = filepath.read_text(encoding="utf-8", errors="replace")
                    import ast
                    ast.parse(content, filename=filepath.name)
                except SyntaxError as syn_err:
                    return f"Python SyntaxError: {syn_err.msg} (line {syn_err.lineno})"
                except Exception as e:
                    return f"Python parse error: {e}"

            # 2. Windows Executable / PE header check
            elif suffix in [".exe", ".dll", ".sys"]:
                try:
                    with open(filepath, "rb") as f:
                        magic = f.read(2)
                        if magic != b"MZ":
                            return f"Corrupted PE Header: missing 'MZ' signature (found {magic!r})"
                except Exception as e:
                    return f"Binary read error: {e}"

            # 3. JSON file check
            elif suffix == ".json":
                try:
                    json.loads(filepath.read_text(encoding="utf-8", errors="replace"))
                except Exception as e:
                    return f"Invalid JSON syntax: {e}"

        except Exception as e:
            return f"Integrity check failed: {e}"

        return None

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
            yield {
                "timestamp": session.created_at.strftime("%H:%M:%S.%f")[:-3],
                "type": "VERDICT",
                "category": "verdict",
                "severity": "violation",
                "verdict_state": "ERROR",
                "title": "Analysis Aborted: Agent Binary Missing",
                "description": "CerberusAgent.exe could not be found.",
                "target_pid": 0,
                "violations": ["Agent Binary Missing"],
            }
            return

        staging_dir = session.filepath.parent.resolve()
        events_jsonl = staging_dir / "events.jsonl"

        integrity_issue = self.check_file_integrity(session.filepath)
        if integrity_issue:
            logger.warning("Integrity check warning for %s: %s", session.filepath.name, integrity_issue)
            yield {
                "timestamp": session.created_at.strftime("%H:%M:%S.%f")[:-3],
                "type": "FILE_INTEGRITY_WARNING",
                "category": "integrity",
                "severity": "warning",
                "title": "File Integrity / Syntax Anomaly Detected",
                "description": f"Pre-execution analysis identified corruption or syntax errors: {integrity_issue}",
                "details": {"issue": integrity_issue, "filename": session.filepath.name},
                "session_id": session.session_id,
            }

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
            async for evt in self._tail_events_file(events_jsonl, session, integrity_issue=integrity_issue):
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
            # WinError 740: Elevation Required, WinError 4551: Application Control / SmartScreen
            win_err = getattr(e, "winerror", None)
            if win_err in (740, 4551) or "elevation" in str(e).lower() or "application control" in str(e).lower() or "blocked" in str(e).lower():
                logger.info("Elevation or execution approval required (winerror %s). Spawning CerberusAgent via PowerShell RunAs...", win_err)
                ps_cmd = [
                    "powershell.exe",
                    "-Command",
                    f"Unblock-File -Path '{self.agent_exe}'; Start-Process -FilePath '{self.agent_exe}' -ArgumentList 'launch --file \"{session.filepath.resolve()}\" --mem-mb {session.memory_limit_mb} --out-file \"{events_jsonl}\"' -Verb RunAs -Wait"
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
                        yield {
                            "type": "VERDICT",
                            "category": "verdict",
                            "severity": "violation",
                            "verdict_state": "ERROR",
                            "title": "Analysis Aborted: Elevation Required",
                            "description": "Administrator elevation required to launch agent.",
                            "target_pid": 0,
                            "violations": [f"Elevation Error: {err_msg}"],
                        }
                        return
                except Exception as runas_err:
                    logger.warning("PowerShell RunAs spawn error: %s", runas_err)

                async for evt in self._tail_events_file(events_jsonl, session, integrity_issue=integrity_issue):
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
                yield {
                    "type": "VERDICT",
                    "category": "verdict",
                    "severity": "violation",
                    "verdict_state": "ERROR",
                    "title": "Analysis Aborted: Process Spawn Error",
                    "description": str(e),
                    "target_pid": 0,
                    "violations": [f"Spawn Error: {e}"],
                }
                return

        # Direct stdout streaming
        received_verdict = False
        target_exit_code = 0
        stderr_lines = []
        has_violation = False

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

                        evt_type = event.get("type", "")
                        if evt_type in ["FILE_ACCESS_VIOLATION", "CHILD_PROCESS_VIOLATION", "NETWORK_VIOLATION", "CONTAINMENT_TRIGGERED", "ACTION_SUSPEND_THREAD", "ACTION_WFP_SEVER"]:
                            has_violation = True

                        if evt_type == "TARGET_STDERR":
                            event["severity"] = "warning"
                            stderr_msg = event.get("description") or event.get("details", {}).get("stderr", "")
                            if stderr_msg:
                                stderr_lines.append(stderr_msg)

                        if evt_type == "PROCESS_EXIT":
                            code_val = event.get("details", {}).get("exit_code", "0")
                            try:
                                target_exit_code = int(code_val)
                            except (ValueError, TypeError):
                                target_exit_code = 0
                            if target_exit_code != 0:
                                event["severity"] = "warning"
                                event["title"] = "Process Terminated Abnormally"

                        if evt_type == "VERDICT":
                            received_verdict = True
                            if not has_violation and event.get("verdict_state") != "FROZEN":
                                is_corrupted = False
                                reasons = []
                                if integrity_issue:
                                    is_corrupted = True
                                    reasons.append(integrity_issue)
                                if target_exit_code != 0:
                                    is_corrupted = True
                                    reasons.append(f"Abnormal Exit Code: {target_exit_code}")
                                if stderr_lines:
                                    for err in stderr_lines:
                                        lower = err.lower()
                                        if any(k in lower for k in ["syntaxerror", "nameerror", "typeerror", "traceback", "fatal", "corrupt", "is not recognized", "cannot find"]):
                                            is_corrupted = True
                                            reasons.append(f"Stderr: {err.strip()}")
                                            break

                                if is_corrupted:
                                    event["verdict_state"] = "CORRUPTED"
                                    event["severity"] = "warning"
                                    event["title"] = "Analysis Complete: Execution Failed / File Corrupted"
                                    event["description"] = f"File execution failed or corrupted: {reasons[0]}"
                                    event["violations"] = reasons

                        yield event
                    except json.JSONDecodeError as json_err:
                        logger.warning("Malformed JSON from agent: %s (%s)", line, json_err)
                else:
                    logger.debug("[Agent stdout] %s", line)

            await proc.wait()
            logger.info("Agent process for session %s exited with code %s", session.session_id, proc.returncode)

            if not received_verdict:
                yield {
                    "timestamp": session.created_at.strftime("%H:%M:%S.%f")[:-3],
                    "type": "VERDICT",
                    "category": "verdict",
                    "severity": "warning" if (integrity_issue or target_exit_code != 0) else "violation",
                    "verdict_state": "CORRUPTED" if (integrity_issue or target_exit_code != 0) else "ERROR",
                    "title": "Analysis Complete: Corrupted File" if (integrity_issue or target_exit_code != 0) else "Analysis Aborted: Execution Failed",
                    "description": f"File could not execute or terminated abnormally with code {proc.returncode}." if not integrity_issue else f"File has syntax/format corruption: {integrity_issue}.",
                    "target_pid": session.target_pid,
                    "violations": [integrity_issue] if integrity_issue else [f"Process exit code {proc.returncode}"],
                }

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

    async def _tail_events_file(
        self,
        events_path: Path,
        session: SandboxSession,
        integrity_issue: Optional[str] = None,
        timeout: float = 30.0
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """Tails the shared events.jsonl file, yielding parsed events until VERDICT is emitted."""
        loop = asyncio.get_event_loop()
        start_time = loop.time()
        target_exit_code = 0
        stderr_lines = []
        has_violation = False

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

                            evt_type = event.get("type", "")
                            if evt_type in ["FILE_ACCESS_VIOLATION", "CHILD_PROCESS_VIOLATION", "NETWORK_VIOLATION", "CONTAINMENT_TRIGGERED", "ACTION_SUSPEND_THREAD", "ACTION_WFP_SEVER"]:
                                has_violation = True

                            if evt_type == "TARGET_STDERR":
                                event["severity"] = "warning"
                                stderr_msg = event.get("description") or event.get("details", {}).get("stderr", "")
                                if stderr_msg:
                                    stderr_lines.append(stderr_msg)

                            if evt_type == "PROCESS_EXIT":
                                code_val = event.get("details", {}).get("exit_code", "0")
                                try:
                                    target_exit_code = int(code_val)
                                except (ValueError, TypeError):
                                    target_exit_code = 0
                                if target_exit_code != 0:
                                    event["severity"] = "warning"
                                    event["title"] = "Process Terminated Abnormally"
                            
                            if evt_type == "VERDICT":
                                if not has_violation and event.get("verdict_state") != "FROZEN":
                                    is_corrupted = False
                                    reasons = []
                                    if integrity_issue:
                                        is_corrupted = True
                                        reasons.append(integrity_issue)
                                    if target_exit_code != 0:
                                        is_corrupted = True
                                        reasons.append(f"Abnormal Exit Code: {target_exit_code}")
                                    if stderr_lines:
                                        for err in stderr_lines:
                                            lower = err.lower()
                                            if any(k in lower for k in ["syntaxerror", "nameerror", "typeerror", "traceback", "fatal", "corrupt", "is not recognized", "cannot find"]):
                                                is_corrupted = True
                                                reasons.append(f"Stderr: {err.strip()}")
                                                break

                                    if is_corrupted:
                                        event["verdict_state"] = "CORRUPTED"
                                        event["severity"] = "warning"
                                        event["title"] = "Analysis Complete: Execution Failed / File Corrupted"
                                        event["description"] = f"File execution failed or corrupted: {reasons[0]}"
                                        event["violations"] = reasons
                                yield event
                                break
                            yield event
                        except json.JSONDecodeError:
                            pass
                else:
                    if loop.time() - last_activity > timeout:
                        logger.warning("Events file idle for %s seconds. Concluding stream.", timeout)
                        break
                    await asyncio.sleep(0.1)
