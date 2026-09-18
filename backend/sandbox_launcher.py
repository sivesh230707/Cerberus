"""
Cerberus Sandbox Launcher
Manages Windows Sandbox (WSB) configuration generation, execution lifecycle,
and environment capability detection.
"""

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import os
import random
import shutil
import subprocess
import uuid
from typing import Optional, Dict, Any
import logging

logger = logging.getLogger("cerberus.launcher")


@dataclass
class SandboxSession:
    session_id: str
    filename: str
    filesize: int
    filepath: Path
    created_at: datetime = field(default_factory=datetime.utcnow)
    target_pid: int = field(default_factory=lambda: random.randint(4100, 8900))
    status: str = "INITIALIZING"
    memory_limit_mb: int = 256
    cpu_limit_percent: int = 50
    contained: bool = False
    fallback_host_mode: bool = False
    details: Dict[str, Any] = field(default_factory=dict)


def check_sandbox_support() -> Dict[str, Any]:
    """
    Checks whether the Windows Sandbox feature is installed and available.
    Windows Sandbox requires Windows 10/11 Pro, Enterprise, or Education
    with virtualization enabled and Containers-DisposableClientVM installed.
    """
    sandbox_exe = shutil.which("WindowsSandbox.exe")
    if not sandbox_exe:
        system_root = os.environ.get("SystemRoot", "C:\\Windows")
        default_path = Path(system_root) / "System32" / "WindowsSandbox.exe"
        if default_path.exists():
            sandbox_exe = str(default_path)

    # Check edition via registry or system info
    edition = "Unknown"
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
        edition, _ = winreg.QueryValueEx(key, "EditionID")
        winreg.CloseKey(key)
    except Exception:
        pass

    available = bool(sandbox_exe and Path(sandbox_exe).exists())
    if available:
        message = "Windows Sandbox is available and ready for isolated execution."
    else:
        message = (
            f"Windows Sandbox not found (Windows Edition: {edition}). "
            "To enable on Windows Pro/Enterprise, run in elevated PowerShell: "
            "Enable-WindowsOptionalFeature -Online -FeatureName 'Containers-DisposableClientVM'"
        )

    return {
        "available": available,
        "sandbox_exe": sandbox_exe,
        "edition": edition,
        "message": message,
    }


class SandboxLauncher:
    """
    Manages generation of Windows Sandbox (.wsb) profiles and handles
    process initialization and containment for submitted payloads.
    """

    def __init__(self, workspace_dir: Optional[Path] = None):
        self.workspace_dir = workspace_dir or Path(__file__).resolve().parent / "staging"
        self.workspace_dir.mkdir(parents=True, exist_ok=True)
        self.active_sessions: Dict[str, SandboxSession] = {}
        self.support_info = check_sandbox_support()

        # Locate compiled agent binary to stage alongside samples
        base_dir = Path(__file__).resolve().parent.parent
        self.agent_bin = base_dir / "windows-agent" / "bin" / "CerberusAgent.exe"

    def create_session(self, filename: str, content: bytes) -> SandboxSession:
        """Create a dedicated sandbox execution session and stage target file and agent."""
        session_id = str(uuid.uuid4())[:8]
        session_dir = self.workspace_dir / session_id
        session_dir.mkdir(parents=True, exist_ok=True)

        target_path = session_dir / filename
        target_path.write_bytes(content)

        # Stage agent binary into session dir so the sandbox mapped folder has it
        if self.agent_bin.exists():
            staged_agent = session_dir / "CerberusAgent.exe"
            try:
                shutil.copy2(self.agent_bin, staged_agent)
            except Exception as e:
                logger.warning("Could not stage agent binary into session dir: %s", e)

        session = SandboxSession(
            session_id=session_id,
            filename=filename,
            filesize=len(content),
            filepath=target_path,
        )

        if not self.support_info["available"]:
            session.fallback_host_mode = True
            session.details["fallback_reason"] = self.support_info["message"]

        self.active_sessions[session_id] = session
        return session

    def generate_wsb_config(self, session: SandboxSession) -> Path:
        """
        Generates Windows Sandbox configuration (.wsb XML).
        Maps the target file directory into the guest desktop with write permissions
        (for events.jsonl streaming) and specifies the agent launch logon command.
        """
        staging_dir = session.filepath.parent.resolve()
        wsb_path = staging_dir / f"cerberus_sandbox_{session.session_id}.wsb"

        wsb_xml = f"""<Configuration>
  <VGpu>Disable</VGpu>
  <Networking>Default</Networking>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>{staging_dir}</HostFolder>
      <SandboxFolder>C:\\Users\\WDAGUtilityAccount\\Desktop\\CerberusSandbox</SandboxFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>cmd.exe /c "C:\\Users\\WDAGUtilityAccount\\Desktop\\CerberusSandbox\\CerberusAgent.exe launch --file C:\\Users\\WDAGUtilityAccount\\Desktop\\CerberusSandbox\\{session.filename} --out-file C:\\Users\\WDAGUtilityAccount\\Desktop\\CerberusSandbox\\events.jsonl --mem-mb {session.memory_limit_mb}"</Command>
  </LogonCommand>
  <MemoryInMB>{session.memory_limit_mb}</MemoryInMB>
</Configuration>
"""
        wsb_path.write_text(wsb_xml, encoding="utf-8")
        session.details["wsb_config_path"] = str(wsb_path)
        return wsb_path

    def launch_sandbox(self, session: SandboxSession) -> Optional[subprocess.Popen]:
        """
        Invokes WindowsSandbox.exe with the generated .wsb profile.
        If Windows Sandbox is unavailable, sets fallback_host_mode = True.
        """
        wsb_path = session.details.get("wsb_config_path")
        if not wsb_path:
            wsb_path = str(self.generate_wsb_config(session))

        sandbox_exe = self.support_info.get("sandbox_exe")
        if self.support_info["available"] and sandbox_exe:
            logger.info("Launching Windows Sandbox for session %s with config %s", session.session_id, wsb_path)
            try:
                proc = subprocess.Popen([sandbox_exe, wsb_path])
                session.details["sandbox_pid"] = proc.pid
                session.details["sandbox_proc"] = proc
                return proc
            except Exception as e:
                logger.error("Failed to launch WindowsSandbox.exe: %s. Falling back to host mode.", e)
                session.fallback_host_mode = True
                session.details["fallback_reason"] = str(e)
                return None
        else:
            logger.warning("Windows Sandbox unavailable. Session %s will run in Host Job-Object mode.", session.session_id)
            session.fallback_host_mode = True
            return None

    def get_session(self, session_id: str) -> Optional[SandboxSession]:
        return self.active_sessions.get(session_id)

    def freeze_session(self, session_id: str) -> bool:
        """Mark a session as frozen/contained."""
        session = self.get_session(session_id)
        if session:
            session.contained = True
            session.status = "FROZEN"
            return True
        return False
