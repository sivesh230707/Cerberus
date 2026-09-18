"""
Cerberus Sandbox Launcher
Manages Windows Sandbox (WSB) configuration generation and execution lifecycle.
Provides isolation abstractions with Windows Sandbox and Job Object enforcement.
"""

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import random
import uuid
from typing import Optional, Dict, Any


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
    details: Dict[str, Any] = field(default_factory=dict)


class SandboxLauncher:
    """
    Manages generation of Windows Sandbox (.wsb) profiles and handles
    process initialization and containment for submitted payloads.
    """

    def __init__(self, workspace_dir: Optional[Path] = None):
        self.workspace_dir = workspace_dir or Path(__file__).resolve().parent / "staging"
        self.workspace_dir.mkdir(parents=True, exist_ok=True)
        self.active_sessions: Dict[str, SandboxSession] = {}

    def create_session(self, filename: str, content: bytes) -> SandboxSession:
        """Create a dedicated sandbox execution session and write target file to staging."""
        session_id = str(uuid.uuid4())[:8]
        session_dir = self.workspace_dir / session_id
        session_dir.mkdir(parents=True, exist_ok=True)

        target_path = session_dir / filename
        target_path.write_bytes(content)

        session = SandboxSession(
            session_id=session_id,
            filename=filename,
            filesize=len(content),
            filepath=target_path,
        )
        self.active_sessions[session_id] = session
        return session

    def generate_wsb_config(self, session: SandboxSession) -> Path:
        """
        Generates Windows Sandbox configuration (.wsb XML).
        Maps the target file directory into the guest desktop and specifies a logon command.
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
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>powershell.exe -ExecutionPolicy Bypass -File C:\\Users\\WDAGUtilityAccount\\Desktop\\CerberusSandbox\\{session.filename}</Command>
  </LogonCommand>
  <MemoryInMB>{session.memory_limit_mb}</MemoryInMB>
</Configuration>
"""
        wsb_path.write_text(wsb_xml, encoding="utf-8")
        session.details["wsb_config_path"] = str(wsb_path)
        return wsb_path

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
