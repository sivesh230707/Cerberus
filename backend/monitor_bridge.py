"""
Cerberus Monitor Bridge
Interfaces with host-level ETW listener and relays real-time event telemetry
over WebSocket to the frontend cockpit. Supports simulation mode for end-to-end testing.
"""

import asyncio
from datetime import datetime
from typing import AsyncGenerator, Dict, Any, List
from .sandbox_launcher import SandboxSession


class MonitorBridge:
    """
    Relays telemetry events from the ETW monitor to connected clients.
    Implements simulated telemetry streams matching Cerberus's 3 v1 behavioral rules:
      1. Flag: any outbound network connection attempt
      2. Flag: any read of a sensitive path (e.g. SAM / credential store)
      3. Flag: any unexpected child process spawn
    Followed by response actions:
      - SuspendThread on target process
      - Dynamic WFP filter outbound network block
    """

    @staticmethod
    def _now() -> str:
        return datetime.now().strftime("%H:%M:%S.%f")[:-3]

    async def stream_events(self, session: SandboxSession) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Asynchronously yields structured telemetry events for a given sandbox session.
        Determines benign vs malicious behavior based on file name or simulation profile.
        """
        is_clean = "clean" in session.filename.lower()
        pid = session.target_pid

        if is_clean:
            events = self._generate_clean_sequence(session, pid)
        else:
            events = self._generate_malicious_sequence(session, pid)

        for event in events:
            delay = event.pop("_delay", 0.7)
            await asyncio.sleep(delay)
            event["timestamp"] = self._now()
            event["session_id"] = session.session_id
            yield event

    def _generate_clean_sequence(self, session: SandboxSession, pid: int) -> List[Dict[str, Any]]:
        return [
            {
                "_delay": 0.4,
                "type": "SESSION_INIT",
                "category": "system",
                "severity": "info",
                "title": "Sandbox Initialized",
                "description": f"Allocated ephemeral Windows Sandbox instance for '{session.filename}'.",
                "details": {"session_id": session.session_id, "filesize": session.filesize},
            },
            {
                "_delay": 0.6,
                "type": "JOB_OBJECT_ATTACH",
                "category": "isolation",
                "severity": "info",
                "title": "Job Object Assigned",
                "description": f"Applied resource limits: Memory capped at {session.memory_limit_mb}MB, CPU rate limited.",
                "details": {"pid": pid, "job_name": f"CerberusJob_{session.session_id}"},
            },
            {
                "_delay": 0.8,
                "type": "PROCESS_START",
                "category": "process",
                "severity": "info",
                "title": "Target Process Started",
                "description": f"Spawned target execution with PID {pid}.",
                "details": {"pid": pid, "image": session.filename, "parent_pid": 1120},
            },
            {
                "_delay": 0.9,
                "type": "FILE_READ_BENIGN",
                "category": "filesystem",
                "severity": "info",
                "title": "Legitimate File Access",
                "description": r"Read benign runtime dependency C:\Windows\System32\kernel32.dll",
                "details": {"path": r"C:\Windows\System32\kernel32.dll", "bytes": 1048576},
            },
            {
                "_delay": 1.0,
                "type": "COMPUTATION_ACTIVE",
                "category": "process",
                "severity": "info",
                "title": "Normal Execution",
                "description": "Target performed arithmetic operations and wrote to local sandboxed stdout.",
                "details": {"cycles": 1420000, "threads": 2},
            },
            {
                "_delay": 0.8,
                "type": "PROCESS_EXIT",
                "category": "process",
                "severity": "info",
                "title": "Process Terminated Normally",
                "description": f"Process {pid} exited gracefully with ExitCode 0.",
                "details": {"pid": pid, "exit_code": 0},
            },
            {
                "_delay": 0.5,
                "type": "VERDICT",
                "category": "verdict",
                "severity": "clean",
                "verdict_state": "CLEAN",
                "title": "Analysis Complete: Clean",
                "description": "No security policy violations observed during sandbox execution.",
                "violations": [],
            },
        ]

    def _generate_malicious_sequence(self, session: SandboxSession, pid: int) -> List[Dict[str, Any]]:
        child_pid = pid + 14
        return [
            {
                "_delay": 0.4,
                "type": "SESSION_INIT",
                "category": "system",
                "severity": "info",
                "title": "Sandbox Initialized",
                "description": f"Allocated ephemeral Windows Sandbox instance for '{session.filename}'.",
                "details": {"session_id": session.session_id, "filesize": session.filesize},
            },
            {
                "_delay": 0.6,
                "type": "JOB_OBJECT_ATTACH",
                "category": "isolation",
                "severity": "info",
                "title": "Job Object Assigned",
                "description": f"Applied resource limits: Memory limit {session.memory_limit_mb}MB, Single-core affinity.",
                "details": {"pid": pid, "job_name": f"CerberusJob_{session.session_id}"},
            },
            {
                "_delay": 0.8,
                "type": "PROCESS_START",
                "category": "process",
                "severity": "info",
                "title": "Target Process Started",
                "description": f"Target launched under ETW monitoring hook (PID: {pid}).",
                "details": {"pid": pid, "image": session.filename},
            },
            {
                "_delay": 1.0,
                "type": "FILE_ACCESS_VIOLATION",
                "category": "filesystem",
                "severity": "violation",
                "rule_id": "RULE_SENSITIVE_PATH",
                "title": "Rule Violation: Sensitive Path Access",
                "description": r"Target attempted to read Windows Credential Store / SAM registry hive at C:\Windows\System32\config\SAM",
                "details": {
                    "path": r"C:\Windows\System32\config\SAM",
                    "desired_access": "GENERIC_READ",
                    "pid": pid,
                },
            },
            {
                "_delay": 0.9,
                "type": "CHILD_PROCESS_VIOLATION",
                "category": "process",
                "severity": "violation",
                "rule_id": "RULE_UNEXPECTED_CHILD",
                "title": "Rule Violation: Unexpected Child Process",
                "description": f"Target spawned unauthorized secondary process 'cmd.exe /c whoami /priv' (Child PID: {child_pid})",
                "details": {
                    "parent_pid": pid,
                    "child_pid": child_pid,
                    "command_line": "cmd.exe /c whoami /priv",
                },
            },
            {
                "_delay": 1.1,
                "type": "NETWORK_VIOLATION",
                "category": "network",
                "severity": "violation",
                "rule_id": "RULE_OUTBOUND_NETWORK",
                "title": "Rule Violation: Outbound Network Connection",
                "description": "Target attempted outbound TCP socket connection to external IP 198.51.100.42:443 (C2 beacon attempt)",
                "details": {
                    "pid": pid,
                    "destination_ip": "198.51.100.42",
                    "destination_port": 443,
                    "protocol": "TCP",
                },
            },
            {
                "_delay": 0.5,
                "type": "CONTAINMENT_TRIGGERED",
                "category": "containment",
                "severity": "critical",
                "title": "Containment Protocol Activated",
                "description": "Suspicious behavior detected! Initiating immediate host isolation response.",
                "details": {"violations_count": 3, "target_pid": pid},
            },
            {
                "_delay": 0.4,
                "type": "ACTION_SUSPEND_THREAD",
                "category": "containment",
                "severity": "critical",
                "title": "Threads Suspended (Freeze)",
                "description": f"Invoked SuspendThread() on all 5 active threads of PID {pid} and Child PID {child_pid}. Process execution frozen.",
                "details": {
                    "target_pid": pid,
                    "child_pid": child_pid,
                    "action": "SuspendThread",
                    "status": "FROZEN",
                },
            },
            {
                "_delay": 0.4,
                "type": "ACTION_WFP_SEVER",
                "category": "containment",
                "severity": "critical",
                "title": "Network Severed (WFP Block)",
                "description": f"Injected dynamic Windows Filtering Platform (WFP) packet filter scoped to PID {pid}. All outbound traffic dropped.",
                "details": {
                    "target_pid": pid,
                    "action": "FWPM_FILTER_ADD",
                    "filter_condition": f"PID == {pid}",
                    "direction": "OUTBOUND_DENY",
                },
            },
            {
                "_delay": 0.6,
                "type": "VERDICT",
                "category": "verdict",
                "severity": "violation",
                "verdict_state": "FROZEN",
                "title": "Verdict: Frozen — Violation Detected",
                "description": "Sandbox frozen and network severed. 3 security policy violations were confirmed.",
                "violations": [
                    "Sensitive path access (C:\\Windows\\System32\\config\\SAM)",
                    "Unexpected child process spawn (cmd.exe)",
                    "Unauthorized outbound TCP connection (198.51.100.42:443)",
                ],
            },
        ]
