"""
Automated End-to-End Test for Cerberus
Uploads samples, connects to the WebSocket stream, verifies telemetry events and final verdicts.
"""

import asyncio
import json
from pathlib import Path
import websockets
import urllib.request
import mimetypes

BASE_URL = "http://127.0.0.1:8000"


def upload_file(filename: str, content: bytes) -> dict:
    boundary = "----CerberusBoundaryTest"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        f"Content-Type: text/plain\r\n\r\n"
    ).encode("utf-8") + content + f"\r\n--{boundary}--\r\n".encode("utf-8")

    req = urllib.request.Request(
        f"{BASE_URL}/api/upload",
        data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))


async def test_session(filename: str, content: bytes, expected_verdict: str):
    print(f"\n[+] Testing upload for: {filename}...")
    session_data = upload_file(filename, content)
    session_id = session_data["session_id"]
    print(f"    Session ID: {session_id}, Assigned PID: {session_data['target_pid']}")

    ws_url = f"ws://127.0.0.1:8000/ws/analysis/{session_id}"
    print(f"    Connecting to WebSocket: {ws_url}...")

    received_events = []
    final_verdict = None

    async with websockets.connect(ws_url) as ws:
        while True:
            try:
                msg = await ws.recv()
                evt = json.loads(msg)
                received_events.append(evt)
                evt_type = evt.get("type")
                sev = evt.get("severity")
                title = evt.get("title")
                print(f"    -> [{evt.get('timestamp')}] {evt_type} ({sev}): {title}")

                if evt_type == "VERDICT":
                    final_verdict = evt.get("verdict_state")
                    break
            except websockets.exceptions.ConnectionClosed:
                break

    print(f"    Total Events Received: {len(received_events)}")
    print(f"    Final Verdict: {final_verdict} (Expected: {expected_verdict})")
    assert final_verdict == expected_verdict, f"Expected {expected_verdict}, got {final_verdict}"
    print(f"[SUCCESS] {filename} verified successfully with verdict {final_verdict}!")
    return received_events


async def main():
    # 1. Test Malicious / Suspicious Payload
    sample_mal = Path(__file__).resolve().parent.parent / "samples" / "test_malicious_sample.ps1"
    if sample_mal.exists():
        malicious_bytes = sample_mal.read_bytes()
    else:
        malicious_bytes = b"Probe-CredentialHive\r\nStart-Process cmd.exe\r\nConnect-Outbound\r\n"

    events_mal = await test_session("malicious_test.ps1", malicious_bytes, "FROZEN")

    # Verify key violations and containment actions
    types = [e["type"] for e in events_mal]
    has_violation = any(v in types for v in ["FILE_ACCESS_VIOLATION", "CHILD_PROCESS_VIOLATION", "NETWORK_VIOLATION"])
    assert has_violation, "Missing expected policy violation event in live agent output"
    assert "ACTION_SUSPEND_THREAD" in types, "Missing SuspendThread containment"
    assert "ACTION_WFP_SEVER" in types, "Missing WFP network cut action"
    print("[+] Policy violation and live containment response confirmed from real C# agent!")

    # 2. Test Clean / Benign Payload
    sample_clean = Path(__file__).resolve().parent.parent / "samples" / "test_clean_sample.bat"
    if sample_clean.exists():
        clean_bytes = sample_clean.read_bytes()
    else:
        clean_bytes = b"@echo off\r\nset /a res=40+2\r\necho %res%\r\n"

    events_clean = await test_session("clean_test.bat", clean_bytes, "CLEAN")
    types_clean = [e["type"] for e in events_clean]
    assert "VERDICT" in types_clean
    assert "FILE_ACCESS_VIOLATION" not in types_clean
    assert "ACTION_SUSPEND_THREAD" not in types_clean
    print("[+] Clean payload verified with 0 violations!")

    print("\n=======================================================")
    print("ALL END-TO-END TELEMETRY & VERDICT TESTS PASSED!")
    print("=======================================================")


if __name__ == "__main__":
    asyncio.run(main())
