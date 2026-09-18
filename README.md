# Cerberus — Windows-Native Behavioral Sandbox Web App

**Cerberus** is a host-monitored behavioral sandbox web application designed for Windows. Users drag and drop suspicious files or scripts into the web interface; Cerberus deploys them inside an isolated, disposable Windows Sandbox instance while real-time Event Tracing for Windows (ETW) monitors behavior. If suspicious activity occurs, Cerberus immediately freezes the process execution and severs its network access, visualizing the entire sequence live in the browser.

---

## 🏛️ Architecture Overview (v1 Scope)

```
                       ┌───────────────────────────────┐
                       │     Cerberus Web Cockpit      │
                       │  (Vanilla JS / Dark UI / WS)  │
                       └──────────────┬────────────────┘
                                      │ WebSocket / HTTP
                                      ▼
                       ┌───────────────────────────────┐
                       │        FastAPI Backend        │
                       │   (Uploads / Session Bridge)   │
                       └──────┬─────────────────┬──────┘
                              │                 │
            ┌─────────────────┴─┐             ┌─┴────────────────┐
            ▼                   ▼             ▼                  ▼
   ┌─────────────────┐ ┌───────────────┐ ┌──────────────┐ ┌──────────────┐
   │ Windows Sandbox │ │  Job Objects  │ │ ETW Listener │ │ WFP Filter   │
   │  (.wsb Config)  │ │ (Memory/CPU)  │ │ (Kernel IO)  │ │ (Net Sever)  │
   └─────────────────┘ └───────────────┘ └──────────────┘ └──────────────┘
```

1. **Isolation Layer**:
   - **Windows Sandbox (WSB)**: Ephemeral disposable micro-VM sandbox config generation (`.wsb`).
   - **Job Objects**: Hard memory cap (256 MB), CPU rate limit, and child process bounds (`JobObjectWrapper.cs`).
2. **Monitoring Layer**:
   - **ETW (Event Tracing for Windows)**: Kernel-level process, filesystem, and TCP/IP connection tracing (`EtwListener.cs`).
   - **3 Fixed MVP Detection Rules**:
     1. Outbound network connection attempt (e.g. C2 beaconing).
     2. Protected credential store access (e.g. `C:\Windows\System32\config\SAM`).
     3. Unexpected secondary child process spawns (e.g. `cmd.exe /c whoami`).
3. **Response Layer**:
   - **Thread Suspension**: Immediate invocation of `SuspendThread()` across all process threads (`ResponseAgent.cs`).
   - **Network Severing**: Dynamic Windows Filtering Platform (WFP) filter injection dropping all outbound packets for the target PID (`ResponseAgent.cs`).
4. **Presentation Layer**:
   - Single-screen cybersecurity command center with drag-and-drop ingestion, live WebSocket telemetry terminal, and animated state banner (`Analyzing` / `Clean` / `Frozen — Violation Detected`).

---

## 🚀 Quick Start & Running Locally

### 1. Requirements
- Windows 10/11 (x64)
- Python 3.10+ (Python 3.11 tested)

### 2. Launch the Application

From PowerShell:

```powershell
cd "C:\Users\sives\.gemini\antigravity-ide\scratch\cerberus"

# Activate the virtual environment
.\.venv\Scripts\Activate.ps1

# Start the Cerberus Backend & Web UI
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

Then open your browser to **`http://127.0.0.1:8000`**.

---

## 🧪 Testing the End-to-End Workflow

The web interface comes with built-in instant demonstration buttons as well as sample payloads in `/samples`:

1. **Test Malicious Script Demo (or drag `samples/test_malicious_sample.ps1`)**:
   - Status changes to **ANALYZING**.
   - Live ETW logs stream: Process start -> Job Object limit check -> Sensitive path access flagged (`SAM`) -> Child process flagged (`cmd.exe`) -> Outbound network beacon flagged (`198.51.100.42:443`).
   - Containment triggers: `SuspendThread` freezes execution, dynamic WFP filter severs network.
   - Final Verdict flips to glowing crimson: **FROZEN — VIOLATION DETECTED**.

2. **Test Clean Script Demo (or drag `samples/test_clean_sample.bat`)**:
   - Status changes to **ANALYZING**.
   - Live ETW logs stream normal calculations and clean process termination.
   - Final Verdict flips to emerald green: **CLEAN**.

---

## 📁 Repository Structure

```
cerberus/
├── backend/
│   ├── .venv/                   # Python virtual environment
│   ├── requirements.txt         # Pinned dependencies
│   ├── main.py                  # FastAPI REST + WebSocket telemetry router
│   ├── sandbox_launcher.py      # WSB XML generator & session tracker
│   └── monitor_bridge.py        # ETW event relay & simulation dispatcher
├── windows-agent/
│   ├── EtwListener.cs           # ETW Kernel session listener & rule evaluator
│   ├── ResponseAgent.cs         # SuspendThread & WFP packet filter injection
│   └── JobObjectWrapper.cs      # Win32 Job Object resource bounds
├── frontend/
│   ├── index.html               # Single-page Cerberus Command Console
│   ├── style.css                # Dark cybersecurity cockpit styling
│   └── app.js                   # WebSocket streaming client & containment state UI
└── samples/
    ├── test_clean_sample.bat    # Benign test batch file
    └── test_malicious_sample.ps1# Suspicious test PowerShell script
```
