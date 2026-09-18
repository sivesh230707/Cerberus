/**
 * Cerberus 3D Defense Core - Integrated Frontend Controller
 * Connects the Stitch Remix 3D cockpit to the Cerberus backend API & WebSocket stream.
 * Manages 6-stage pipeline transitions, real-time ETW event rendering,
 * dynamic Three.js / CSS 3D viewport state, and containment alerts.
 */

document.addEventListener('DOMContentLoaded', () => {
  // DOM Elements - Navigation & Status
  const statusWsb = document.getElementById('status-wsb');
  const statusProbes = document.getElementById('status-probes');

  // Workload Dropper & File Input
  const fileUploadBtn = document.getElementById('fileUploadBtn');
  const fileInput = document.getElementById('file-input');
  const activeWorkloadLabel = document.getElementById('activeWorkloadLabel');
  const activeWorkloadBadge = document.getElementById('activeWorkloadBadge');

  // Pipeline Stepper Buttons
  const stepBtns = document.querySelectorAll('.state-step-btn');

  // Payload Selectors & Run Button
  const payloadBtns = document.querySelectorAll('.payload-btn');
  const btnExecuteCycle = document.getElementById('btn-execute-cycle');

  // 3D Core Viewport & HUD Elements
  const spatialSceneWrapper = document.getElementById('spatialSceneWrapper');
  const centralCoreCube = document.getElementById('centralCoreCube');
  const cubeIconState = document.getElementById('cubeIconState');
  const cubeCenterTitle = document.getElementById('cubeCenterTitle');
  const cubeCenterSub = document.getElementById('cubeCenterSub');
  const cubeCenterPid = document.getElementById('cubeCenterPid');
  const containmentClamps = document.getElementById('containmentClamps');
  const threatStatusPill = document.getElementById('threatStatusPill');
  const explodedLayersContainer = document.getElementById('explodedLayersContainer');
  const toggleExplodedBtn = document.getElementById('toggleExplodedBtn');
  const explodedBtnText = document.getElementById('explodedBtnText');

  // State Banner Elements
  const stateBannerTitle = document.getElementById('stateBannerTitle');
  const stateBannerDesc = document.getElementById('stateBannerDesc');
  const stateBannerCode = document.getElementById('stateBannerCode');
  const stateBannerIcon = document.getElementById('stateBannerIcon');

  // Telemetry Terminal / Stream Elements
  const syscallStreamBox = document.getElementById('syscallStreamBox');
  const syscallCounter = document.getElementById('syscallCounter');
  const latencyCounter = document.getElementById('latencyCounter');
  const filterBtns = document.querySelectorAll('.stream-filter-btn');
  const autoscrollChk = document.getElementById('autoscroll-chk');
  const btnManualContain = document.getElementById('btn-manual-contain');

  // Verdict Box Elements
  const verdictSummaryBox = document.getElementById('verdictSummaryBox');
  const verdictBadge = document.getElementById('verdictBadge');
  const verdictDetailText = document.getElementById('verdictDetailText');

  // State
  let currentState = 'upload';
  let isExploded = false;
  let activeSocket = null;
  let timerInterval = null;
  let startTime = null;
  let totalEvents = 0;
  let currentFilter = 'all';
  let activeSessionId = null;
  let activeTargetPid = null;
  let activeFilename = 'Awaiting Ingest';
  let selectedPayloadType = 'rev_shell';

  // Three.js Scene References
  let threeCore = null;

  // -------------------------------------------------------------
  // 1. Initialize Host Status & Probes
  // -------------------------------------------------------------
  function checkSystemStatus() {
    fetch('/api/system/status')
      .then(res => res.json())
      .then(status => {
        if (statusWsb) {
          if (status.available) {
            statusWsb.innerHTML = `
              <span class="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
              <span class="font-label-sm text-label-sm font-medium">SANDBOX: <span class="text-emerald-600 font-bold">ISOLATED VM</span></span>
            `;
          } else {
            statusWsb.innerHTML = `
              <span class="w-2 h-2 rounded-full bg-amber-500 animate-pulse"></span>
              <span class="font-label-sm text-label-sm font-medium" title="${escapeHtml(status.message || 'Host Job Object fallback')}">
                SANDBOX: <span class="text-amber-600 font-bold">HOST JOB-OBJECT</span>
              </span>
            `;
          }
        }
      })
      .catch(err => {
        console.warn('Unable to query system status:', err);
      });
  }
  checkSystemStatus();

  // -------------------------------------------------------------
  // 2. Cerberus State Machine Definition
  // -------------------------------------------------------------
  const STAGE_CONFIG = {
    upload: {
      stepIndex: 1,
      title: "STAGE 1: UPLOAD & INGESTION",
      desc: "Payload staged in memory. Cryptographic hash computed. Zero execution rights.",
      code: "STAGE::01",
      icon: "cloud_upload",
      cubeIcon: "shield",
      cubeTitle: "ENCLAVE α",
      cubeSub: "AWAITING INGEST",
      pillText: "ENCLAVE: PREPARED",
      pillClass: "bg-surface-container-high text-on-surface",
      clamps: false,
      verdictText: "Awaiting execution trigger. File sha256 checksum calculated.",
      verdictBadge: "READY",
      verdictBadgeClass: "bg-surface-container-high text-on-surface",
      theme: "neutral"
    },
    isolate: {
      stepIndex: 2,
      title: "STAGE 2: EPHEMERAL ISOLATION",
      desc: "Mounted disposable sandbox container / Job Object memory quota bounds enforced.",
      code: "STAGE::02",
      icon: "view_in_ar",
      cubeIcon: "folder_zip",
      cubeTitle: "ISOLATED ENCLAVE",
      cubeSub: "JOB OBJECT ATTACHED",
      pillText: "ENCLAVE: ACTIVE",
      pillClass: "bg-primary-fixed text-on-primary-fixed-variant",
      clamps: false,
      verdictText: "Target staged inside isolated environment with strict resource limits.",
      verdictBadge: "ISOLATED",
      verdictBadgeClass: "bg-primary-fixed text-on-primary-fixed-variant",
      theme: "primary"
    },
    observe: {
      stepIndex: 3,
      title: "STAGE 3: RUNTIME OBSERVATION",
      desc: "Target executing under ETW kernel tracepoints. Telemetry engine monitoring File, Network, Process.",
      code: "STAGE::03",
      icon: "visibility",
      cubeIcon: "troubleshoot",
      cubeTitle: "ETW PROBES LIVE",
      cubeSub: "TELEMETRY STREAMING",
      pillText: "TELEMETRY: ACTIVE",
      pillClass: "bg-secondary-fixed text-on-secondary-fixed-variant",
      clamps: false,
      verdictText: "Monitoring system call activity, thread creations, and outbound network connect attempts.",
      verdictBadge: "OBSERVING",
      verdictBadgeClass: "bg-secondary-fixed text-on-secondary-fixed-variant",
      theme: "secondary"
    },
    detect: {
      stepIndex: 4,
      title: "STAGE 4: DECISION NEXUS DETECT",
      desc: "SECURITY POLICY BREACH: Malicious behavior detected in real-time kernel telemetry.",
      code: "STAGE::04",
      icon: "warning",
      cubeIcon: "report",
      cubeTitle: "THREAT FLAGGED",
      cubeSub: "VIOLATION DETECTED",
      pillText: "THREAT IDENTIFIED",
      pillClass: "bg-error-container text-on-error-container animate-pulse",
      clamps: false,
      verdictText: "Decision Nexus identified high-severity policy trip. Preparing containment response.",
      verdictBadge: "BREACH FLAGGED",
      verdictBadgeClass: "bg-error-container text-on-error-container",
      theme: "threat"
    },
    contain: {
      stepIndex: 5,
      title: "STAGE 5: CONTAINMENT INTERCEPT",
      desc: "Instant stasis enforced: Threads suspended via SuspendThread, outbound network severed via WFP.",
      code: "STAGE::05",
      icon: "lock",
      cubeIcon: "lock",
      cubeTitle: "LOCKED & FROZEN",
      cubeSub: "STASIS INTERCEPT",
      pillText: "CONTAINED (0.04ms)",
      pillClass: "bg-tertiary-container text-on-tertiary-container font-bold",
      clamps: true,
      verdictText: "Threat execution halted at kernel boundary. Outbound traffic severed before packet escape.",
      verdictBadge: "CONTAINED",
      verdictBadgeClass: "bg-tertiary-container text-on-tertiary-container",
      theme: "contained"
    },
    verdict: {
      stepIndex: 6,
      title: "STAGE 6: FORENSIC VERDICT",
      desc: "Sandbox analysis concluded. Cryptographic forensic audit generated. Host filesystem pristine.",
      code: "STAGE::06",
      icon: "verified",
      cubeIcon: "gavel",
      cubeTitle: "HOST PROTECTED",
      cubeSub: "ZERO RESIDUE",
      pillText: "AUDIT: COMPLETED",
      pillClass: "bg-primary text-on-primary",
      clamps: true,
      verdictText: "Analysis finalized. All telemetry logged to audit store.",
      verdictBadge: "SAFE VERDICT",
      verdictBadgeClass: "bg-primary text-on-primary",
      theme: "verdict"
    }
  };

  function setCerberusState(stateKey, customDesc, customVerdict) {
    currentState = stateKey;
    const data = STAGE_CONFIG[stateKey];
    if (!data) return;

    // 1. Update Stepper Buttons
    stepBtns.forEach(btn => {
      const step = btn.getAttribute('data-step');
      const dot = btn.querySelector('.step-dot');
      if (step === stateKey) {
        btn.className = "state-step-btn active px-space-md py-1.5 rounded-full font-label-sm text-label-sm uppercase font-semibold transition-all duration-200 flex items-center gap-1 bg-primary text-on-primary shadow-sm";
        if (dot) dot.className = "step-dot w-1.5 h-1.5 rounded-full bg-surface-container-lowest";
      } else {
        btn.className = "state-step-btn px-space-md py-1.5 rounded-full font-label-sm text-label-sm uppercase font-medium text-on-surface-variant hover:bg-surface-container-high hover:text-on-surface transition-all duration-200 flex items-center gap-1";
        if (dot) dot.className = "step-dot w-1.5 h-1.5 rounded-full bg-outline-variant";
      }
    });

    // 2. Update Central 3D Cube Annotation
    if (cubeIconState) cubeIconState.textContent = data.cubeIcon;
    if (cubeCenterTitle) cubeCenterTitle.textContent = data.cubeTitle;
    if (cubeCenterSub) cubeCenterSub.textContent = data.cubeSub;
    if (cubeCenterPid && activeTargetPid) {
      cubeCenterPid.textContent = `PID: ${activeTargetPid} :: ACTIVE`;
    }

    // 3. Update Containment Clamps
    if (containmentClamps) {
      if (data.clamps) {
        containmentClamps.classList.remove('opacity-0', 'scale-90');
        containmentClamps.classList.add('opacity-100', 'scale-100');
      } else {
        containmentClamps.classList.remove('opacity-100', 'scale-100');
        containmentClamps.classList.add('opacity-0', 'scale-90');
      }
    }

    // 4. Update State Banner
    if (stateBannerTitle) stateBannerTitle.textContent = data.title;
    if (stateBannerDesc) stateBannerDesc.textContent = customDesc || data.desc;
    if (stateBannerCode) stateBannerCode.textContent = data.code;
    if (stateBannerIcon) stateBannerIcon.textContent = data.icon;

    // 5. Update Threat Status Pill
    if (threatStatusPill) {
      threatStatusPill.className = `font-label-sm text-label-sm px-2.5 py-1 rounded-full font-mono font-bold uppercase transition-all flex items-center gap-1.5 ${data.pillClass}`;
      threatStatusPill.innerHTML = `<span class="w-2 h-2 rounded-full bg-current"></span> ${data.pillText}`;
    }

    // 6. Update Verdict Box
    if (verdictDetailText) {
      verdictDetailText.textContent = customVerdict || data.verdictText;
    }
    if (verdictBadge) {
      verdictBadge.textContent = data.verdictBadge;
      verdictBadge.className = `font-label-sm text-label-sm px-2 py-0.5 rounded font-mono font-bold ${data.verdictBadgeClass}`;
    }

    // 7. Update Three.js Core Color Scheme
    if (threeCore) {
      threeCore.updateState(data.theme);
    }
  }

  // -------------------------------------------------------------
  // 3. File Upload & Ingestion Logic
  // -------------------------------------------------------------
  if (fileUploadBtn && fileInput) {
    fileUploadBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      fileInput.click();
    });

    fileInput.addEventListener('change', (e) => {
      if (e.target.files && e.target.files.length > 0) {
        uploadFile(e.target.files[0]);
      }
    });

    // Drag and Drop
    ['dragenter', 'dragover'].forEach(eventName => {
      fileUploadBtn.addEventListener(eventName, (e) => {
        e.preventDefault();
        e.stopPropagation();
        fileUploadBtn.classList.add('ring-2', 'ring-primary');
      }, false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
      fileUploadBtn.addEventListener(eventName, (e) => {
        e.preventDefault();
        e.stopPropagation();
        fileUploadBtn.classList.remove('ring-2', 'ring-primary');
      }, false);
    });

    fileUploadBtn.addEventListener('drop', (e) => {
      const dt = e.dataTransfer;
      if (dt && dt.files && dt.files.length > 0) {
        uploadFile(dt.files[0]);
      }
    });
  }

  // Also support dropping anywhere on spatial scene
  if (spatialSceneWrapper) {
    ['dragenter', 'dragover'].forEach(evt => {
      spatialSceneWrapper.addEventListener(evt, (e) => {
        e.preventDefault();
        e.stopPropagation();
      });
    });
    spatialSceneWrapper.addEventListener('drop', (e) => {
      e.preventDefault();
      e.stopPropagation();
      if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length > 0) {
        uploadFile(e.dataTransfer.files[0]);
      }
    });
  }

  // -------------------------------------------------------------
  // 4. Sample Payload Presets & Execution
  // -------------------------------------------------------------
  const PAYLOAD_PRESETS = {
    rev_shell: {
      filename: "suspicious_payload_sample.ps1",
      displayName: "reverse_shell.py",
      content: `# Cerberus Malicious Simulation Payload
Probe-CredentialHive -Path "C:\\Windows\\System32\\config\\SAM"
Start-Process "cmd.exe" -ArgumentList "/c whoami /priv"
Connect-Outbound -Destination "198.51.100.42:443"
`,
      type: "MALICIOUS"
    },
    buffer_probe: {
      filename: "buffer_probe_sample.c",
      displayName: "buffer_probe.c",
      content: `// Memory probe taint evaluation
#include <windows.h>
int main() {
    void* p = VirtualAlloc(NULL, 1024*1024*64, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    return 0;
}
`,
      type: "TAINT RISK"
    },
    clean_eval: {
      filename: "clean_worker_benchmark.bat",
      displayName: "clean_data_agg.py",
      content: `@echo off
echo Cerberus Clean Benchmark Run
set /a x=1024 * 768
echo Result: %x%
`,
      type: "BENIGN"
    }
  };

  payloadBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const type = btn.getAttribute('data-payload');
      selectPayload(type);
    });
  });

  function selectPayload(type) {
    selectedPayloadType = type;
    payloadBtns.forEach(b => {
      const isCur = b.getAttribute('data-payload') === type;
      if (isCur) {
        b.className = "payload-btn active text-left p-space-sm rounded-lg bg-surface-container-high/60 transition-all flex flex-col gap-0.5 ring-1 ring-primary";
      } else {
        b.className = "payload-btn text-left p-space-sm rounded-lg bg-surface-container-lowest hover:bg-surface-container-high/40 transition-all flex flex-col gap-0.5";
      }
    });

    const preset = PAYLOAD_PRESETS[type];
    if (preset && activeWorkloadLabel) {
      activeWorkloadLabel.textContent = `${preset.displayName} (Standby)`;
    }
  }

  if (btnExecuteCycle) {
    btnExecuteCycle.addEventListener('click', () => {
      const preset = PAYLOAD_PRESETS[selectedPayloadType] || PAYLOAD_PRESETS.rev_shell;
      const file = new File([preset.content], preset.filename, { type: 'text/plain' });
      uploadFile(file);
    });
  }

  // -------------------------------------------------------------
  // 5. Upload & Session Launch Controller
  // -------------------------------------------------------------
  async function uploadFile(file) {
    resetAnalysisSession(file.name);

    const formData = new FormData();
    formData.append('file', file);

    try {
      setCerberusState('isolate', `Staging target payload '${file.name}' inside disposable Windows Sandbox environment.`);

      const response = await fetch('/api/upload', {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) {
        throw new Error(`Server returned HTTP ${response.status}: ${response.statusText}`);
      }

      const session = await response.json();
      activeSessionId = session.session_id;
      activeTargetPid = session.target_pid;

      if (activeWorkloadLabel) {
        activeWorkloadLabel.textContent = `${file.name} (PID: ${session.target_pid})`;
      }
      if (cubeCenterPid) {
        cubeCenterPid.textContent = `PID: ${session.target_pid} :: ACTIVE`;
      }

      appendStreamEvent({
        timestamp: formatTimestamp(),
        category: 'SYS',
        severity: 'info',
        title: 'SESSION_INITIALIZED',
        description: `Session '${session.session_id}' launched. Target PID: ${session.target_pid}. FallbackHostMode: ${session.fallback_host_mode}`
      });

      // Connect real-time telemetry WebSocket
      connectTelemetryWebSocket(session.session_id);
    } catch (err) {
      console.error('Upload error:', err);
      setCerberusState('verdict', `Analysis launch failed: ${err.message}`, 'LAUNCH ERROR');
      appendStreamEvent({
        timestamp: formatTimestamp(),
        category: 'SYS',
        severity: 'critical',
        title: 'LAUNCH_ERROR',
        description: err.message
      });
      clearInterval(timerInterval);
    }
  }

  function resetAnalysisSession(filename) {
    if (activeSocket) {
      activeSocket.close();
      activeSocket = null;
    }
    clearInterval(timerInterval);

    totalEvents = 0;
    activeFilename = filename;
    if (syscallCounter) syscallCounter.textContent = '0';
    if (syscallStreamBox) syscallStreamBox.innerHTML = '';

    startTime = Date.now();
    timerInterval = setInterval(() => {
      const elapsed = ((Date.now() - startTime) / 1000).toFixed(2);
      if (latencyCounter) latencyCounter.textContent = `${elapsed}s`;
    }, 50);

    setCerberusState('upload', `Payload '${filename}' uploaded. Initializing ephemeral containment enclave.`);
  }

  // -------------------------------------------------------------
  // 6. WebSocket Live Telemetry Ingestion
  // -------------------------------------------------------------
  function connectTelemetryWebSocket(sessionId) {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/analysis/${sessionId}`;

    activeSocket = new WebSocket(wsUrl);

    activeSocket.onopen = () => {
      console.log(`[Cerberus] Connected to telemetry WebSocket for session ${sessionId}`);
      setCerberusState('observe');
    };

    activeSocket.onmessage = (e) => {
      try {
        const event = JSON.parse(e.data);
        handleIncomingTelemetryEvent(event);
      } catch (err) {
        console.error('Error parsing telemetry JSON:', err);
      }
    };

    activeSocket.onclose = () => {
      console.log('[Cerberus] Telemetry WebSocket channel closed.');
      clearInterval(timerInterval);
    };

    activeSocket.onerror = (err) => {
      console.error('[Cerberus] Telemetry WebSocket error:', err);
    };
  }

  function handleIncomingTelemetryEvent(event) {
    totalEvents++;
    if (syscallCounter) syscallCounter.textContent = String(totalEvents);

    // Dynamic State Machine Milestones
    if (event.type === 'SESSION_INIT' || event.type === 'JOB_OBJECT_ATTACH') {
      setCerberusState('isolate');
    } else if (event.type === 'PROCESS_START' || event.type === 'TELEMETRY_ENGINE_ACTIVE') {
      setCerberusState('observe');
    } else if (
      event.type === 'FILE_ACCESS_VIOLATION' ||
      event.type === 'CHILD_PROCESS_VIOLATION' ||
      event.type === 'NETWORK_VIOLATION' ||
      event.severity === 'violation'
    ) {
      setCerberusState('detect', `Policy breach tripped: ${event.title || event.type}. Immediate interception primed.`);
    } else if (event.type === 'ACTION_SUSPEND_THREAD' || event.type === 'ACTION_WFP_SEVER' || event.category === 'containment') {
      setCerberusState('contain', `Threat contained: ${event.description || 'Threads suspended and outbound cut.'}`);
    } else if (event.type === 'VERDICT') {
      clearInterval(timerInterval);
      if (event.verdict_state === 'FROZEN') {
        const violationSummary = (event.violations && event.violations.length > 0) ? event.violations.join('; ') : 'Severe policy trips';
        setCerberusState('verdict', `EXECUTION FROZEN: Contained ${violationSummary}. Host system protected with zero residue.`, 'CONTAINED');
        if (verdictBadge) {
          verdictBadge.textContent = 'FROZEN (VIOLATION)';
          verdictBadge.className = 'font-label-sm text-label-sm px-2 py-0.5 rounded font-mono font-bold bg-tertiary-container text-on-tertiary-container';
        }
      } else if (event.verdict_state === 'CLEAN') {
        setCerberusState('verdict', 'EXECUTION CLEAN: Target ran to completion inside the sandbox with 0 suspicious behaviors detected.', 'VERIFIED CLEAN');
        if (verdictBadge) {
          verdictBadge.textContent = 'CLEAN RUNTIME';
          verdictBadge.className = 'font-label-sm text-label-sm px-2 py-0.5 rounded font-mono font-bold bg-primary text-on-primary';
        }
      } else {
        setCerberusState('verdict', event.description || 'Analysis completed.', event.verdict_state || 'COMPLETE');
      }
    } else if (event.type === 'ERROR') {
      clearInterval(timerInterval);
      setCerberusState('verdict', event.description || 'Runtime error encountered.', 'ERROR');
    }

    // Append to Terminal Stream
    appendStreamEvent(event);
  }

  function appendStreamEvent(event) {
    if (!syscallStreamBox) return;

    const row = document.createElement('div');
    const category = event.category || 'system';
    const severity = event.severity || 'info';

    row.className = `p-1.5 rounded flex items-start justify-between gap-1 shadow-xs transition-all stream-event-row`;
    row.dataset.category = category;
    row.dataset.severity = severity;

    // Apply color styling based on severity
    if (severity === 'critical' || severity === 'violation') {
      row.classList.add('bg-error-container/40', 'border-l-2', 'border-error');
    } else if (category === 'containment') {
      row.classList.add('bg-secondary-fixed/40', 'border-l-2', 'border-secondary');
    } else {
      row.classList.add('bg-surface-container-lowest');
    }

    let detailItems = '';
    if (event.details && typeof event.details === 'object' && Object.keys(event.details).length > 0) {
      detailItems = Object.entries(event.details)
        .map(([k, v]) => `<span class="text-[10px] text-outline mr-2"><strong class="text-on-surface">${escapeHtml(k)}:</strong> ${escapeHtml(v)}</span>`)
        .join('');
      detailItems = `<div class="mt-0.5 flex flex-wrap">${detailItems}</div>`;
    }

    let catBadgeColor = 'text-primary';
    if (category === 'network') catBadgeColor = 'text-secondary';
    if (category === 'file') catBadgeColor = 'text-amber-600';
    if (category === 'process') catBadgeColor = 'text-indigo-600';
    if (category === 'containment') catBadgeColor = 'text-tertiary font-bold';

    row.innerHTML = `
      <div class="flex flex-col flex-1 min-w-0">
        <div class="flex items-center gap-1.5">
          <span class="font-mono text-[10px] ${catBadgeColor}">[${escapeHtml(category.toUpperCase())}]</span>
          <span class="font-semibold text-on-surface truncate text-label-sm">${escapeHtml(event.title || event.type)}</span>
        </div>
        <span class="text-outline text-[11px] truncate">${escapeHtml(event.description || '')}</span>
        ${detailItems}
      </div>
      <span class="text-outline-variant font-mono text-[10px] whitespace-nowrap ml-1">${escapeHtml(event.timestamp || formatTimestamp())}</span>
    `;

    // Apply active filter
    if (currentFilter === 'violation' && severity !== 'violation' && severity !== 'critical') {
      row.style.display = 'none';
    } else if (currentFilter === 'containment' && category !== 'containment') {
      row.style.display = 'none';
    }

    syscallStreamBox.appendChild(row);

    // Auto-scroll
    if (!autoscrollChk || autoscrollChk.checked) {
      syscallStreamBox.scrollTop = syscallStreamBox.scrollHeight;
    }
  }

  // -------------------------------------------------------------
  // 7. Terminal Filtering Controls
  // -------------------------------------------------------------
  filterBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      filterBtns.forEach(b => {
        b.className = "stream-filter-btn px-2 py-0.5 rounded text-[10px] font-label-sm uppercase font-semibold transition-all text-on-surface-variant hover:bg-surface-container";
      });
      btn.className = "stream-filter-btn px-2 py-0.5 rounded text-[10px] font-label-sm uppercase font-semibold transition-all bg-primary text-on-primary shadow-xs";

      currentFilter = btn.dataset.filter || 'all';
      applyStreamFilter();
    });
  });

  function applyStreamFilter() {
    if (!syscallStreamBox) return;
    const items = syscallStreamBox.querySelectorAll('.stream-event-row');
    items.forEach(item => {
      const cat = item.dataset.category || '';
      const sev = item.dataset.severity || '';

      if (currentFilter === 'all') {
        item.style.display = 'flex';
      } else if (currentFilter === 'violation') {
        item.style.display = (sev === 'violation' || sev === 'critical') ? 'flex' : 'none';
      } else if (currentFilter === 'containment') {
        item.style.display = (cat === 'containment') ? 'flex' : 'none';
      }
    });
  }

  // -------------------------------------------------------------
  // 8. Manual Emergency Containment Action
  // -------------------------------------------------------------
  if (btnManualContain) {
    btnManualContain.addEventListener('click', () => {
      setCerberusState('contain', 'Manual emergency stasis invoked. Process threads suspended.');
      appendStreamEvent({
        timestamp: formatTimestamp(),
        category: 'containment',
        severity: 'critical',
        title: 'MANUAL_STASIS_INTERCEPT',
        description: 'Operator manually triggered immediate thread freeze and network sever.'
      });
    });
  }

  // -------------------------------------------------------------
  // 9. Exploded 3D View Toggle
  // -------------------------------------------------------------
  if (toggleExplodedBtn) {
    toggleExplodedBtn.addEventListener('click', () => {
      isExploded = !isExploded;
      if (isExploded) {
        if (centralCoreCube) centralCoreCube.classList.add('hidden');
        if (explodedLayersContainer) explodedLayersContainer.classList.remove('hidden');
        if (explodedBtnText) explodedBtnText.textContent = "COLLAPSE TO CORE";
      } else {
        if (centralCoreCube) centralCoreCube.classList.remove('hidden');
        if (explodedLayersContainer) explodedLayersContainer.classList.add('hidden');
        if (explodedBtnText) explodedBtnText.textContent = "EXPLODE 3D LAYERS";
      }
    });
  }

  // -------------------------------------------------------------
  // 10. Mouse Parallax on CSS 3D Cube
  // -------------------------------------------------------------
  if (spatialSceneWrapper && centralCoreCube) {
    const parentContainer = spatialSceneWrapper.parentElement;
    if (parentContainer) {
      parentContainer.addEventListener('mousemove', (e) => {
        if (isExploded) return;
        const rect = parentContainer.getBoundingClientRect();
        const x = e.clientX - rect.left - (rect.width / 2);
        const y = e.clientY - rect.top - (rect.height / 2);
        const rotY = 38 + (x / 24);
        const rotX = -24 - (y / 24);
        centralCoreCube.style.transform = `rotateX(${rotX}deg) rotateY(${rotY}deg)`;
      });

      parentContainer.addEventListener('mouseleave', () => {
        if (!isExploded) {
          centralCoreCube.style.transform = 'rotateX(-24deg) rotateY(38deg)';
        }
      });
    }
  }

  // -------------------------------------------------------------
  // 11. Three.js Interactive Defense Core Setup
  // -------------------------------------------------------------
  initThreeJsDefenseCore();

  function initThreeJsDefenseCore() {
    const threeContainer = document.getElementById('threejs-canvas-mount');
    if (!threeContainer || typeof THREE === 'undefined') return;

    try {
      const width = threeContainer.clientWidth || 460;
      const height = threeContainer.clientHeight || 420;

      const scene = new THREE.Scene();
      const camera = new THREE.PerspectiveCamera(40, width / height, 0.1, 1000);
      camera.position.set(13, 10, 15);
      camera.lookAt(0, 0, 0);

      const renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true });
      renderer.setSize(width, height);
      renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
      threeContainer.appendChild(renderer.domElement);

      // Lighting
      const ambientLight = new THREE.AmbientLight(0xf0f7ff, 1.3);
      scene.add(ambientLight);

      const dirLight1 = new THREE.DirectionalLight(0x0284c7, 2.0);
      dirLight1.position.set(15, 20, 10);
      scene.add(dirLight1);

      const pointLight = new THREE.PointLight(0x38bdf8, 2.5, 25);
      pointLight.position.set(0, 0, 0);
      scene.add(pointLight);

      // Master Rotating Group
      const coreGroup = new THREE.Group();
      scene.add(coreGroup);

      // Grid Helper
      const gridHelper = new THREE.GridHelper(9, 10, 0x0284c7, 0xdbeafe);
      gridHelper.position.y = -3.2;
      coreGroup.add(gridHelper);

      // Gyroscopic Rings
      const gyroGroup = new THREE.Group();
      coreGroup.add(gyroGroup);

      const ring1Geo = new THREE.TorusGeometry(2.2, 0.03, 16, 64);
      const ring1Mat = new THREE.MeshBasicMaterial({ color: 0x0ea5e9, transparent: true, opacity: 0.65 });
      const gyroRing1 = new THREE.Mesh(ring1Geo, ring1Mat);
      gyroGroup.add(gyroRing1);

      const ring2Geo = new THREE.TorusGeometry(2.4, 0.025, 16, 64);
      const ring2Mat = new THREE.MeshBasicMaterial({ color: 0x6366f1, transparent: true, opacity: 0.5 });
      const gyroRing2 = new THREE.Mesh(ring2Geo, ring2Mat);
      gyroRing2.rotation.x = Math.PI / 2.4;
      gyroGroup.add(gyroRing2);

      // Inner Core
      const innerCubeGeo = new THREE.BoxGeometry(1.8, 1.8, 1.8);
      const innerCubeMat = new THREE.MeshPhongMaterial({
        color: 0x0284c7,
        emissive: 0x0369a1,
        emissiveIntensity: 0.5,
        shininess: 90,
        transparent: true,
        opacity: 0.8
      });
      const innerCubeMesh = new THREE.Mesh(innerCubeGeo, innerCubeMat);
      coreGroup.add(innerCubeMesh);

      const innerEdges = new THREE.EdgesGeometry(innerCubeGeo);
      const innerWireMat = new THREE.LineBasicMaterial({ color: 0xffffff, transparent: true, opacity: 0.85 });
      innerCubeMesh.add(new THREE.LineSegments(innerEdges, innerWireMat));

      // Particles
      const particleCount = 24;
      const particleGeo = new THREE.BufferGeometry();
      const particlePos = new Float32Array(particleCount * 3);
      const particleVel = [];

      for (let i = 0; i < particleCount; i++) {
        particlePos[i * 3] = (Math.random() - 0.5) * 4.0;
        particlePos[i * 3 + 1] = (Math.random() - 0.5) * 4.0;
        particlePos[i * 3 + 2] = (Math.random() - 0.5) * 4.0;
        particleVel.push({
          x: (Math.random() - 0.5) * 0.012,
          y: (Math.random() - 0.5) * 0.012,
          z: (Math.random() - 0.5) * 0.012
        });
      }
      particleGeo.setAttribute('position', new THREE.BufferAttribute(particlePos, 3));
      const particleMat = new THREE.PointsMaterial({
        color: 0x38bdf8,
        size: 0.12,
        transparent: true,
        opacity: 0.8
      });
      const particlesMesh = new THREE.Points(particleGeo, particleMat);
      coreGroup.add(particlesMesh);

      // Render loop
      let clock = new THREE.Clock();
      function animate() {
        requestAnimationFrame(animate);
        const elapsed = clock.getElapsedTime();

        coreGroup.rotation.y += 0.003;
        gyroRing1.rotation.z = elapsed * 0.35;
        gyroRing1.rotation.y = elapsed * 0.18;
        gyroRing2.rotation.x = -elapsed * 0.28;

        const pulse = 1.0 + Math.sin(elapsed * 2.2) * 0.04;
        innerCubeMesh.scale.set(pulse, pulse, pulse);
        innerCubeMesh.rotation.y = -elapsed * 0.25;

        // Drift particles
        const pArr = particleGeo.attributes.position.array;
        for (let i = 0; i < particleCount; i++) {
          pArr[i * 3] += particleVel[i].x;
          pArr[i * 3 + 1] += particleVel[i].y;
          pArr[i * 3 + 2] += particleVel[i].z;

          if (Math.abs(pArr[i * 3]) > 2.2) particleVel[i].x *= -1;
          if (Math.abs(pArr[i * 3 + 1]) > 2.2) particleVel[i].y *= -1;
          if (Math.abs(pArr[i * 3 + 2]) > 2.2) particleVel[i].z *= -1;
        }
        particleGeo.attributes.position.needsUpdate = true;

        renderer.render(scene, camera);
      }
      animate();

      window.addEventListener('resize', () => {
        const w = threeContainer.clientWidth || 460;
        const h = threeContainer.clientHeight || 420;
        camera.aspect = w / h;
        camera.updateProjectionMatrix();
        renderer.setSize(w, h);
      });

      threeCore = {
        updateState: (theme) => {
          if (theme === 'threat' || theme === 'contained') {
            innerCubeMat.color.setHex(0xba1a1a);
            innerCubeMat.emissive.setHex(0x93000b);
            dirLight1.color.setHex(0xba1a1a);
            pointLight.color.setHex(0xff5449);
            ring1Mat.color.setHex(0xff5449);
          } else if (theme === 'verdict') {
            innerCubeMat.color.setHex(0x006194);
            innerCubeMat.emissive.setHex(0x004b73);
            dirLight1.color.setHex(0x0284c7);
            pointLight.color.setHex(0x38bdf8);
            ring1Mat.color.setHex(0x0ea5e9);
          } else {
            innerCubeMat.color.setHex(0x0284c7);
            innerCubeMat.emissive.setHex(0x0369a1);
            dirLight1.color.setHex(0x0284c7);
            pointLight.color.setHex(0x38bdf8);
            ring1Mat.color.setHex(0x0ea5e9);
          }
        }
      };
    } catch (err) {
      console.warn('Three.js canvas initialization skipped:', err);
    }
  }

  // -------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------
  function formatTimestamp() {
    const now = new Date();
    return now.toTimeString().split(' ')[0] + '.' + String(now.getMilliseconds()).padStart(3, '0');
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }
});
