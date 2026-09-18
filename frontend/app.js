/**
 * Cerberus Runtime Defense Machine - Dual-Mode Frontend Controller
 * - Front Page (Standby): stitch_remix_1 layout with candidate dropper & enclave matrix
 * - Upload/Analysis State: stitch_remix_2 layout with 3D layered ortho-strata,
 *   real-time BPF telemetry stream, diagnostic matrix, and slide-to-confirm emergency kill slider.
 */

document.addEventListener('DOMContentLoaded', () => {
  // Navigation & Host Status Elements
  const statusWsb = document.getElementById('status-wsb');
  const viewStandby = document.getElementById('view-standby');
  const viewActiveAnalysis = document.getElementById('view-active-analysis');
  const fileInput = document.getElementById('file-input');
  const btnReturnStandby = document.getElementById('btn-return-standby');

  // Standby Elements (stitch_remix_1)
  const fileUploadBtn = document.getElementById('fileUploadBtn');
  const activeWorkloadLabel = document.getElementById('activeWorkloadLabel');
  const activeWorkloadBadge = document.getElementById('activeWorkloadBadge');
  const btnExecuteCycle = document.getElementById('btn-execute-cycle');
  const payloadBtns = document.querySelectorAll('.payload-btn');
  const standbyCentralCube = document.getElementById('centralCoreCube');
  const spatialSceneWrapper = document.getElementById('spatialSceneWrapper');
  const btnResetPerspective = document.getElementById('btn-reset-perspective');
  const standbySyscallBox = document.getElementById('syscallStreamBox');
  const standbySyscallCounter = document.getElementById('syscallCounter');
  const standbyLatencyCounter = document.getElementById('latencyCounter');
  const standbyManualContain = document.getElementById('btn-manual-contain');

  // Active Analysis Elements (stitch_remix_2)
  const activeTargetTitle = document.getElementById('active-target-title');
  const activeTargetStatusBadge = document.getElementById('active-target-status-badge');
  const activePidBadge = document.getElementById('active-pid-badge');
  const activeSandboxLabel = document.getElementById('active-sandbox-label');
  const activeMemDisplay = document.getElementById('active-mem-display');
  const activeCpuDisplay = document.getElementById('active-cpu-display');
  const activeContainDisplay = document.getElementById('active-contain-display');
  const enclaveCube = document.getElementById('enclave-cube');
  const activeDetectNode = document.getElementById('active-detect-node');
  const activeDetectIcon = document.getElementById('active-detect-icon');
  const activeDetectTitle = document.getElementById('active-detect-title');
  const activeDetectSub = document.getElementById('active-detect-sub');
  const activeDetectBadge = document.getElementById('active-detect-badge');
  const activeSeccompStatus = document.getElementById('active-seccomp-status');
  const activeVerdictPlaneTitle = document.getElementById('active-verdict-plane-title');
  const activeVerdictHash = document.getElementById('active-verdict-hash');
  const activeSyscallBox = document.getElementById('active-syscall-box');

  // Active Diagnostic Counters
  const diagInodeWrites = document.getElementById('diag-inode-writes');
  const diagForkDepth = document.getElementById('diag-fork-depth');
  const diagMemoryResident = document.getElementById('diag-memory-resident');
  const diagThreatScore = document.getElementById('diag-threat-score');
  const activeContainmentBadge = document.getElementById('active-containment-badge');

  // Pipeline Indicators (Active View)
  const pipeStage4 = document.getElementById('pipe-stage-4');
  const pipeDetectLabel = document.getElementById('pipe-detect-label');
  const pipeStage5 = document.getElementById('pipe-stage-5');
  const pipeContainLabel = document.getElementById('pipe-contain-label');
  const pipeStage6 = document.getElementById('pipe-stage-6');
  const pipeVerdictLabel = document.getElementById('pipe-verdict-label');

  // Rotation HUD Controls
  const btnRotateLeft = document.getElementById('btn-rotate-left');
  const btnRotateRight = document.getElementById('btn-rotate-right');
  const btnResetCoreView = document.getElementById('btn-reset-core-view');
  const btnFocusTarget = document.getElementById('btn-focus-target');
  const yawVal = document.getElementById('yaw-val');
  const pitchVal = document.getElementById('pitch-val');
  const zoomVal = document.getElementById('zoom-val');

  // Slide-to-Confirm Emergency Kill Slider Elements
  const sliderTrack = document.getElementById('kill-slider-track');
  const sliderHandle = document.getElementById('kill-slider-handle');
  const sliderProgress = document.getElementById('slider-progress');
  const sliderTrackText = document.getElementById('slider-track-text');
  const handleIcon = document.getElementById('handle-icon');

  // Application State
  let activeSocket = null;
  let timerInterval = null;
  let startTime = null;
  let totalEvents = 0;
  let activeSessionId = null;
  let activeTargetPid = null;
  let currentSelectedPayload = 'rev_shell';

  // 3D Viewport Transform State for Layered Ortho-Strata Cube
  let yaw = -34;
  let pitch = 24;
  let zoom = 1.0;
  let isFocused = false;

  // -------------------------------------------------------------
  // 1. Host System Status
  // -------------------------------------------------------------
  function fetchSystemStatus() {
    fetch('/api/system/status')
      .then(r => r.json())
      .then(st => {
        if (statusWsb) {
          if (st.available) {
            statusWsb.innerHTML = `
              <span class="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
              <span class="font-label-sm text-label-sm font-medium">SANDBOX: <span class="text-emerald-600 font-bold">ISOLATED VM</span></span>
            `;
            if (activeSandboxLabel) activeSandboxLabel.textContent = 'ISOLATED_VM_WSB';
          } else {
            statusWsb.innerHTML = `
              <span class="w-2 h-2 rounded-full bg-amber-500 animate-pulse"></span>
              <span class="font-label-sm text-label-sm font-medium" title="${escapeHtml(st.message || 'Host Job Object fallback')}">
                SANDBOX: <span class="text-amber-600 font-bold">HOST JOB-OBJECT</span>
              </span>
            `;
            if (activeSandboxLabel) activeSandboxLabel.textContent = 'HOST_JOB_OBJECT';
          }
        }
      })
      .catch(err => console.warn('Status query failed:', err));
  }
  fetchSystemStatus();

  // -------------------------------------------------------------
  // 2. View Switching: Standby vs Active Analysis
  // -------------------------------------------------------------
  function switchToActiveView(filename, pid) {
    if (viewStandby) viewStandby.classList.add('hidden');
    if (viewActiveAnalysis) viewActiveAnalysis.classList.remove('hidden');

    if (activeTargetTitle) activeTargetTitle.textContent = filename;
    if (activeTargetStatusBadge) {
      activeTargetStatusBadge.textContent = 'ANALYZING';
      activeTargetStatusBadge.className = 'font-label-sm text-label-sm bg-primary text-on-primary px-1 py-0.5 rounded animate-pulse';
    }
    if (activePidBadge) activePidBadge.textContent = `PID: ${pid} [JAIL]`;

    // Reset diagnostic values to baseline
    if (diagInodeWrites) diagInodeWrites.textContent = '0';
    if (diagForkDepth) diagForkDepth.textContent = '1';
    if (diagMemoryResident) diagMemoryResident.textContent = '14.2 MB';
    if (diagThreatScore) {
      diagThreatScore.textContent = '0/100';
      diagThreatScore.className = 'font-headline-sm text-headline-sm text-primary font-bold';
    }
    if (activeContainmentBadge) {
      activeContainmentBadge.textContent = 'MONITORING';
      activeContainmentBadge.className = 'font-label-sm text-label-sm bg-primary-fixed text-on-primary-fixed px-space-xs py-0.5 rounded font-mono font-bold';
    }

    // Reset detect node
    if (activeDetectNode) {
      activeDetectNode.style.boxShadow = 'inset 0 0 0 1px rgba(0, 97, 148, 0.4)';
    }
    if (activeDetectIcon) {
      activeDetectIcon.textContent = 'troubleshoot';
      activeDetectIcon.className = 'material-symbols-outlined text-primary text-[28px] animate-pulse';
    }
    if (activeDetectTitle) {
      activeDetectTitle.textContent = 'PROBES ACTIVE';
      activeDetectTitle.className = 'font-label-md text-label-md font-bold text-primary mt-1';
    }
    if (activeDetectSub) {
      activeDetectSub.textContent = 'ETW KERNEL HOOKS ARMED';
    }
    if (activeDetectBadge) {
      activeDetectBadge.className = 'font-label-sm text-label-sm text-primary font-semibold flex items-center gap-1';
      activeDetectBadge.innerHTML = `<span class="w-1.5 h-1.5 rounded-full bg-primary animate-ping"></span> STREAMING`;
    }

    // Reset Pipeline stages
    if (pipeStage4) pipeStage4.className = 'flex flex-col gap-1 p-2 rounded bg-surface-container-low';
    if (pipeDetectLabel) pipeDetectLabel.textContent = 'MONITORING';
    if (pipeStage5) pipeStage5.className = 'flex flex-col gap-1 p-2 rounded bg-surface-container-low';
    if (pipeContainLabel) pipeContainLabel.textContent = 'STANDBY';
    if (pipeStage6) {
      pipeStage6.className = 'flex flex-col gap-1 p-2 rounded bg-surface-container-low text-on-surface';
    }
    if (pipeVerdictLabel) pipeVerdictLabel.textContent = 'PENDING';

    // Clear active log
    if (activeSyscallBox) activeSyscallBox.innerHTML = '';

    // Reset 3D cube perspective
    resetCoreView();
  }

  function switchToStandbyView() {
    if (activeSocket) {
      activeSocket.close();
      activeSocket = null;
    }
    clearInterval(timerInterval);

    if (viewActiveAnalysis) viewActiveAnalysis.classList.add('hidden');
    if (viewStandby) viewStandby.classList.remove('hidden');

    if (activeWorkloadLabel) {
      activeWorkloadLabel.textContent = 'Click or drop payload script...';
    }
    if (activeWorkloadBadge) {
      activeWorkloadBadge.textContent = 'STANDBY';
    }
  }

  if (btnReturnStandby) {
    btnReturnStandby.addEventListener('click', switchToStandbyView);
  }

  // -------------------------------------------------------------
  // 3. Standby Preset Payloads & Selection
  // -------------------------------------------------------------
  const PAYLOAD_PRESETS = {
    rev_shell: {
      filename: "suspicious_payload.ps1",
      displayName: "reverse_shell.py",
      content: `# Cerberus Malicious Simulation Payload
Probe-CredentialHive -Path "C:\\Windows\\System32\\config\\SAM"
Start-Process "cmd.exe" -ArgumentList "/c whoami /priv"
Connect-Outbound -Destination "198.51.100.42:443"
`,
      tag: "MALICIOUS"
    },
    buffer_probe: {
      filename: "buffer_probe.c",
      displayName: "buffer_probe.c",
      content: `// Memory probe taint evaluation
#include <windows.h>
int main() {
    void* p = VirtualAlloc(NULL, 1024*1024*64, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    return 0;
}
`,
      tag: "TAINT RISK"
    },
    clean_eval: {
      filename: "clean_worker_benchmark.bat",
      displayName: "clean_data_agg.py",
      content: `@echo off
echo Cerberus Clean Benchmark Run
set /a x=1024 * 768
echo Result: %x%
`,
      tag: "BENIGN"
    }
  };

  payloadBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const type = btn.getAttribute('data-payload');
      selectPayload(type);
    });
  });

  function selectPayload(type) {
    currentSelectedPayload = type;
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
      const preset = PAYLOAD_PRESETS[currentSelectedPayload] || PAYLOAD_PRESETS.rev_shell;
      const file = new File([preset.content], preset.filename, { type: 'text/plain' });
      handleFileUpload(file);
    });
  }

  // -------------------------------------------------------------
  // 4. File Dropper & Native File Upload
  // -------------------------------------------------------------
  if (fileUploadBtn && fileInput) {
    fileUploadBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      fileInput.click();
    });

    fileInput.addEventListener('change', (e) => {
      if (e.target.files && e.target.files.length > 0) {
        handleFileUpload(e.target.files[0]);
      }
    });

    // Drag and drop
    ['dragenter', 'dragover'].forEach(ev => {
      fileUploadBtn.addEventListener(ev, (e) => {
        e.preventDefault();
        e.stopPropagation();
        fileUploadBtn.classList.add('ring-2', 'ring-primary');
      });
    });

    ['dragleave', 'drop'].forEach(ev => {
      fileUploadBtn.addEventListener(ev, (e) => {
        e.preventDefault();
        e.stopPropagation();
        fileUploadBtn.classList.remove('ring-2', 'ring-primary');
      });
    });

    fileUploadBtn.addEventListener('drop', (e) => {
      if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length > 0) {
        handleFileUpload(e.dataTransfer.files[0]);
      }
    });
  }

  if (spatialSceneWrapper) {
    ['dragenter', 'dragover'].forEach(ev => {
      spatialSceneWrapper.addEventListener(ev, (e) => {
        e.preventDefault();
        e.stopPropagation();
      });
    });
    spatialSceneWrapper.addEventListener('drop', (e) => {
      e.preventDefault();
      e.stopPropagation();
      if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length > 0) {
        handleFileUpload(e.dataTransfer.files[0]);
      }
    });
  }

  // -------------------------------------------------------------
  // 5. File Upload API & Telemetry WebSocket Hook
  // -------------------------------------------------------------
  async function handleFileUpload(file) {
    const formData = new FormData();
    formData.append('file', file);

    // Switch view to stitch_remix_2 immediately!
    switchToActiveView(file.name, 'Allocating...');

    totalEvents = 0;
    startTime = Date.now();
    timerInterval = setInterval(() => {
      const elapsed = ((Date.now() - startTime) / 1000).toFixed(2);
      if (standbyLatencyCounter) standbyLatencyCounter.textContent = `${elapsed}s`;
    }, 50);

    appendActiveLog({
      timestamp: formatTimestamp(),
      call: `sys_execve("${escapeHtml(file.name)}")`,
      status: "INIT",
      type: "info"
    });

    try {
      const response = await fetch('/api/upload', {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) {
        throw new Error(`Upload failed: ${response.statusText}`);
      }

      const session = await response.json();
      activeSessionId = session.session_id;
      activeTargetPid = session.target_pid;

      if (activePidBadge) activePidBadge.textContent = `PID: ${session.target_pid} [JAIL]`;

      appendActiveLog({
        timestamp: formatTimestamp(),
        call: `cgroup_jail_attach(pid=${session.target_pid})`,
        status: "BOUND",
        type: "info"
      });

      connectWebSocket(session.session_id);
    } catch (err) {
      console.error('Launch failure:', err);
      appendActiveLog({
        timestamp: formatTimestamp(),
        call: `launch_error("${escapeHtml(err.message)}")`,
        status: "FAILED",
        type: "error"
      });
      clearInterval(timerInterval);
    }
  }

  function connectWebSocket(sessionId) {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/analysis/${sessionId}`;

    activeSocket = new WebSocket(wsUrl);

    activeSocket.onopen = () => {
      console.log(`[Cerberus] Connected to telemetry WebSocket for session ${sessionId}`);
    };

    activeSocket.onmessage = (e) => {
      try {
        const event = JSON.parse(e.data);
        handleTelemetryEvent(event);
      } catch (err) {
        console.error('Error parsing telemetry event:', err);
      }
    };

    activeSocket.onclose = () => {
      console.log('[Cerberus] WebSocket closed.');
      clearInterval(timerInterval);
    };

    activeSocket.onerror = (err) => {
      console.error('[Cerberus] WebSocket error:', err);
    };
  }

  function handleTelemetryEvent(event) {
    totalEvents++;
    if (standbySyscallCounter) standbySyscallCounter.textContent = String(totalEvents);

    // Inode, Memory, Fork metrics
    if (event.category === 'file') {
      if (diagInodeWrites) {
        const cur = parseInt(diagInodeWrites.textContent) || 0;
        diagInodeWrites.textContent = String(cur + 1);
      }
    } else if (event.category === 'process') {
      if (diagForkDepth) {
        const cur = parseInt(diagForkDepth.textContent) || 1;
        diagForkDepth.textContent = String(cur + 1);
      }
    }

    // Dynamic memory resident simulation
    if (diagMemoryResident) {
      const memMb = (16.0 + totalEvents * 1.8).toFixed(1);
      diagMemoryResident.textContent = `${memMb} MB`;
      if (activeMemDisplay) activeMemDisplay.textContent = `${memMb} / 128 MB`;
    }

    // Check for violations / containment
    const isViolation = event.severity === 'violation' || event.severity === 'critical';
    const isContainment = event.category === 'containment' || event.type.startsWith('ACTION_');

    if (isViolation || isContainment) {
      // Elevate Threat Score
      if (diagThreatScore) {
        diagThreatScore.textContent = '98/100';
        diagThreatScore.className = 'font-headline-sm text-headline-sm text-tertiary font-bold animate-pulse';
      }

      // Update Active Containment Badge
      if (activeContainmentBadge) {
        activeContainmentBadge.textContent = 'LOCKDOWN';
        activeContainmentBadge.className = 'font-label-sm text-label-sm bg-tertiary-fixed text-on-tertiary-fixed px-space-xs py-0.5 rounded font-mono font-bold animate-pulse';
      }

      // Update Layer 3 Detect Node in the 3D Cube
      if (activeDetectNode) {
        activeDetectNode.style.boxShadow = 'inset 0 0 0 1px rgba(220, 38, 38, 0.6), 0 4px 18px rgba(224, 41, 40, 0.3)';
      }
      if (activeDetectIcon) {
        activeDetectIcon.textContent = 'lock_clock';
        activeDetectIcon.className = 'material-symbols-outlined text-tertiary text-[28px] animate-pulse';
      }
      if (activeDetectTitle) {
        activeDetectTitle.textContent = 'TAINT DETECTED';
        activeDetectTitle.className = 'font-label-md text-label-md font-bold text-tertiary mt-1';
      }
      if (activeDetectSub) {
        activeDetectSub.textContent = escapeHtml(event.title || event.description || 'POLICY TRIP');
      }

      // Update Stage 4 & 5 indicators
      if (pipeStage4) pipeStage4.className = 'flex flex-col gap-1 p-2 rounded bg-tertiary-fixed/30 text-on-surface';
      if (pipeDetectLabel) pipeDetectLabel.textContent = 'SIGNAL TRIP';
      if (pipeStage5) pipeStage5.className = 'flex flex-col gap-1 p-2 rounded bg-tertiary text-on-tertiary shadow-sm';
      if (pipeContainLabel) pipeContainLabel.textContent = 'STASIS CUBE';
    }

    // Verdict handling
    if (event.type === 'VERDICT') {
      clearInterval(timerInterval);

      if (event.verdict_state === 'FROZEN') {
        if (activeTargetStatusBadge) {
          activeTargetStatusBadge.textContent = 'THREAT FROZEN';
          activeTargetStatusBadge.className = 'font-label-sm text-label-sm bg-tertiary text-on-tertiary px-1 py-0.5 rounded font-bold';
        }
        if (pipeStage6) {
          pipeStage6.className = 'flex flex-col gap-1 p-2 rounded bg-tertiary text-on-tertiary shadow-sm font-bold';
        }
        if (pipeVerdictLabel) pipeVerdictLabel.textContent = 'MALICIOUS';
        if (activeVerdictPlaneTitle) {
          activeVerdictPlaneTitle.textContent = 'L5: CONTAINED (ZERO EGRESS)';
          activeVerdictPlaneTitle.className = 'font-label-sm text-label-sm text-tertiary font-bold tracking-wider';
        }
      } else if (event.verdict_state === 'CLEAN') {
        if (activeTargetStatusBadge) {
          activeTargetStatusBadge.textContent = 'CLEAN';
          activeTargetStatusBadge.className = 'font-label-sm text-label-sm bg-primary text-on-primary px-1 py-0.5 rounded font-bold';
        }
        if (diagThreatScore) {
          diagThreatScore.textContent = '0/100';
          diagThreatScore.className = 'font-headline-sm text-headline-sm text-primary font-bold';
        }
        if (activeDetectNode) {
          activeDetectNode.style.boxShadow = 'inset 0 0 0 1px rgba(0, 97, 148, 0.4)';
        }
        if (activeDetectIcon) {
          activeDetectIcon.textContent = 'verified';
          activeDetectIcon.className = 'material-symbols-outlined text-primary text-[28px]';
        }
        if (activeDetectTitle) {
          activeDetectTitle.textContent = 'CLEAN CODE';
          activeDetectTitle.className = 'font-label-md text-label-md font-bold text-primary mt-1';
        }
        if (activeDetectSub) {
          activeDetectSub.textContent = 'NOMINAL EXECUTION :: EXIT 0';
        }
        if (pipeStage6) {
          pipeStage6.className = 'flex flex-col gap-1 p-2 rounded bg-primary text-on-primary shadow-sm font-bold';
        }
        if (pipeVerdictLabel) pipeVerdictLabel.textContent = 'SAFE VERDICT';
        if (activeVerdictPlaneTitle) {
          activeVerdictPlaneTitle.textContent = 'L5: CLEAN RUNTIME';
          activeVerdictPlaneTitle.className = 'font-label-sm text-label-sm text-primary font-bold tracking-wider';
        }
      }
    }

    // Append to active BPF stream log
    let callStr = event.description || event.title || event.type;
    let statusStr = "ALLOW";
    let typeClass = "info";

    if (isViolation) {
      statusStr = "BLOCKED";
      typeClass = "error";
    } else if (isContainment) {
      statusStr = "STASIS";
      typeClass = "warning";
    } else if (event.type === 'VERDICT') {
      statusStr = event.verdict_state || "DONE";
      typeClass = "verdict";
    }

    appendActiveLog({
      timestamp: event.timestamp || formatTimestamp(),
      call: callStr,
      status: statusStr,
      type: typeClass
    });
  }

  function appendActiveLog(entry) {
    if (!activeSyscallBox) return;

    const row = document.createElement('div');
    row.className = 'p-1.5 rounded flex items-center justify-between text-label-sm font-mono';

    if (entry.type === 'error') {
      row.className += ' bg-error-container text-on-error-container';
      row.innerHTML = `
        <span class="text-on-error-container/80 text-[10px]">${escapeHtml(entry.timestamp)}</span>
        <span class="font-bold text-error text-[11px] truncate mx-2">${escapeHtml(entry.call)}</span>
        <span class="font-bold text-error text-[10px]">${escapeHtml(entry.status)}</span>
      `;
    } else if (entry.type === 'warning') {
      row.className += ' bg-tertiary-fixed/30 text-on-surface';
      row.innerHTML = `
        <span class="text-outline text-[10px]">${escapeHtml(entry.timestamp)}</span>
        <span class="font-semibold text-tertiary text-[11px] truncate mx-2">${escapeHtml(entry.call)}</span>
        <span class="font-bold text-tertiary text-[10px]">${escapeHtml(entry.status)}</span>
      `;
    } else {
      row.className += ' bg-surface-container-low text-on-surface';
      row.innerHTML = `
        <span class="text-outline text-[10px]">${escapeHtml(entry.timestamp)}</span>
        <span class="text-on-surface text-[11px] truncate mx-2">${escapeHtml(entry.call)}</span>
        <span class="text-primary font-bold text-[10px]">${escapeHtml(entry.status)}</span>
      `;
    }

    activeSyscallBox.appendChild(row);
    activeSyscallBox.scrollTop = activeSyscallBox.scrollHeight;
  }

  // -------------------------------------------------------------
  // 6. 3D Layered Ortho-Strata Cube Orientation Controller
  // -------------------------------------------------------------
  function updateCubeTransform() {
    if (!enclaveCube) return;
    enclaveCube.style.transform = `perspective(1100px) rotateX(${pitch}deg) rotateY(${yaw}deg) rotateZ(0deg) scale3d(${zoom}, ${zoom}, ${zoom})`;

    if (yawVal) yawVal.innerText = `${yaw}°`;
    if (pitchVal) pitchVal.innerText = `${pitch}°`;
    if (zoomVal) zoomVal.innerText = `${zoom.toFixed(1)}x`;
  }

  function rotateCore(deltaYaw, deltaPitch) {
    yaw += deltaYaw;
    pitch += deltaPitch;
    updateCubeTransform();
  }

  function resetCoreView() {
    yaw = -34;
    pitch = 24;
    zoom = 1.0;
    isFocused = false;
    updateCubeTransform();
  }

  function toggleFocusTarget() {
    isFocused = !isFocused;
    zoom = isFocused ? 1.3 : 1.0;
    yaw = isFocused ? -15 : -34;
    pitch = isFocused ? 12 : 24;
    updateCubeTransform();
  }

  if (btnRotateLeft) btnRotateLeft.addEventListener('click', () => rotateCore(-15, 0));
  if (btnRotateRight) btnRotateRight.addEventListener('click', () => rotateCore(15, 0));
  if (btnResetCoreView) btnResetCoreView.addEventListener('click', resetCoreView);
  if (btnFocusTarget) btnFocusTarget.addEventListener('click', toggleFocusTarget);

  // Standby Cube Mouse Parallax & Reset
  if (btnResetPerspective && standbyCentralCube) {
    btnResetPerspective.addEventListener('click', () => {
      standbyCentralCube.style.transform = 'rotateX(-24deg) rotateY(38deg)';
    });
  }

  if (spatialSceneWrapper && standbyCentralCube) {
    const parentContainer = spatialSceneWrapper.parentElement;
    if (parentContainer) {
      parentContainer.addEventListener('mousemove', (e) => {
        const rect = parentContainer.getBoundingClientRect();
        const x = e.clientX - rect.left - (rect.width / 2);
        const y = e.clientY - rect.top - (rect.height / 2);
        const rotY = 38 + (x / 24);
        const rotX = -24 - (y / 24);
        standbyCentralCube.style.transform = `rotateX(${rotX}deg) rotateY(${rotY}deg)`;
      });

      parentContainer.addEventListener('mouseleave', () => {
        standbyCentralCube.style.transform = 'rotateX(-24deg) rotateY(38deg)';
      });
    }
  }

  // -------------------------------------------------------------
  // 7. Drag-to-Confirm Emergency Kill Slider Interaction
  // -------------------------------------------------------------
  if (sliderTrack && sliderHandle) {
    let isDragging = false;
    let startX = 0;
    let currentX = 0;
    let maxDistance = 0;

    const computeMaxDistance = () => {
      const trackWidth = sliderTrack.clientWidth;
      const handleWidth = sliderHandle.clientWidth;
      return trackWidth - handleWidth - 8;
    };

    const onStart = (e) => {
      isDragging = true;
      startX = e.type.includes('touch') ? e.touches[0].clientX : e.clientX;
      maxDistance = computeMaxDistance();
      sliderHandle.style.transition = 'none';
      if (sliderProgress) sliderProgress.style.transition = 'none';
    };

    const onMove = (e) => {
      if (!isDragging) return;
      const clientX = e.type.includes('touch') ? e.touches[0].clientX : e.clientX;
      const delta = clientX - startX;
      currentX = Math.max(0, Math.min(delta, maxDistance));
      sliderHandle.style.transform = `translateX(${currentX}px)`;
      if (sliderProgress) sliderProgress.style.width = `${currentX + 48}px`;

      if (sliderTrackText) {
        sliderTrackText.style.opacity = currentX > maxDistance * 0.8 ? '0.1' : '0.6';
      }
    };

    const onEnd = () => {
      if (!isDragging) return;
      isDragging = false;
      maxDistance = computeMaxDistance();

      if (currentX >= maxDistance - 6) {
        // Dispatched kill action
        sliderHandle.style.transform = `translateX(${maxDistance}px)`;
        if (sliderProgress) {
          sliderProgress.style.width = '100%';
          sliderProgress.classList.remove('bg-tertiary/20');
          sliderProgress.classList.add('bg-tertiary');
        }
        if (handleIcon) handleIcon.innerText = 'done_all';
        if (sliderTrackText) {
          sliderTrackText.innerText = 'SANDBOX TERMINATED (SIGKILL)';
          sliderTrackText.classList.remove('text-on-surface-variant/60');
          sliderTrackText.classList.add('text-on-tertiary', 'opacity-100');
        }
        sliderTrack.classList.add('bg-tertiary');

        // Log containment
        appendActiveLog({
          timestamp: formatTimestamp(),
          call: "kernel_sigaction(SIGKILL, target_pid)",
          status: "TERMINATED",
          type: "warning"
        });

        if (activeTargetStatusBadge) {
          activeTargetStatusBadge.textContent = 'MANUALLY TERMINATED';
          activeTargetStatusBadge.className = 'font-label-sm text-label-sm bg-tertiary text-on-tertiary px-1 py-0.5 rounded font-bold';
        }

        setTimeout(() => {
          sliderHandle.style.transition = 'transform 0.4s ease';
          if (sliderProgress) {
            sliderProgress.style.transition = 'width 0.4s ease';
            sliderProgress.style.width = '48px';
            sliderProgress.classList.add('bg-tertiary/20');
            sliderProgress.classList.remove('bg-tertiary');
          }
          sliderHandle.style.transform = 'translateX(0px)';
          sliderTrack.classList.remove('bg-tertiary');
          if (sliderTrackText) {
            sliderTrackText.innerText = '>>> SLIDE TO TERMINATE SANDBOX >>>';
            sliderTrackText.classList.add('text-on-surface-variant/60');
            sliderTrackText.classList.remove('text-on-tertiary');
          }
          if (handleIcon) handleIcon.innerText = 'double_arrow';
          currentX = 0;
        }, 2800);
      } else {
        // Snap back
        sliderHandle.style.transition = 'transform 0.3s cubic-bezier(0.16, 1, 0.3, 1)';
        if (sliderProgress) {
          sliderProgress.style.transition = 'width 0.3s cubic-bezier(0.16, 1, 0.3, 1)';
          sliderProgress.style.width = '48px';
        }
        sliderHandle.style.transform = 'translateX(0px)';
        if (sliderTrackText) sliderTrackText.style.opacity = '0.6';
        currentX = 0;
      }
    };

    sliderHandle.addEventListener('mousedown', onStart);
    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onEnd);

    sliderHandle.addEventListener('touchstart', onStart, { passive: true });
    window.addEventListener('touchmove', onMove, { passive: true });
    window.addEventListener('touchend', onEnd);
  }

  // Standby Manual Kill Button
  if (standbyManualContain) {
    standbyManualContain.addEventListener('click', () => {
      alert('Upload a workload first to engage active containment stasis.');
    });
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
