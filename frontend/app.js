/**
 * Cerberus Frontend Application Logic
 * Handles file ingestion, WebSocket telemetry ingestion, live UI state management,
 * and containment alert transitions.
 */

document.addEventListener('DOMContentLoaded', () => {
  // DOM Elements
  const dropzone = document.getElementById('dropzone');
  const fileInput = document.getElementById('file-input');
  const btnDemoMalicious = document.getElementById('btn-demo-malicious');
  const btnDemoClean = document.getElementById('btn-demo-clean');

  // Verdict Banner Elements
  const verdictBanner = document.getElementById('verdict-banner');
  const verdictBadge = document.getElementById('verdict-badge');
  const verdictTitle = document.getElementById('verdict-title');
  const verdictDesc = document.getElementById('verdict-desc');
  const verdictTimer = document.getElementById('verdict-timer');
  const verdictIconContainer = document.getElementById('verdict-icon-container');

  // Metadata & Containment Elements
  const targetStateTag = document.getElementById('target-state-tag');
  const metaFilename = document.getElementById('meta-filename');
  const metaPid = document.getElementById('meta-pid');
  const containmentProcDetail = document.getElementById('containment-proc-detail');
  const containmentNetDetail = document.getElementById('containment-net-detail');
  const pillProcState = document.getElementById('pill-proc-state');
  const pillNetState = document.getElementById('pill-net-state');

  // Terminal Elements
  const terminalStream = document.getElementById('terminal-stream');
  const streamEmpty = document.getElementById('stream-empty');
  const eventCountBadge = document.getElementById('event-count-badge');
  const autoscrollChk = document.getElementById('autoscroll-chk');
  const filterBtns = document.querySelectorAll('.filter-btn');

  // State
  let activeSocket = null;
  let timerInterval = null;
  let startTime = null;
  let totalEvents = 0;
  let currentFilter = 'all';

  // SVG Icons
  const ICONS = {
    ready: `<svg viewBox="0 0 24 24" width="34" height="34" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg>`,
    analyzing: `<svg viewBox="0 0 24 24" width="34" height="34" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg>`,
    clean: `<svg viewBox="0 0 24 24" width="34" height="34" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>`,
    frozen: `<svg viewBox="0 0 24 24" width="34" height="34" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`
  };

  // Drag and drop event listeners
  ['dragenter', 'dragover'].forEach(eventName => {
    dropzone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropzone.classList.add('dragover');
    }, false);
  });

  ['dragleave', 'drop'].forEach(eventName => {
    dropzone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropzone.classList.remove('dragover');
    }, false);
  });

  dropzone.addEventListener('drop', (e) => {
    const dt = e.dataTransfer;
    const files = dt.files;
    if (files.length > 0) {
      handleFileUpload(files[0]);
    }
  });

  fileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
      handleFileUpload(e.target.files[0]);
    }
  });

  // Demo buttons
  btnDemoMalicious.addEventListener('click', () => {
    const maliciousBlob = new File(
      [
        '# Cerberus Malicious Simulation\n' +
        'Probe-CredentialHive -Path "C:\\Windows\\System32\\config\\SAM"\n' +
        'Start-Process "cmd.exe" -ArgumentList "/c whoami /priv"\n' +
        'Connect-Outbound -Destination "198.51.100.42:443"\n'
      ],
      'suspicious_payload_sample.ps1',
      { type: 'text/plain' }
    );
    handleFileUpload(maliciousBlob);
  });

  btnDemoClean.addEventListener('click', () => {
    const cleanBlob = new File(
      [
        '@echo off\n' +
        'echo Cerberus Clean Benchmark Run\n' +
        'set /a x=1024 * 768\n' +
        'echo Result: %x%\n'
      ],
      'clean_worker_benchmark.bat',
      { type: 'text/plain' }
    );
    handleFileUpload(cleanBlob);
  });

  // Filter Buttons
  filterBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      filterBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      currentFilter = btn.dataset.filter;
      applyFilter();
    });
  });

  function applyFilter() {
    const items = terminalStream.querySelectorAll('.event-item');
    items.forEach(item => {
      const category = item.dataset.category || '';
      const severity = item.dataset.severity || '';

      if (currentFilter === 'all') {
        item.style.display = 'flex';
      } else if (currentFilter === 'violation') {
        item.style.display = (severity === 'violation' || severity === 'critical') ? 'flex' : 'none';
      } else if (currentFilter === 'containment') {
        item.style.display = (category === 'containment') ? 'flex' : 'none';
      }
    });
  }

  function resetState(filename) {
    if (activeSocket) {
      activeSocket.close();
      activeSocket = null;
    }
    clearInterval(timerInterval);

    totalEvents = 0;
    eventCountBadge.textContent = '0 EVENTS';
    terminalStream.innerHTML = '';
    streamEmpty.style.display = 'none';

    startTime = Date.now();
    timerInterval = setInterval(() => {
      const elapsed = ((Date.now() - startTime) / 1000).toFixed(2);
      verdictTimer.textContent = `${elapsed}s`;
    }, 50);

    // Update banner to Analyzing state
    verdictBanner.className = 'verdict-banner state-analyzing';
    verdictBadge.textContent = 'ANALYZING';
    verdictTitle.textContent = `Analyzing: ${filename}`;
    verdictDesc.textContent = 'Running inside disposable Windows Sandbox. Monitoring ETW telemetry for network, file, and process violations...';
    verdictIconContainer.innerHTML = ICONS.analyzing;

    // Update containment metadata cards
    targetStateTag.textContent = 'MONITORING';
    metaFilename.textContent = filename;
    metaPid.textContent = 'Allocating...';

    containmentProcDetail.textContent = 'Executing inside Job Object';
    containmentNetDetail.textContent = 'Monitoring Outbound Connects';
    pillProcState.className = 'containment-pill active';
    pillProcState.textContent = 'ACTIVE';
    pillNetState.className = 'containment-pill normal';
    pillNetState.textContent = 'PASS';
  }

  async function handleFileUpload(file) {
    resetState(file.name);

    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await fetch('/api/upload', {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) {
        throw new Error(`Upload failed: ${response.statusText}`);
      }

      const session = await response.json();
      metaPid.textContent = `PID ${session.target_pid}`;

      connectWebSocket(session.session_id);
    } catch (err) {
      console.error(err);
      verdictTitle.textContent = 'Upload or Launch Failed';
      verdictDesc.textContent = err.message;
      verdictBadge.textContent = 'ERROR';
      verdictBanner.className = 'verdict-banner state-frozen';
      clearInterval(timerInterval);
    }
  }

  function connectWebSocket(sessionId) {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/analysis/${sessionId}`;

    activeSocket = new WebSocket(wsUrl);

    activeSocket.onopen = () => {
      console.log(`[Cerberus] Connected to telemetry WebSocket for ${sessionId}`);
    };

    activeSocket.onmessage = (e) => {
      try {
        const event = JSON.parse(e.data);
        renderTelemetryEvent(event);
      } catch (err) {
        console.error('Error parsing telemetry event:', err);
      }
    };

    activeSocket.onclose = () => {
      console.log('[Cerberus] WebSocket telemetry channel closed.');
      clearInterval(timerInterval);
    };

    activeSocket.onerror = (err) => {
      console.error('[Cerberus] WebSocket error:', err);
    };
  }

  function renderTelemetryEvent(event) {
    totalEvents++;
    eventCountBadge.textContent = `${totalEvents} EVENTS`;

    // Process containment triggers
    if (event.type === 'ACTION_SUSPEND_THREAD') {
      pillProcState.className = 'containment-pill frozen';
      pillProcState.textContent = 'FROZEN';
      containmentProcDetail.textContent = 'All Threads Suspended (SuspendThread)';
      targetStateTag.textContent = 'CONTAINED';
    } else if (event.type === 'ACTION_WFP_SEVER') {
      pillNetState.className = 'containment-pill blocked';
      pillNetState.textContent = 'BLOCKED';
      containmentNetDetail.textContent = 'Outbound Cut via Dynamic WFP Filter';
    }

    // Process Final Verdict
    if (event.type === 'VERDICT') {
      clearInterval(timerInterval);
      if (event.verdict_state === 'FROZEN') {
        verdictBanner.className = 'verdict-banner state-frozen';
        verdictBadge.textContent = 'FROZEN — VIOLATION DETECTED';
        verdictTitle.textContent = 'Threat Contained: Sandbox Execution Frozen';
        verdictDesc.textContent = `Security policy violations triggered immediate containment: ${event.violations.join('; ')}. Host is protected.`;
        verdictIconContainer.innerHTML = ICONS.frozen;
        targetStateTag.textContent = 'FROZEN / CONTAINED';
      } else if (event.verdict_state === 'CLEAN') {
        verdictBanner.className = 'verdict-banner state-clean';
        verdictBadge.textContent = 'CLEAN';
        verdictTitle.textContent = 'Execution Complete: Clean';
        verdictDesc.textContent = 'Target ran to completion inside the sandbox with 0 suspicious behaviors detected.';
        verdictIconContainer.innerHTML = ICONS.clean;
        targetStateTag.textContent = 'COMPLETED';
      }
    }

    // Render Event Item in terminal
    const item = document.createElement('div');
    item.className = `event-item sev-${event.severity || 'info'}`;
    item.dataset.category = event.category || 'system';
    item.dataset.severity = event.severity || 'info';

    let detailsHtml = '';
    if (event.details && Object.keys(event.details).length > 0) {
      const parts = Object.entries(event.details)
        .map(([k, v]) => `<span class="detail-item"><strong>${k}:</strong> ${v}</span>`)
        .join('');
      detailsHtml = `<div class="event-details-box">${parts}</div>`;
    }

    item.innerHTML = `
      <div class="event-meta-row">
        <span class="event-time">[${event.timestamp || '00:00:00.000'}]</span>
        <span class="event-tag cat-${event.category || 'system'}">${event.category || 'SYS'}</span>
        <span class="event-title">${escapeHtml(event.title || event.type)}</span>
      </div>
      <div class="event-desc">${escapeHtml(event.description || '')}</div>
      ${detailsHtml}
    `;

    terminalStream.appendChild(item);

    // Check filter applicability
    if (currentFilter === 'violation' && (event.severity !== 'violation' && event.severity !== 'critical')) {
      item.style.display = 'none';
    } else if (currentFilter === 'containment' && event.category !== 'containment') {
      item.style.display = 'none';
    }

    // Auto-scroll
    if (autoscrollChk.checked) {
      terminalStream.scrollTop = terminalStream.scrollHeight;
    }
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
