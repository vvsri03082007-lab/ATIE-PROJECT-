/**
 * ATIE Cyber SOC Operations Dashboard Client Application
 * Handles real-time Server-Sent Events (SSE), reactive DOM rendering,
 * Web Audio synthesizer alerts, and REST management.
 */

// State
const state = {
  isSimulating: false,
  soundEnabled: true,
  autoScroll: true,
  logs: [],
  alerts: [],
  blacklist: [],
  activeAlertModal: null,
  audioCtx: null
};

// DOM Elements
const elements = {
  statusPill: document.getElementById('statusPill'),
  statusText: document.getElementById('statusText'),
  logSourceSelect: document.getElementById('logSourceSelect'),
  delaySelect: document.getElementById('delaySelect'),
  btnStartSim: document.getElementById('btnStartSim'),
  btnStopSim: document.getElementById('btnStopSim'),
  btnClearAlerts: document.getElementById('btnClearAlerts'),
  btnToggleSound: document.getElementById('btnToggleSound'),
  soundIconOn: document.getElementById('soundIconOn'),
  soundIconOff: document.getElementById('soundIconOff'),
  
  // KPIs
  kpiLogsIngested: document.getElementById('kpiLogsIngested'),
  kpiAlertsTotal: document.getElementById('kpiAlertsTotal'),
  kpiCriticalBadge: document.getElementById('kpiCriticalBadge'),
  kpiMaxRisk: document.getElementById('kpiMaxRisk'),
  kpiBlacklistCount: document.getElementById('kpiBlacklistCount'),

  // Stream & Feed
  terminalStream: document.getElementById('terminalStream'),
  streamCountBadge: document.getElementById('streamCountBadge'),
  chkAutoScroll: document.getElementById('chkAutoScroll'),
  btnClearStream: document.getElementById('btnClearStream'),
  alertFeed: document.getElementById('alertFeed'),
  alertCountBadge: document.getElementById('alertCountBadge'),
  alertSearchInput: document.getElementById('alertSearchInput'),

  // Tabs
  tabButtons: document.querySelectorAll('.tab-btn'),
  tabPanes: document.querySelectorAll('.tab-pane'),

  // Analytics
  statCritVal: document.getElementById('statCritVal'),
  barCrit: document.getElementById('barCrit'),
  statHighVal: document.getElementById('statHighVal'),
  barHigh: document.getElementById('barHigh'),
  statMedVal: document.getElementById('statMedVal'),
  barMed: document.getElementById('barMed'),
  statLowVal: document.getElementById('statLowVal'),
  barLow: document.getElementById('barLow'),
  categoryBars: document.getElementById('categoryBars'),

  // Blacklist
  newIpInput: document.getElementById('newIpInput'),
  btnAddBlacklist: document.getElementById('btnAddBlacklist'),
  searchBlacklistInput: document.getElementById('searchBlacklistInput'),
  blacklistTableBody: document.getElementById('blacklistTableBody'),

  // Thresholds
  rangeWindowSec: document.getElementById('rangeWindowSec'),
  valWindowSec: document.getElementById('valWindowSec'),
  rangeFailureThresh: document.getElementById('rangeFailureThresh'),
  valFailureThresh: document.getElementById('valFailureThresh'),
  rangeZScore: document.getElementById('rangeZScore'),
  valZScore: document.getElementById('valZScore'),
  btnSaveThresholds: document.getElementById('btnSaveThresholds'),

  // Analyzer
  analyzerParserSelect: document.getElementById('analyzerParserSelect'),
  analyzerInput: document.getElementById('analyzerInput'),
  btnRunAnalyzer: document.getElementById('btnRunAnalyzer'),
  analyzerResultBox: document.getElementById('analyzerResultBox'),

  // Report
  reportMarkdownPre: document.getElementById('reportMarkdownPre'),
  btnRefreshReport: document.getElementById('btnRefreshReport'),
  btnDownloadReport: document.getElementById('btnDownloadReport'),

  // Modal
  alertModal: document.getElementById('alertModal'),
  modalSeverityPill: document.getElementById('modalSeverityPill'),
  modalRiskScore: document.getElementById('modalRiskScore'),
  modalCategory: document.getElementById('modalCategory'),
  modalIp: document.getElementById('modalIp'),
  modalSystem: document.getElementById('modalSystem'),
  modalDesc: document.getElementById('modalDesc'),
  modalPayload: document.getElementById('modalPayload'),
  modalBlockIpBtn: document.getElementById('modalBlockIpBtn'),
  btnCloseModal: document.getElementById('btnCloseModal'),
  modalCloseBtn: document.getElementById('modalCloseBtn')
};

// Initialize
document.addEventListener('DOMContentLoaded', () => {
  setupAudio();
  setupEventListeners();
  initSse();
  fetchStatus();
  fetchAlerts();
  loadBlacklist();
  loadReport();
});

// Audio Synthesizer for Critical Threat Alerts
function setupAudio() {
  try {
    const AudioContext = window.AudioContext || window.webkitAudioContext;
    if (AudioContext) {
      state.audioCtx = new AudioContext();
    }
  } catch (e) {
    console.warn('Web Audio not supported:', e);
  }
}

function playCyberAlarm() {
  if (!state.soundEnabled || !state.audioCtx) return;
  try {
    if (state.audioCtx.state === 'suspended') {
      state.audioCtx.resume();
    }
    const now = state.audioCtx.currentTime;
    const osc = state.audioCtx.createOscillator();
    const gain = state.audioCtx.createGain();

    osc.type = 'sawtooth';
    osc.frequency.setValueAtTime(880, now);
    osc.frequency.exponentialRampToValueAtTime(440, now + 0.15);
    osc.frequency.setValueAtTime(880, now + 0.15);
    osc.frequency.exponentialRampToValueAtTime(440, now + 0.3);

    gain.gain.setValueAtTime(0.12, now);
    gain.gain.exponentialRampToValueAtTime(0.01, now + 0.35);

    osc.connect(gain);
    gain.connect(state.audioCtx.destination);

    osc.start(now);
    osc.stop(now + 0.35);
  } catch (e) {
    console.warn('Audio playback error', e);
  }
}

// Server-Sent Events (SSE) Client
function initSse() {
  const eventSource = new EventSource('/api/simulation/stream');

  eventSource.addEventListener('log', (e) => {
    try {
      const log = JSON.parse(e.data);
      appendLogToStream(log);
    } catch (err) {
      console.error('Error parsing SSE log:', err);
    }
  });

  eventSource.addEventListener('alert', (e) => {
    try {
      const alert = JSON.parse(e.data);
      prependAlert(alert);
      if (alert.severity === 'CRITICAL') {
        playCyberAlarm();
      }
      fetchStatus();
    } catch (err) {
      console.error('Error parsing SSE alert:', err);
    }
  });

  eventSource.addEventListener('complete', () => {
    setSimulatingUI(false);
    fetchStatus();
  });

  eventSource.addEventListener('stopped', () => {
    setSimulatingUI(false);
    fetchStatus();
  });

  eventSource.addEventListener('cleared', () => {
    state.logs = [];
    state.alerts = [];
    elements.terminalStream.innerHTML = '<div class="terminal-line" style="color: var(--text-muted); justify-content: center; padding: 2rem 0;">Log telemetry stream cleared.</div>';
    elements.alertFeed.innerHTML = '<div class="terminal-line" style="color: var(--text-muted); justify-content: center; padding: 2rem 0;">No active threat alerts triggered yet.</div>';
    fetchStatus();
  });

  eventSource.onerror = () => {
    // Reconnects automatically
  };
}

// REST API Operations
async function fetchStatus() {
  try {
    const res = await fetch('/api/status');
    const data = await res.json();

    setSimulatingUI(data.isSimulating);
    elements.kpiLogsIngested.textContent = data.totalLogsIngested.toLocaleString();
    elements.kpiAlertsTotal.textContent = data.totalAlerts.toLocaleString();
    elements.kpiBlacklistCount.textContent = data.blacklistCount;

    // Thresholds inputs
    if (data.thresholds) {
      elements.rangeWindowSec.value = data.thresholds.slidingWindowSeconds;
      elements.valWindowSec.textContent = data.thresholds.slidingWindowSeconds + ' seconds';
      elements.rangeFailureThresh.value = data.thresholds.failureThreshold;
      elements.valFailureThresh.textContent = data.thresholds.failureThreshold + ' failures';
      elements.rangeZScore.value = data.thresholds.zScore;
      elements.valZScore.textContent = Number(data.thresholds.zScore).toFixed(2) + ' σ';
    }

    // Severity Analytics
    if (data.severityStats) {
      const crit = data.severityStats.CRITICAL || 0;
      const high = data.severityStats.HIGH || 0;
      const med = data.severityStats.MEDIUM || 0;
      const low = data.severityStats.LOW || 0;
      const total = crit + high + med + low;

      elements.kpiCriticalBadge.textContent = crit + ' critical';
      elements.statCritVal.textContent = crit;
      elements.statHighVal.textContent = high;
      elements.statMedVal.textContent = med;
      elements.statLowVal.textContent = low;

      elements.barCrit.style.width = total > 0 ? (crit / total * 100) + '%' : '0%';
      elements.barHigh.style.width = total > 0 ? (high / total * 100) + '%' : '0%';
      elements.barMed.style.width = total > 0 ? (med / total * 100) + '%' : '0%';
      elements.barLow.style.width = total > 0 ? (low / total * 100) + '%' : '0%';
    }

    // Category Analytics
    if (data.categoryStats) {
      renderCategoryBars(data.categoryStats);
    }

  } catch (err) {
    console.error('Error fetching status:', err);
  }
}

async function fetchAlerts(searchQuery = '') {
  try {
    const url = searchQuery ? `/api/alerts?q=${encodeURIComponent(searchQuery)}` : '/api/alerts';
    const res = await fetch(url);
    const data = await res.json();

    state.alerts = data.alerts || [];
    renderAlertFeed(state.alerts);

    // Compute max risk
    let maxR = 0;
    state.alerts.forEach(a => {
      if (a.riskScore > maxR) maxR = a.riskScore;
    });
    elements.kpiMaxRisk.textContent = maxR.toFixed(1);

  } catch (err) {
    console.error('Error fetching alerts:', err);
  }
}

function setSimulatingUI(simulating) {
  state.isSimulating = simulating;
  if (simulating) {
    elements.statusPill.classList.add('simulating');
    elements.statusText.textContent = 'STREAMING LIVE';
    elements.btnStartSim.disabled = true;
    elements.btnStopSim.disabled = false;
  } else {
    elements.statusPill.classList.remove('simulating');
    elements.statusText.textContent = 'STANDBY';
    elements.btnStartSim.disabled = false;
    elements.btnStopSim.disabled = true;
  }
}

// Ingestion Stream Render
function appendLogToStream(log) {
  state.logs.push(log);
  if (state.logs.length > 200) state.logs.shift();

  elements.streamCountBadge.textContent = state.logs.length + ' logs';

  const line = document.createElement('div');
  line.className = 'terminal-line';

  const methodClass = 'method-' + (log.requestType || 'GET');
  const statusClass = 'status-' + log.statusCode;

  line.innerHTML = `
    <span class="log-time">${log.timestamp}</span>
    <span class="log-method ${methodClass}">${log.requestType}</span>
    <span class="log-ip">${log.ipAddress}</span>
    <span class="log-status ${statusClass}">${log.statusCode}</span>
    <span class="log-payload">${escapeHtml(log.payload)}</span>
  `;

  // Remove placeholder if present
  if (elements.terminalStream.children.length === 1 && elements.terminalStream.children[0].textContent.includes('Waiting for log')) {
    elements.terminalStream.innerHTML = '';
  }

  elements.terminalStream.appendChild(line);

  if (state.autoScroll) {
    elements.terminalStream.scrollTop = elements.terminalStream.scrollHeight;
  }
}

// Threat Alert Matrix Render
function prependAlert(alert) {
  state.alerts.unshift(alert);
  renderAlertFeed(state.alerts);
}

function renderAlertFeed(alertList) {
  elements.alertCountBadge.textContent = alertList.length + ' alerts';

  if (!alertList.length) {
    elements.alertFeed.innerHTML = '<div class="terminal-line" style="color: var(--text-muted); justify-content: center; padding: 2rem 0;">No active threat alerts triggered yet.</div>';
    return;
  }

  elements.alertFeed.innerHTML = '';
  alertList.forEach(alert => {
    const card = document.createElement('div');
    const color = alert.severity === 'CRITICAL' ? 'var(--cyber-critical)' :
                  alert.severity === 'HIGH' ? '#fb7185' :
                  alert.severity === 'MEDIUM' ? '#fbbf24' : '#60a5fa';

    card.className = 'alert-card new-alert';
    card.style.setProperty('--alert-color', color);

    // Algorithm tag determination
    let algoTag = 'Boyer-Moore';
    if (alert.category === 'DIRECTORY_TRAVERSAL') algoTag = 'Prefix Trie';
    else if (alert.category === 'BRUTE_FORCE') algoTag = 'Sliding Window';
    else if (alert.category === 'TRAFFIC_ANOMALY') algoTag = 'Z-Score Anomaly';
    else if (alert.category === 'SUSPICIOUS_IP') algoTag = 'IP Reputation';

    card.innerHTML = `
      <div class="alert-top">
        <div class="alert-badges">
          <span class="severity-pill severity-${alert.severity}">${alert.severity}</span>
          <span class="algo-tag">[${algoTag}]</span>
          <span style="font-size: 0.72rem; font-weight: 700; color: #cbd5e1;">${alert.categoryDisplay || alert.category}</span>
        </div>
        <span class="risk-badge">Risk ${alert.riskScore}</span>
      </div>
      <div class="alert-desc">${escapeHtml(alert.description)}</div>
      <div class="alert-meta">
        <span>Target: <b class="alert-target">${alert.affectedSystem}</b></span>
        <span>IP: <b style="color: var(--cyber-cyan);">${alert.sourceIp}</b></span>
        <span>${alert.timestamp.split(' ')[1] || alert.timestamp}</span>
      </div>
    `;

    card.addEventListener('click', () => openAlertModal(alert));
    elements.alertFeed.appendChild(card);
  });
}

function renderCategoryBars(catStats) {
  elements.categoryBars.innerHTML = '';
  let total = 0;
  for (const cat in catStats) {
    total += catStats[cat];
  }

  if (total === 0) {
    elements.categoryBars.innerHTML = '<div style="font-size: 0.75rem; color: var(--text-muted);">No threat data accumulated yet.</div>';
    return;
  }

  for (const [category, count] of Object.entries(catStats)) {
    if (count === 0) continue;
    const pct = ((count / total) * 100).toFixed(0);
    const row = document.createElement('div');
    row.className = 'bar-row';
    row.innerHTML = `
      <div class="bar-labels">
        <span>${category}</span>
        <span>${count} (${pct}%)</span>
      </div>
      <div class="bar-track">
        <div class="bar-fill" style="width: ${pct}%; background: linear-gradient(90deg, var(--cyber-cyan), var(--cyber-purple));"></div>
      </div>
    `;
    elements.categoryBars.appendChild(row);
  }
}

// Threat Intel (IP Blacklist)
async function loadBlacklist() {
  try {
    const res = await fetch('/api/intel/blacklist');
    const data = await res.json();
    state.blacklist = data.blacklist || [];
    renderBlacklistTable(state.blacklist);
    elements.kpiBlacklistCount.textContent = state.blacklist.length;
  } catch (err) {
    console.error('Error loading blacklist:', err);
  }
}

function renderBlacklistTable(ips) {
  if (!ips.length) {
    elements.blacklistTableBody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--text-muted);">No blacklisted IPs found.</td></tr>';
    return;
  }

  elements.blacklistTableBody.innerHTML = '';
  ips.forEach(ip => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td style="color: var(--cyber-cyan); font-weight: 600;">${ip}</td>
      <td><span class="severity-pill severity-CRITICAL" style="font-size: 0.65rem;">BLOCKED (Threat Actor)</span></td>
      <td style="color: var(--cyber-rose); font-weight: 700;">+2.5 Severity Weight</td>
      <td>
        <button class="btn btn-danger btn-icon" title="Remove IP from blacklist" onclick="removeBlacklistIp('${ip}')">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <polyline points="3 6 5 6 21 6"/>
            <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>
          </svg>
        </button>
      </td>
    `;
    elements.blacklistTableBody.appendChild(tr);
  });
}

window.removeBlacklistIp = async function(ip) {
  try {
    const res = await fetch(`/api/intel/blacklist?ip=${encodeURIComponent(ip)}`, { method: 'DELETE' });
    const result = await res.json();
    if (result.success) {
      loadBlacklist();
      fetchStatus();
    }
  } catch (e) {
    console.error('Error removing IP:', e);
  }
};

// Incident Report
async function loadReport() {
  try {
    const res = await fetch('/api/report/markdown');
    const markdown = await res.text();
    elements.reportMarkdownPre.textContent = markdown;
  } catch (err) {
    elements.reportMarkdownPre.textContent = 'Failed to load incident report.';
  }
}

// Modal Inspection
function openAlertModal(alert) {
  state.activeAlertModal = alert;
  elements.modalSeverityPill.className = `severity-pill severity-${alert.severity}`;
  elements.modalSeverityPill.textContent = alert.severity;
  elements.modalRiskScore.textContent = `Risk: ${alert.riskScore} / 10.0`;
  elements.modalCategory.textContent = alert.categoryDisplay || alert.category;
  elements.modalIp.textContent = alert.sourceIp;
  elements.modalSystem.textContent = alert.affectedSystem;
  elements.modalDesc.textContent = alert.description;
  elements.modalPayload.textContent = alert.payload || '(None / Traffic Volume Trigger)';

  elements.alertModal.classList.add('open');
}

function closeAlertModal() {
  elements.alertModal.classList.remove('open');
  state.activeAlertModal = null;
}

// Event Listeners Setup
function setupEventListeners() {
  // Start simulation
  elements.btnStartSim.addEventListener('click', async () => {
    try {
      const logType = elements.logSourceSelect.value;
      const delayMs = parseInt(elements.delaySelect.value, 10);
      await fetch('/api/simulation/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ logType, delayMs })
      });
      setSimulatingUI(true);
    } catch (e) {
      console.error(e);
    }
  });

  // Stop simulation
  elements.btnStopSim.addEventListener('click', async () => {
    try {
      await fetch('/api/simulation/stop', { method: 'POST' });
      setSimulatingUI(false);
    } catch (e) {
      console.error(e);
    }
  });

  // Clear alerts
  elements.btnClearAlerts.addEventListener('click', async () => {
    if (confirm('Clear all ingested events, alert history, and statistics?')) {
      await fetch('/api/alerts/clear', { method: 'POST' });
    }
  });

  // Sound toggle
  elements.btnToggleSound.addEventListener('click', () => {
    state.soundEnabled = !state.soundEnabled;
    elements.soundIconOn.style.display = state.soundEnabled ? 'block' : 'none';
    elements.soundIconOff.style.display = state.soundEnabled ? 'none' : 'block';
  });

  // Stream controls
  elements.chkAutoScroll.addEventListener('change', (e) => {
    state.autoScroll = e.target.checked;
  });

  elements.btnClearStream.addEventListener('click', () => {
    state.logs = [];
    elements.terminalStream.innerHTML = '<div class="terminal-line" style="color: var(--text-muted); justify-content: center; padding: 2rem 0;">Stream display cleared.</div>';
    elements.streamCountBadge.textContent = '0 logs';
  });

  // Alert search
  elements.alertSearchInput.addEventListener('input', (e) => {
    fetchAlerts(e.target.value.trim());
  });

  // Tabs switching
  elements.tabButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const targetTab = btn.getAttribute('data-tab');
      elements.tabButtons.forEach(b => b.classList.remove('active'));
      elements.tabPanes.forEach(p => p.classList.remove('active'));

      btn.classList.add('active');
      document.getElementById(targetTab).classList.add('active');

      if (targetTab === 'tab-report') loadReport();
      if (targetTab === 'tab-intel') loadBlacklist();
    });
  });

  // Threshold sliders
  elements.rangeWindowSec.addEventListener('input', (e) => {
    elements.valWindowSec.textContent = e.target.value + ' seconds';
  });
  elements.rangeFailureThresh.addEventListener('input', (e) => {
    elements.valFailureThresh.textContent = e.target.value + ' failures';
  });
  elements.rangeZScore.addEventListener('input', (e) => {
    elements.valZScore.textContent = Number(e.target.value).toFixed(2) + ' σ';
  });

  elements.btnSaveThresholds.addEventListener('click', async () => {
    const slidingWindowSeconds = parseInt(elements.rangeWindowSec.value, 10);
    const failureThreshold = parseInt(elements.rangeFailureThresh.value, 10);
    const zScore = parseFloat(elements.rangeZScore.value);

    try {
      const res = await fetch('/api/thresholds', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ slidingWindowSeconds, failureThreshold, zScore })
      });
      const data = await res.json();
      if (data.success) {
        alert('Thresholds successfully applied to active detection engines!');
      }
    } catch (e) {
      alert('Error updating thresholds.');
    }
  });

  // Blacklist Add
  elements.btnAddBlacklist.addEventListener('click', async () => {
    const ip = elements.newIpInput.value.trim();
    if (!ip) return;
    try {
      const res = await fetch('/api/intel/blacklist', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip })
      });
      const data = await res.json();
      if (data.success) {
        elements.newIpInput.value = '';
        loadBlacklist();
        fetchStatus();
      } else {
        alert(data.error || 'Failed to add IP');
      }
    } catch (e) {
      console.error(e);
    }
  });

  elements.searchBlacklistInput.addEventListener('input', (e) => {
    const q = e.target.value.toLowerCase().trim();
    const filtered = state.blacklist.filter(ip => ip.toLowerCase().includes(q));
    renderBlacklistTable(filtered);
  });

  // Custom Payload Analyzer
  document.querySelectorAll('.payload-pill').forEach(btn => {
    btn.addEventListener('click', () => {
      elements.analyzerParserSelect.value = btn.getAttribute('data-type');
      elements.analyzerInput.value = btn.getAttribute('data-log');
    });
  });

  elements.btnRunAnalyzer.addEventListener('click', async () => {
    const logType = elements.analyzerParserSelect.value;
    const rawLog = elements.analyzerInput.value.trim();

    if (!rawLog) {
      alert('Please enter or select a raw log to analyze.');
      return;
    }

    try {
      const res = await fetch('/api/custom-log/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ logType, rawLog })
      });

      const data = await res.json();
      elements.analyzerResultBox.style.display = 'block';

      if (data.error) {
        elements.analyzerResultBox.innerHTML = `<span style="color: var(--cyber-rose);">[PARSER ERROR] ${escapeHtml(data.error)}</span>`;
        return;
      }

      if (data.threatDetected && data.alert) {
        const a = data.alert;
        elements.analyzerResultBox.innerHTML = `
          <div style="color: var(--cyber-critical); font-weight: 700; margin-bottom: 0.5rem; display: flex; align-items: center; gap: 0.5rem;">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>
            [ALERT TRIGGERED] ${escapeHtml(a.categoryDisplay)} (Severity: ${a.severity}, Risk: ${a.riskScore}/10)
          </div>
          <div style="color: var(--text-secondary); margin-bottom: 0.25rem;"><b>Reason:</b> ${escapeHtml(a.description)}</div>
          <div style="color: var(--text-muted); font-size: 0.75rem;">Source IP: <b style="color: var(--cyber-cyan);">${a.sourceIp}</b> | Target: <b>${a.affectedSystem}</b></div>
        `;
      } else {
        elements.analyzerResultBox.innerHTML = `
          <div style="color: var(--cyber-emerald); font-weight: 700; display: flex; align-items: center; gap: 0.5rem;">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
            [CLEAN] Parsed successfully. No signatures or rate anomalies detected.
          </div>
          <div style="color: var(--text-muted); font-size: 0.75rem; margin-top: 0.35rem;">Log Type: ${data.logEntry.logType} | IP: ${data.logEntry.ipAddress} | Method: ${data.logEntry.requestType} | Status: ${data.logEntry.statusCode}</div>
        `;
      }

    } catch (e) {
      console.error(e);
      elements.analyzerResultBox.style.display = 'block';
      elements.analyzerResultBox.innerHTML = `<span style="color: var(--cyber-rose);">Analysis failed: ${e.message}</span>`;
    }
  });

  // Report Actions
  elements.btnRefreshReport.addEventListener('click', loadReport);
  elements.btnDownloadReport.addEventListener('click', () => {
    const text = elements.reportMarkdownPre.textContent;
    const blob = new Blob([text], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `incident_report_${new Date().toISOString().slice(0, 10)}.md`;
    a.click();
    URL.revokeObjectURL(url);
  });

  // Modal Actions
  elements.btnCloseModal.addEventListener('click', closeAlertModal);
  elements.modalCloseBtn.addEventListener('click', closeAlertModal);
  elements.alertModal.addEventListener('click', (e) => {
    if (e.target === elements.alertModal) closeAlertModal();
  });

  elements.modalBlockIpBtn.addEventListener('click', async () => {
    if (state.activeAlertModal && state.activeAlertModal.sourceIp) {
      const ip = state.activeAlertModal.sourceIp;
      await fetch('/api/intel/blacklist', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip })
      });
      loadBlacklist();
      fetchStatus();
      closeAlertModal();
      alert(`Source IP ${ip} successfully added to active blacklist database.`);
    }
  });
}

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
}
