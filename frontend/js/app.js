/**
 * AI Network Attack Forecasting — Client Application
 * Handles navigation, dynamic API telemetry fetching, forward simulation, and SVG charts.
 */

// ── NAVIGATION HANDLER ──
const navItems = document.querySelectorAll('.nav-item');
const pages = document.querySelectorAll('.page');

navItems.forEach(item => {
  item.addEventListener('click', () => {
    navItems.forEach(n => n.classList.remove('active'));
    pages.forEach(p => p.classList.remove('active'));
    item.classList.add('active');
    const target = document.getElementById('page-' + item.dataset.page);
    if (target) target.classList.add('active');
  });
});

// ── LIVE CLOCK ──
function updateClock() {
  const now = new Date();
  const t = now.toTimeString().split(' ')[0] + ' IST';
  const el = document.getElementById('live-clock');
  if (el) el.textContent = t;
  const dt = document.getElementById('dossier-time');
  if (dt) dt.textContent = t;
}
setInterval(updateClock, 1000);
updateClock();

// ── API SERVICE & DYNAMIC DATA BINDING ──
const API = {
  async get(endpoint) {
    try {
      const res = await fetch(`/api/${endpoint}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    } catch (e) {
      console.warn(`API get /api/${endpoint} failed:`, e);
      return null;
    }
  },
  async post(endpoint, data) {
    try {
      const res = await fetch(`/api/${endpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    } catch (e) {
      console.warn(`API post /api/${endpoint} failed:`, e);
      return null;
    }
  }
};

// ── 01 FETCH THREAT OVERVIEW ──
async function loadThreatOverview() {
  const data = await API.get('threat-overview');
  if (!data) return;

  const probEl = document.getElementById('prob-val');
  if (probEl) probEl.innerHTML = `${data.infiltration_probability}<span>%</span>`;

  const statusEl = document.getElementById('threat-status');
  if (statusEl) {
    statusEl.textContent = `⚠ ${data.threat_level}`;
    statusEl.className = data.threat_level === 'HIGH RISK' ? 'th-status' : 'th-status ok';
  }

  const horizonEl = document.getElementById('fcst-horizon');
  if (horizonEl) horizonEl.textContent = data.forecast_horizon;

  const leadEl = document.getElementById('lead-time-sub');
  if (leadEl) leadEl.textContent = `+${data.lead_time_seconds}s ADVANCE`;

  const flowEl = document.getElementById('flow-count');
  if (flowEl) flowEl.textContent = Number(data.active_flows).toLocaleString();

  const synEl = document.getElementById('syn-ack-ratio');
  if (synEl) synEl.textContent = `${data.syn_ack_ratio}×`;

  const confEl = document.getElementById('model-conf');
  if (confEl) confEl.innerHTML = `${data.model_confidence}<span style="font-size:20px">%</span>`;
}

// ── 03 FETCH FORECAST TIMELINE ──
async function loadForecastTimeline() {
  const data = await API.get('forecast?k=5');
  if (!data || !data.predicted) return;

  // Render K-step table
  const tbody = document.getElementById('kstep-tbody');
  if (tbody) {
    tbody.innerHTML = data.predicted.map(p => `
      <tr class="${p.prob > 75 ? 'row-high' : 'row-med'}">
        <td>k = ${p.step}</td>
        <td>+${p.offset_seconds}s</td>
        <td>${p.stage}</td>
        <td class="risk-high">${p.prob}%</td>
        <td>TA0008</td>
        <td><span class="risk-badge h">${p.risk_level}</span></td>
        <td>+${p.offset_seconds}s</td>
      </tr>
    `).join('');
  }
}

// ── 07 FETCH EXPLAINABILITY (SHAP & ATTENTION) ──
async function loadExplainability() {
  const data = await API.get('explainability');
  if (!data || !data.top_features) return;

  const fr = document.getElementById('feature-rows');
  if (fr) {
    const maxVal = Math.max(...data.top_features.map(f => Math.abs(f.importance))) || 1.0;
    fr.innerHTML = data.top_features.map((f, i) => {
      const pct = (Math.abs(f.importance) / maxVal * 85).toFixed(1);
      const isPos = f.importance >= 0;
      const cls = isPos ? 'positive' : 'negative';
      const sign = isPos ? '+' : '';
      return `
        <div class="feature-row">
          <div class="fr-rank">${String(i + 1).padStart(2, '0')}</div>
          <div class="fr-name">${f.feature.replace(/_/g, ' ').toUpperCase()}</div>
          <div class="fr-bar-wrap"><div class="fr-bar ${cls}" style="width:${pct}%"></div></div>
          <div class="fr-val ${cls}">${sign}${f.importance.toFixed(2)}</div>
          <div class="fr-type">${f.category}</div>
        </div>
      `;
    }).join('');
  }
}

// ── 08 SIMULATION HANDLER ──
function updateSim() {
  document.getElementById('sim-syn-val').textContent = document.getElementById('sim-syn').value;
  document.getElementById('sim-entropy-val').textContent = document.getElementById('sim-entropy').value;
  document.getElementById('sim-k-val').textContent = document.getElementById('sim-k').value + ' steps';
}

async function runSimulation() {
  const btn = document.getElementById('sim-run-btn');
  const res = document.getElementById('sim-result');
  btn.classList.add('running');
  btn.textContent = 'RUNNING FORWARD ROLLOUT ON PYTORCH MODEL...';

  const syn = parseFloat(document.getElementById('sim-syn').value);
  const entropy = parseFloat(document.getElementById('sim-entropy').value);
  const k = parseInt(document.getElementById('sim-k').value);

  const data = await API.post('simulate', {
    syn_rate: syn,
    port_entropy: entropy,
    k_steps: k
  });

  btn.classList.remove('running');
  btn.textContent = '▶ RUN K-STEP PREDICTION';

  if (data && data.trajectory) {
    const seqStr = data.trajectory.map(t => `k${t.step}=${t.prob_pct}% (${t.stage})`).join(' → ');
    res.innerHTML = `<strong>PREDICTED TRAJECTORY:</strong> ${seqStr} &nbsp;|&nbsp; <span style="color:var(--red);font-weight:700">PEAK RISK: ${data.peak_risk_pct}%</span>`;
  } else {
    res.textContent = 'Simulation complete.';
  }
}

// ── 06 FETCH MITRE DATA ──
async function loadMitreData(tacticId = 'TA0001') {
  const data = await API.get(`mitre?tactic=${tacticId}`);
  if (!data) return;

  const nextContainer = document.getElementById('mitre-next-steps');
  if (nextContainer && data.next_tactics) {
    nextContainer.innerHTML = data.next_tactics.map(n => `
      <div style="margin-bottom:8px">
        <div style="display:flex;justify-content:space-between;font-family:'JetBrains Mono',monospace;font-size:10px">
          <strong>${n.tactic_name}</strong>
          <span>${(n.probability * 100).toFixed(1)}% (${n.transition_count}x)</span>
        </div>
        <div style="background:var(--cream-3);height:6px;margin-top:3px">
          <div style="background:var(--red);height:100%;width:${(n.probability * 100).toFixed(1)}%"></div>
        </div>
      </div>
    `).join('');
  }
}

// ── 09 FETCH BENCHMARK DATA ──
async function loadBenchmark() {
  const data = await API.get('benchmark');
  if (!data || !data.models) return;
  console.log('Loaded benchmark models:', data.models);
}

// ── 05 TRAFFIC FLOWS FILTER ──
const flows = [
  { ts:'14:31:42.103', src:'10.0.2.15', dst:'192.168.1.42', port:'445', proto:'TCP', flags:'SYN', pkts:12, bytes:'1,440', dur:'0.24s', risk:'h', cat:'suspicious,tcp,high,scan' },
  { ts:'14:31:42.229', src:'10.0.2.15', dst:'10.10.1.5', port:'445', proto:'TCP', flags:'SYN', pkts:8, bytes:'960', dur:'0.18s', risk:'h', cat:'suspicious,tcp,high,scan' },
  { ts:'14:31:43.011', src:'192.168.1.42', dst:'10.10.1.20', port:'3306', proto:'TCP', flags:'SYN ACK', pkts:24, bytes:'3,200', dur:'1.2s', risk:'m', cat:'suspicious,tcp' },
  { ts:'14:31:44.512', src:'10.0.2.15', dst:'10.10.1.21', port:'3306', proto:'TCP', flags:'SYN', pkts:6, bytes:'720', dur:'0.12s', risk:'h', cat:'suspicious,tcp,high,scan' },
  { ts:'14:31:45.002', src:'10.10.2.5', dst:'8.8.8.8', port:'53', proto:'UDP', flags:'—', pkts:2, bytes:'128', dur:'0.04s', risk:'l', cat:'udp' },
  { ts:'14:31:45.218', src:'192.168.1.10', dst:'10.0.2.15', port:'443', proto:'TCP', flags:'PSH ACK', pkts:45, bytes:'12,480', dur:'2.4s', risk:'m', cat:'suspicious,tcp' },
  { ts:'14:31:46.001', src:'10.0.2.15', dst:'10.10.2.6', port:'445', proto:'TCP', flags:'SYN', pkts:9, bytes:'1,080', dur:'0.19s', risk:'h', cat:'suspicious,tcp,high,scan' },
  { ts:'14:31:47.103', src:'10.10.2.5', dst:'10.10.1.5', port:'88', proto:'TCP', flags:'SYN', pkts:3, bytes:'360', dur:'0.08s', risk:'l', cat:'tcp' }
];

function renderFlows(filter = 'all') {
  const tbody = document.getElementById('flow-tbody');
  if (!tbody) return;
  const filtered = flows.filter(f => filter === 'all' || f.cat.includes(filter));
  tbody.innerHTML = filtered.map(f => `
    <tr class="${f.risk === 'h' ? 'row-high' : (f.risk === 'm' ? 'row-med' : '')}">
      <td>${f.ts}</td>
      <td>${f.src}</td>
      <td>${f.dst}</td>
      <td>${f.port}</td>
      <td>${f.proto}</td>
      <td>${f.flags}</td>
      <td>${f.pkts}</td>
      <td>${f.bytes}</td>
      <td>${f.dur}</td>
      <td><span class="risk-badge ${f.risk}">${f.risk === 'h' ? 'HIGH' : (f.risk === 'm' ? 'MED' : 'LOW')}</span></td>
    </tr>
  `).join('');
}

function filterFlows(cat, btn) {
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  renderFlows(cat);
}

// ── NODE TOOLTIPS ──
const nodeData = {
  attacker: "SRC: 10.0.2.15 (EXTERNAL THREAT ACTOR)\nSTATUS: ACTIVE ATTACKER\nFLAGS: TCP SYN FLOOD / SCAN\nFLOWS: 2,841 ACTIVE",
  gateway: "IP: 172.16.0.1\nTYPE: PERIMETER FIREWALL / GATEWAY\nSTATUS: TRAFFIC PASSING",
  target: "DST: 192.168.1.42\nSTATUS: COMPROMISED HOST\nTECHNIQUE: T1059 SCRIPT EXECUTION\nRISK: CRITICAL",
  dc: "IP: 10.10.1.5 (PORT 445 SMB)\nTYPE: DOMAIN CONTROLLER\nSTATUS: TARGET OF LATERAL SCAN\nRISK: HIGH",
  db: "IP: 10.10.1.20 (PORT 3306)\nTYPE: DATABASE SERVER\nSTATUS: MONITORED",
  h3: "IP: 10.10.1.21\nTYPE: BACKUP DB\nSTATUS: BEING SCANNED"
};

const tooltip = document.getElementById('node-tooltip');
document.querySelectorAll('.net-node').forEach(node => {
  node.addEventListener('mouseenter', e => {
    const id = node.dataset.id;
    if (nodeData[id]) {
      tooltip.textContent = nodeData[id];
      tooltip.style.display = 'block';
    }
  });
  node.addEventListener('mousemove', e => {
    const cont = document.getElementById('network-svg-container');
    const rect = cont.getBoundingClientRect();
    let x = e.clientX - rect.left + 15;
    let y = e.clientY - rect.top + 15;
    if (x + 200 > rect.width) x -= 215;
    tooltip.style.left = x + 'px';
    tooltip.style.top = y + 'px';
  });
  node.addEventListener('mouseleave', () => { tooltip.style.display = 'none'; });
});

// ── LIVE SCENARIO INGESTION ──
async function loadScenario(scenarioName, btn) {
  document.querySelectorAll('#main .filter-btn').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');

  const label = document.getElementById('current-scenario-label');
  if (label) label.textContent = `${scenarioName.toUpperCase()} (ANALYZING...)`;

  const data = await API.get(`scenario?name=${scenarioName}`);
  if (data && !data.error) {
    if (label) label.textContent = `${scenarioName.toUpperCase()} (${data.filename}) — ${data.records_analyzed} FLOWS LOADED`;
    await loadThreatOverview();
    await loadForecastTimeline();
    await loadExplainability();
  } else {
    if (label) label.textContent = `ERROR LOADING ${scenarioName.toUpperCase()}`;
  }
}

// ── JSON DOSSIER EXPORT ──
async function exportJsonReport() {
  const overview = await API.get('threat-overview');
  const forecast = await API.get('forecast');
  const explain = await API.get('explainability');

  const report = {
    dossier_id: "NWF-28491",
    classification: "RESTRICTED // CYBER DEFENSE INTELLIGENCE",
    timestamp: new Date().toISOString(),
    system: "Causal World Model NIDS (SIH PS #26153)",
    threat_overview: overview,
    forecast_trajectory: forecast,
    explainability: explain,
    proactive_defensive_playbook: [
      "Isolate compromised host 192.168.1.42",
      "Block inbound SMB/RPC TCP 445 on edge router",
      "Revoke Kerberos TGT tickets for Domain Admin credentials",
      "Quarantine subnet 10.10.1.0/24"
    ]
  };

  const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `incident_dossier_NWF28491_${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

// ── INITIAL DATA BOOTSTRAP ──
window.addEventListener('DOMContentLoaded', () => {
  loadThreatOverview();
  loadForecastTimeline();
  loadExplainability();
  loadMitreData('TA0001');
  loadBenchmark();
  renderFlows('all');

  // Auto-refresh telemetry every 10 seconds
  setInterval(loadThreatOverview, 10000);
});
