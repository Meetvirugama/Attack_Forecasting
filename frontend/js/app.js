/**
 * CyberLens — Frontend Application
 * Fetches data from the local REST API and renders all 6 dashboard tabs.
 * Written in plain ES6 JavaScript — no external libraries required.
 */

const API = 'http://localhost:8000/api';

// ── STATE ─────────────────────────────────────────────────────────────────────
let currentScenario = 'infiltration';
let overviewData    = null;
let forecastData    = null;
let explainData     = null;
let mitreData       = null;
let benchmarkData   = null;

// ── BOOT ──────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  startClock();
  refreshAll();
});

function startClock() {
  const el = document.getElementById('headerTime');
  const tick = () => {
    const now = new Date();
    el.textContent = now.toLocaleTimeString('en-GB', { hour12: false });
  };
  tick();
  setInterval(tick, 1000);
}

// ── TAB SWITCHING ─────────────────────────────────────────────────────────────
function showTab(name) {
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
  document.getElementById('nav-' + name).classList.add('active');

  // Set active nav icon
  document.querySelectorAll('.nav-btn').forEach(b => {
    const icon = b.querySelector('.nav-icon');
    if (icon) icon.textContent = b.classList.contains('active') ? '◈' : '⬡';
  });

  // Lazy-draw charts when tab becomes visible
  if (name === 'forecast' && forecastData)   drawForecastChart(forecastData);
  if (name === 'explain'  && explainData)    drawFeatureChart(explainData);
  if (name === 'compare'  && benchmarkData)  drawCompareChart(benchmarkData);
}

// ── SCENARIO SWITCHING ────────────────────────────────────────────────────────
function loadScenario(name) {
  currentScenario = name;
  document.querySelectorAll('.scenario-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('btn-' + name).classList.add('active');
  setStatus('LOADING...', false);
  refreshAll();
}

// ── REFRESH ALL DATA ──────────────────────────────────────────────────────────
async function refreshAll() {
  setStatus('LOADING...', false);

  try {
    // Load scenario first, then refresh overview / forecast / explain concurrently
    const scenarioRes = await fetchJson(`${API}/scenario?name=${currentScenario}`);
    if (scenarioRes.error) throw new Error(scenarioRes.error);

    overviewData = scenarioRes.overview;
    forecastData = scenarioRes.forecast;
    explainData  = scenarioRes.explainability;

    renderOverview(overviewData);
    renderForecast(forecastData);
    renderExplain(explainData);

    // MITRE & benchmark can load independently
    const tactic = overviewData?.mitre_tactic_current || 'TA0001';
    [mitreData, benchmarkData] = await Promise.all([
      fetchJson(`${API}/mitre?tactic=${tactic}`),
      fetchJson(`${API}/benchmark`)
    ]);

    renderKillChain(mitreData, overviewData);
    renderBenchmark(benchmarkData);

    setStatus('LIVE', true);
  } catch (err) {
    console.warn('API error:', err);
    setStatus('OFFLINE — using demo data', false);
    loadDemoData();
  }
}

// ── STATUS ────────────────────────────────────────────────────────────────────
function setStatus(text, ok) {
  document.getElementById('statusText').textContent = text;
  const dot = document.getElementById('statusDot');
  dot.style.background    = ok ? 'var(--green)' : 'var(--amber)';
  dot.style.boxShadow     = ok ? '0 0 8px var(--green)' : '0 0 8px var(--amber)';
}

// ── FETCH HELPER ──────────────────────────────────────────────────────────────
async function fetchJson(url) {
  const r = await fetch(url);
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

// ── OVERVIEW ──────────────────────────────────────────────────────────────────
function renderOverview(d) {
  if (!d) return;

  const risk = d.infiltration_probability ?? 0;
  document.getElementById('riskVal').textContent  = risk.toFixed(1) + '%';
  document.getElementById('riskBar').style.width  = Math.min(risk, 100) + '%';

  document.getElementById('stageVal').textContent    = d.current_stage    ?? '—';
  document.getElementById('nextStageVal').textContent = 'Next → ' + (d.predicted_next_stage ?? '—');
  document.getElementById('leadVal').textContent     = (d.lead_time_seconds ?? '—') + 's';
  document.getElementById('flowsVal').textContent    = (d.active_flows ?? '—').toLocaleString();
  document.getElementById('suspiciousVal').textContent = (d.suspicious_nodes ?? '—') + ' suspicious nodes';

  document.getElementById('overviewCaseId').textContent = 'CASE: ' + (d.case_id ?? 'CL-0001');

  document.getElementById('mStatus').textContent   = d.status      ?? '—';
  document.getElementById('mModel').textContent    = d.model_name  ?? '—';
  document.getElementById('mDataset').textContent  = d.dataset     ?? '—';
  document.getElementById('mConf').textContent     = (d.model_confidence ?? '—') + '%';
  document.getElementById('mTacticNow').textContent  = d.mitre_tactic_current  ?? '—';
  document.getElementById('mTacticNext').textContent = d.mitre_tactic_predicted ?? '—';
  document.getElementById('mSynAck').textContent   = d.syn_ack_ratio ?? '—';
  document.getElementById('mHorizon').textContent  = d.forecast_horizon ?? '—';

  // Campaigns
  const campaigns = d.observed_campaigns ?? [];
  document.getElementById('campaignList').innerHTML = campaigns.length
    ? campaigns.map(c => `<div class="campaign-tag">${c}</div>`).join('')
    : '<span class="muted">—</span>';

  // Threat meter
  document.getElementById('threatFill').style.width = Math.min(risk, 100) + '%';
  const threatLevel = d.threat_level ?? 'LOW';
  const tagEl = document.getElementById('threatTag');
  tagEl.textContent = threatLevel;
  tagEl.style.color = risk > 70 ? 'var(--red)' : risk > 40 ? 'var(--amber)' : 'var(--green-dim)';
  tagEl.style.borderColor = tagEl.style.color;
}

// ── FORECAST ──────────────────────────────────────────────────────────────────
function renderForecast(d) {
  if (!d) return;

  document.getElementById('fcLeadTime').textContent = (d.lead_time_seconds ?? '—') + 's';
  document.getElementById('fcPeakRisk').textContent = (d.max_risk_score ?? '—') + '%';

  // Historical list
  const histEl = document.getElementById('histList');
  histEl.innerHTML = (d.historical ?? []).map(h =>
    `<div class="step-row">
       <span class="step-time">${h.time}</span>
       <span class="step-stage">${h.stage}</span>
       <span class="step-risk">${h.prob.toFixed(1)}%</span>
     </div>`
  ).join('');

  // Predicted list
  const predEl = document.getElementById('predList');
  predEl.innerHTML = (d.predicted ?? []).map(p =>
    `<div class="step-row predicted">
       <span class="step-time">${p.time_label}</span>
       <span class="step-stage">${p.stage}</span>
       <span class="step-risk">${p.prob}%</span>
     </div>`
  ).join('');

  // Draw chart if tab is active
  const panel = document.getElementById('tab-forecast');
  if (panel.classList.contains('active')) drawForecastChart(d);
}

function drawForecastChart(d) {
  const canvas = document.getElementById('forecastChart');
  const ctx = canvas.getContext('2d');
  canvas.width  = canvas.offsetWidth  * window.devicePixelRatio;
  canvas.height = canvas.offsetHeight * window.devicePixelRatio;
  ctx.scale(window.devicePixelRatio, window.devicePixelRatio);

  const W = canvas.offsetWidth, H = canvas.offsetHeight;
  const PAD = { top: 20, right: 20, bottom: 36, left: 50 };
  const plotW = W - PAD.left - PAD.right;
  const plotH = H - PAD.top  - PAD.bottom;

  ctx.clearRect(0, 0, W, H);

  const hist = (d.historical ?? []).map(h => h.prob);
  const pred = (d.predicted  ?? []).map(p => p.prob);
  const allPts = [...hist, ...pred];
  const labels = [
    ...(d.historical ?? []).map(h => h.time),
    ...(d.predicted  ?? []).map(p => p.time_label)
  ];

  const minY = 0, maxY = 105;
  const toX  = i => PAD.left + (i / (allPts.length - 1)) * plotW;
  const toY  = v => PAD.top  + (1 - (v - minY) / (maxY - minY)) * plotH;

  // Grid
  ctx.strokeStyle = '#1f3320';
  ctx.lineWidth = 1;
  for (let y = 0; y <= 100; y += 25) {
    const py = toY(y);
    ctx.beginPath();
    ctx.moveTo(PAD.left, py);
    ctx.lineTo(PAD.left + plotW, py);
    ctx.stroke();
    ctx.fillStyle = '#3a5a3a';
    ctx.font = '10px JetBrains Mono';
    ctx.fillText(y + '%', PAD.left - 36, py + 4);
  }

  // NOW divider
  const nowX = toX(hist.length - 1);
  ctx.strokeStyle = '#3a5a3a';
  ctx.setLineDash([4, 4]);
  ctx.beginPath();
  ctx.moveTo(nowX, PAD.top);
  ctx.lineTo(nowX, PAD.top + plotH);
  ctx.stroke();
  ctx.setLineDash([]);
  ctx.fillStyle = '#3a5a3a';
  ctx.font = '9px JetBrains Mono';
  ctx.fillText('NOW', nowX + 4, PAD.top + 10);

  // Historical line (green)
  if (hist.length > 0) {
    ctx.strokeStyle = '#00c832';
    ctx.lineWidth = 2;
    ctx.shadowColor = '#00ff41';
    ctx.shadowBlur = 6;
    ctx.beginPath();
    hist.forEach((v, i) => {
      const x = toX(i), y = toY(v);
      i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
    });
    ctx.stroke();
    ctx.shadowBlur = 0;

    // Dots
    hist.forEach((v, i) => {
      ctx.beginPath();
      ctx.arc(toX(i), toY(v), 3, 0, Math.PI * 2);
      ctx.fillStyle = '#00c832';
      ctx.fill();
    });
  }

  // Predicted line (red dashed)
  if (pred.length > 0) {
    const offset = hist.length - 1;
    ctx.strokeStyle = '#ef4444';
    ctx.lineWidth = 2;
    ctx.setLineDash([6, 3]);
    ctx.shadowColor = '#ef4444';
    ctx.shadowBlur = 6;
    ctx.beginPath();
    [hist[hist.length - 1], ...pred].forEach((v, i) => {
      const x = toX(offset + i), y = toY(v);
      i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
    });
    ctx.stroke();
    ctx.setLineDash([]);
    ctx.shadowBlur = 0;

    pred.forEach((v, i) => {
      ctx.beginPath();
      ctx.arc(toX(offset + i + 1), toY(v), 3, 0, Math.PI * 2);
      ctx.fillStyle = '#ef4444';
      ctx.fill();
    });
  }

  // X labels
  ctx.fillStyle = '#3a5a3a';
  ctx.font = '9px JetBrains Mono';
  labels.forEach((lbl, i) => {
    if (i % 2 === 0 || i === labels.length - 1) {
      ctx.fillText(lbl, toX(i) - 10, PAD.top + plotH + 16);
    }
  });

  // Legend
  ctx.fillStyle = '#00c832'; ctx.fillRect(W - 150, 8, 12, 3);
  ctx.fillStyle = '#6b9b6b'; ctx.font = '9px JetBrains Mono';
  ctx.fillText('Observed', W - 134, 12);
  ctx.fillStyle = '#ef4444'; ctx.fillRect(W - 60, 8, 12, 3);
  ctx.fillText('AI Forecast', W - 44, 12);
}

// ── KILL CHAIN ────────────────────────────────────────────────────────────────
const STAGES = [
  { idx: 0, name: 'Normal',      tactic: '—'       },
  { idx: 1, name: 'Recon',       tactic: 'TA0043'  },
  { idx: 2, name: 'Init Access', tactic: 'TA0001'  },
  { idx: 3, name: 'Lateral Mvt', tactic: 'TA0008'  },
  { idx: 4, name: 'C2',          tactic: 'TA0011'  },
  { idx: 5, name: 'Exfil',       tactic: 'TA0010'  },
];

function renderKillChain(mitreD, overviewD) {
  const currentTactic = overviewD?.mitre_tactic_current  ?? 'TA0001';
  const nextTactic    = overviewD?.mitre_tactic_predicted ?? 'TA0008';

  const stagesEl = document.getElementById('chainStages');
  stagesEl.innerHTML = STAGES.map((s, i) => {
    const isActive    = s.tactic === currentTactic;
    const isPredicted = s.tactic === nextTactic;
    const cls = isActive ? 'active' : isPredicted ? 'predicted' : '';
    const arrow = i < STAGES.length - 1 ? '<span class="stage-arrow">→</span>' : '';
    return `
      <div class="stage-block">
        <div class="stage-box ${cls}">
          <div class="stage-idx">[${String(s.idx).padStart(2,'0')}]</div>
          <div class="stage-name">${s.name}</div>
          <div class="stage-tactic">${s.tactic}</div>
        </div>
        ${arrow}
      </div>`;
  }).join('');

  if (!mitreD) return;

  // Next tactics
  const nextTactics = mitreD.next_tactics ?? [];
  document.getElementById('nextTacticsList').innerHTML = nextTactics.slice(0, 6).map(t =>
    `<div class="tactic-row">
       <span class="tactic-id">${t.tactic_id ?? '—'}</span>
       <span class="tactic-name">${t.name ?? '—'}</span>
       <span class="tactic-prob">${((t.probability ?? 0) * 100).toFixed(0)}%</span>
     </div>`
  ).join('') || '<span class="muted">No data</span>';

  // Forecast chains
  const chains = mitreD.forecast_chains ?? [];
  document.getElementById('forecastChains').innerHTML = chains.slice(0, 3).map((ch, i) => {
    const steps = Array.isArray(ch.chain) ? ch.chain.join(' → ') : (ch.chain ?? '—');
    const prob  = ((ch.probability ?? 0) * 100).toFixed(1);
    return `<div class="chain-row">[${i+1}] ${steps} <span style="color:var(--amber);">(${prob}%)</span></div>`;
  }).join('') || '<span class="muted">No data</span>';

  // Context
  const ctx = mitreD.campaign_context ?? {};
  document.getElementById('campaignContext').innerHTML =
    `Tactic: <span style="color:var(--green-dim)">${ctx.tactic_id ?? '—'}</span> &nbsp;|&nbsp;
     Campaigns: <span style="color:var(--green-dim)">${ctx.campaign_count ?? '—'}</span> &nbsp;|&nbsp;
     Severity: <span style="color:var(--amber)">${ctx.avg_severity ?? '—'}/100</span><br/>
     Examples: ${(ctx.example_campaigns ?? []).join(', ') || '—'}`;
}

// ── EXPLAIN ───────────────────────────────────────────────────────────────────
function renderExplain(d) {
  if (!d) return;

  // Attention heatmap
  const weights = d.attention_weights ?? Array(10).fill(0.1);
  const maxW    = Math.max(...weights, 0.001);
  const gridEl  = document.getElementById('attentionGrid');
  gridEl.innerHTML = weights.map((w, i) => {
    const alpha = Math.round((w / maxW) * 200);
    const color = `rgba(0,200,50,${(w / maxW).toFixed(2)})`;
    return `<div class="attn-cell" style="background:${color};" title="T-${9-i}: weight=${w.toFixed(3)}"></div>`;
  }).join('');

  document.getElementById('outcomeBox').textContent =
    '▶ ' + (d.target_prediction ?? 'Unknown prediction');

  // Chart
  const panel = document.getElementById('tab-explain');
  if (panel.classList.contains('active')) drawFeatureChart(d);
}

function drawFeatureChart(d) {
  const canvas = document.getElementById('featureChart');
  const ctx = canvas.getContext('2d');
  canvas.width  = canvas.offsetWidth  * window.devicePixelRatio;
  canvas.height = canvas.offsetHeight * window.devicePixelRatio;
  ctx.scale(window.devicePixelRatio, window.devicePixelRatio);

  const W = canvas.offsetWidth, H = canvas.offsetHeight;
  const features = (d.top_features ?? []).slice(0, 10);
  if (!features.length) return;

  const PAD  = { top: 10, right: 20, bottom: 10, left: 160 };
  const barH = Math.floor((H - PAD.top - PAD.bottom) / features.length) - 3;
  const maxImp = Math.max(...features.map(f => f.importance), 0.001);

  ctx.clearRect(0, 0, W, H);

  features.forEach((f, i) => {
    const y    = PAD.top + i * (barH + 3);
    const barW = ((f.importance / maxImp) * (W - PAD.left - PAD.right));

    // Label
    ctx.fillStyle = '#6b9b6b';
    ctx.font = `${Math.min(barH, 11)}px JetBrains Mono`;
    ctx.textAlign = 'right';
    ctx.fillText(f.feature ?? '—', PAD.left - 6, y + barH * 0.7);

    // Bar background
    ctx.fillStyle = '#162016';
    ctx.fillRect(PAD.left, y, W - PAD.left - PAD.right, barH);

    // Bar fill (gradient green → amber on high)
    const pct = f.importance / maxImp;
    ctx.fillStyle = pct > 0.7 ? '#f59e0b' : '#00c832';
    ctx.fillRect(PAD.left, y, barW, barH);

    // Value
    ctx.fillStyle = '#c8e6c8';
    ctx.font = `${Math.min(barH, 10)}px JetBrains Mono`;
    ctx.textAlign = 'left';
    ctx.fillText(f.importance.toFixed(4), PAD.left + barW + 4, y + barH * 0.7);
  });

  ctx.textAlign = 'left';
}

// ── BENCHMARK ─────────────────────────────────────────────────────────────────
function renderBenchmark(d) {
  if (!d || !d.models) return;
  benchmarkData = d;

  const tbody = document.getElementById('compareBody');
  tbody.innerHTML = d.models.map(row => {
    const isCyber = (row.Model ?? '').toLowerCase().includes('world');
    const cls     = isCyber ? 'class="highlight"' : '';
    const acc  = row.Accuracy   != null ? (row.Accuracy   * 100).toFixed(2) + '%' : (row['Accuracy']   ?? '—');
    const f1   = row['F1-Score']!= null ? (row['F1-Score']* 100).toFixed(2) + '%' : '—';
    const auc  = row['ROC-AUC'] != null ? (row['ROC-AUC'] * 100).toFixed(2) + '%' : '—';
    const fpr  = row['FPR']     != null ? row['FPR']      : '—';
    const lt   = row['Lead-Time']?? row['lead_time'] ?? '—';
    return `<tr ${cls}>
      <td>${row.Model ?? '—'}</td>
      <td>${acc}</td><td>${f1}</td><td>${auc}</td><td>${fpr}</td>
      <td style="color:${isCyber?'var(--green)':'var(--muted)'}">${lt}</td>
    </tr>`;
  }).join('');

  const panel = document.getElementById('tab-compare');
  if (panel.classList.contains('active')) drawCompareChart(d);
}

function drawCompareChart(d) {
  const canvas = document.getElementById('compareChart');
  const ctx = canvas.getContext('2d');
  canvas.width  = canvas.offsetWidth  * window.devicePixelRatio;
  canvas.height = canvas.offsetHeight * window.devicePixelRatio;
  ctx.scale(window.devicePixelRatio, window.devicePixelRatio);

  const W = canvas.offsetWidth, H = canvas.offsetHeight;
  const models   = d.models ?? [];
  const leadTimes= models.map(m => {
    const lt = m['Lead-Time'] ?? m['lead_time'] ?? '0s';
    return parseFloat(String(lt).replace(/[^0-9.]/g,'')) || 0;
  });
  const names = models.map(m => (m.Model ?? '?').replace('Causal World Model','CyberLens'));

  if (!leadTimes.length) return;
  ctx.clearRect(0, 0, W, H);

  const PAD  = { top:20, right:20, bottom:30, left:160 };
  const barH = Math.floor((H - PAD.top - PAD.bottom) / leadTimes.length) - 4;
  const maxV = Math.max(...leadTimes, 1);

  leadTimes.forEach((v, i) => {
    const y    = PAD.top + i * (barH + 4);
    const barW = (v / maxV) * (W - PAD.left - PAD.right);

    // Label
    ctx.fillStyle = '#6b9b6b';
    ctx.font = `${Math.min(barH, 11)}px JetBrains Mono`;
    ctx.textAlign = 'right';
    ctx.fillText(names[i] ?? '—', PAD.left - 6, y + barH * 0.72);

    // BG
    ctx.fillStyle = '#162016';
    ctx.fillRect(PAD.left, y, W - PAD.left - PAD.right, barH);

    // Fill
    ctx.fillStyle = v > 0 ? '#00c832' : '#3a5a3a';
    ctx.fillRect(PAD.left, y, barW || 4, barH);

    // Label
    ctx.fillStyle = '#c8e6c8';
    ctx.font = `10px JetBrains Mono`;
    ctx.textAlign = 'left';
    ctx.fillText(v > 0 ? `+${v}s` : '0s (reactive)', PAD.left + (barW || 6) + 4, y + barH * 0.72);
  });
  ctx.textAlign = 'left';
}

// ── SIMULATION ────────────────────────────────────────────────────────────────
async function runSimulate() {
  const btn = document.getElementById('runSimBtn');
  btn.disabled = true;
  btn.textContent = '// running...';

  const payload = {
    syn_rate:     parseFloat(document.getElementById('synSlider').value),
    port_entropy: parseFloat(document.getElementById('entSlider').value),
    k_steps:      parseInt(document.getElementById('kSlider').value),
  };

  try {
    const r = await fetch(`${API}/simulate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await r.json();

    const resEl = document.getElementById('simResults');
    const traj  = data.trajectory ?? [];
    resEl.innerHTML =
      `<div class="sim-row"><span class="sim-label">SYN RATE INPUT</span><span class="sim-val">${data.syn_rate_input}</span></div>
       <div class="sim-row"><span class="sim-label">PORT ENTROPY INPUT</span><span class="sim-val">${data.port_entropy_input}</span></div>
       <div class="sim-row"><span class="sim-label">PEAK RISK</span><span class="sim-val ${data.peak_risk_pct > 65 ? 'high' : ''}">${data.peak_risk_pct}%</span></div>
       <div class="sim-row"><span class="sim-label">LEAD TIME</span><span class="sim-val">${data.lead_time_seconds ?? 'N/A'}s</span></div>` +
       traj.map(s =>
         `<div class="sim-row"><span class="sim-label">STEP ${s.step}</span>
          <span class="sim-val ${s.prob_pct > 65 ? 'high' : ''}">${s.prob_pct}%</span>
          <span class="sim-label">${s.stage}</span></div>`
       ).join('');

    drawSimChart(traj);
  } catch (err) {
    document.getElementById('simResults').innerHTML =
      '<span class="red">// error: could not connect to API</span>';
  }

  btn.disabled = false;
  btn.textContent = '▶ RUN SIMULATION';
}

function drawSimChart(traj) {
  const canvas = document.getElementById('simChart');
  const ctx = canvas.getContext('2d');
  canvas.width  = canvas.offsetWidth  * window.devicePixelRatio;
  canvas.height = canvas.offsetHeight * window.devicePixelRatio;
  ctx.scale(window.devicePixelRatio, window.devicePixelRatio);

  const W = canvas.offsetWidth, H = canvas.offsetHeight;
  if (!traj.length) return;

  const PAD  = { top: 16, right: 20, bottom: 28, left: 46 };
  const vals = traj.map(s => s.prob_pct);
  const toX  = i => PAD.left + (i / (vals.length - 1 || 1)) * (W - PAD.left - PAD.right);
  const toY  = v => PAD.top  + (1 - v / 105) * (H - PAD.top - PAD.bottom);

  ctx.clearRect(0, 0, W, H);

  // Grid
  [0, 25, 50, 75, 100].forEach(y => {
    const py = toY(y);
    ctx.strokeStyle = '#1f3320';
    ctx.lineWidth   = 1;
    ctx.beginPath(); ctx.moveTo(PAD.left, py); ctx.lineTo(W - PAD.right, py); ctx.stroke();
    ctx.fillStyle = '#3a5a3a';
    ctx.font = '9px JetBrains Mono';
    ctx.fillText(y + '%', 2, py + 3);
  });

  // Line
  ctx.strokeStyle = '#00c832';
  ctx.lineWidth = 2;
  ctx.shadowColor = '#00ff41'; ctx.shadowBlur = 6;
  ctx.beginPath();
  vals.forEach((v, i) => i === 0 ? ctx.moveTo(toX(i), toY(v)) : ctx.lineTo(toX(i), toY(v)));
  ctx.stroke();
  ctx.shadowBlur = 0;

  vals.forEach((v, i) => {
    ctx.beginPath();
    ctx.arc(toX(i), toY(v), 4, 0, Math.PI * 2);
    ctx.fillStyle = v > 65 ? '#ef4444' : '#00c832';
    ctx.fill();
    ctx.fillStyle = '#6b9b6b';
    ctx.font = '8px JetBrains Mono';
    ctx.fillText('S' + traj[i].step, toX(i) - 5, H - 8);
  });
}

// ── DEMO DATA (no backend) ────────────────────────────────────────────────────
function loadDemoData() {
  overviewData = {
    case_id: 'CL-DEMO-001', status: 'DEMO MODE', classification: '—',
    model_name: 'LSTM+ATTENTION', dataset: 'CIC-IDS-2017',
    infiltration_probability: 74.2, threat_level: 'HIGH RISK',
    forecast_horizon: '+10s (K=5)', lead_time_seconds: 18.4,
    active_flows: 1842, suspicious_nodes: 5, syn_ack_ratio: 4.2,
    model_confidence: 93.1, current_stage: 'EXECUTION',
    predicted_next_stage: 'LATERAL MOVEMENT',
    mitre_tactic_current: 'TA0002', mitre_tactic_predicted: 'TA0008',
    observed_campaigns: ['Conti', 'SolarWinds', 'NotPetya'],
  };

  forecastData = {
    historical: [
      { time:'T-30m', prob:18.0, stage:'Normal' },
      { time:'T-20m', prob:22.5, stage:'Recon' },
      { time:'T-10m', prob:28.0, stage:'Recon' },
      { time:'T-5m',  prob:36.0, stage:'Init Access' },
      { time:'NOW',   prob:44.0, stage:'Execution' },
    ],
    predicted: [
      { step:1, time_label:'+5m',  prob:58.0, stage:'Lateral Mvt' },
      { step:2, time_label:'+10m', prob:71.0, stage:'Lateral Mvt' },
      { step:3, time_label:'+15m', prob:82.0, stage:'C2' },
      { step:4, time_label:'+20m', prob:91.0, stage:'C2' },
      { step:5, time_label:'+25m', prob:96.0, stage:'Exfil' },
    ],
    lead_time_seconds: 18.4,
    max_risk_score: 96.0,
  };

  explainData = {
    top_features: [
      { feature:'syn_flag_count',      importance: 0.36 },
      { feature:'ack_flag_count',      importance: 0.21 },
      { feature:'dst_port_entropy',    importance: 0.18 },
      { feature:'psh_flag_count',      importance: 0.15 },
      { feature:'flow_count',          importance: 0.12 },
      { feature:'total_fwd_bytes',     importance: 0.09 },
      { feature:'syn_ack_ratio',       importance: 0.08 },
      { feature:'iat_std',             importance: 0.07 },
      { feature:'ttl_variance',        importance: 0.05 },
      { feature:'unique_dst_ports',    importance: 0.04 },
    ],
    attention_weights: [0.04,0.04,0.06,0.08,0.09,0.11,0.13,0.16,0.14,0.15],
    target_prediction: 'LATERAL MOVEMENT (TA0008)',
  };

  benchmarkData = {
    models: [
      { Model:'Logistic Regression', Accuracy:0.9718, 'F1-Score':0.9781, 'ROC-AUC':0.9973, FPR:'0.98%', 'Lead-Time':'0s (Reactive)' },
      { Model:'Random Forest',        Accuracy:0.9084, 'F1-Score':0.9385, 'ROC-AUC':0.9981, FPR:'0.98%', 'Lead-Time':'0s (Reactive)' },
      { Model:'CyberLens World Model',Accuracy:0.9394, 'F1-Score':0.9601, 'ROC-AUC':0.9952, FPR:'1.96%', 'Lead-Time':'+18.4s (Predictive)' },
    ]
  };

  renderOverview(overviewData);
  renderForecast(forecastData);
  renderExplain(explainData);
  renderKillChain(null, overviewData);
  renderBenchmark(benchmarkData);
}
