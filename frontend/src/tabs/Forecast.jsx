import {
  AreaChart, Area, LineChart, Line,
  XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, ReferenceLine, Legend,
} from 'recharts';

export default function Forecast({ data }) {
  if (!data) return <div className="loading-pulse">// Loading forecast...</div>;

  const fc   = data.forecast ?? {};
  const hist = (fc.historical ?? []).map(h => ({ time: h.time, hist: h.prob, stage: h.stage }));
  const pred = (fc.predicted  ?? []).map(p => ({ time: p.time_label, pred: p.prob, stage: p.stage }));

  // Merge for the combined chart
  const combined = [
    ...hist,
    { time: 'NOW', hist: hist[hist.length - 1]?.hist, pred: hist[hist.length - 1]?.hist },
    ...pred,
  ];

  const tooltipStyle = {
    background: '#131f13', border: '1px solid #233823',
    fontFamily: 'JetBrains Mono', fontSize: '0.65rem', color: '#b8dbb8',
    borderRadius: '4px',
  };

  return (
    <div>
      <div className="panel-header">
        <span className="panel-title">// RISK FORECAST TRAJECTORY</span>
        <span className="panel-sub">K-step autoregressive rollout</span>
      </div>

      {/* Main chart */}
      <div className="card">
        <div className="card-title">// RISK TRAJECTORY (observed + predicted)</div>
        <ResponsiveContainer width="100%" height={260}>
          <AreaChart data={combined} margin={{ top: 15, right: 15, left: -20, bottom: 0 }}>
            <defs>
              <linearGradient id="gHist" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%"  stopColor="#00ff41" stopOpacity={0.15} />
                <stop offset="95%" stopColor="#00ff41" stopOpacity={0}   />
              </linearGradient>
              <linearGradient id="gPred" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%"  stopColor="#ff3b3b" stopOpacity={0.15} />
                <stop offset="95%" stopColor="#ff3b3b" stopOpacity={0}   />
              </linearGradient>
            </defs>
            <CartesianGrid stroke="#1a2e1a" strokeDasharray="3 3" />
            <XAxis dataKey="time" tick={{ fill: '#5a8a5a', fontFamily: 'JetBrains Mono', fontSize: 10 }} />
            <YAxis domain={[0, 105]} tickFormatter={v => `${v}%`} tick={{ fill: '#5a8a5a', fontFamily: 'JetBrains Mono', fontSize: 10 }} />
            <Tooltip contentStyle={tooltipStyle} formatter={v => `${v?.toFixed(1)}%`} />
            <ReferenceLine x="NOW" stroke="#3d5e3d" strokeDasharray="4 4" label={{ value: 'NOW', fill: '#5a8a5a', fontFamily: 'JetBrains Mono', fontSize: 9 }} />
            <Area type="monotone" dataKey="hist" name="Observed"   stroke="#00ff41" fill="url(#gHist)" strokeWidth={2} dot={{ fill: '#00ff41', r: 3 }} connectNulls />
            <Area type="monotone" dataKey="pred" name="AI Forecast" stroke="#ff3b3b" fill="url(#gPred)" strokeWidth={2} strokeDasharray="6 3" dot={{ fill: '#ff3b3b', r: 3 }} connectNulls />
            <Legend wrapperStyle={{ fontFamily: 'JetBrains Mono', fontSize: '0.65rem', color: '#b8dbb8', paddingTop: '10px' }} />
          </AreaChart>
        </ResponsiveContainer>
      </div>

      <div className="two-col">
        {/* Historical */}
        <div className="card">
          <div className="card-title">// HISTORICAL (OBSERVED)</div>
          <div className="step-list">
            {(fc.historical ?? []).map((h, i) => (
              <div key={i} className="step-row">
                <span className="step-time">{h.time}</span>
                <span className="step-stage">{h.stage}</span>
                <span className="step-risk">{h.prob?.toFixed(1)}%</span>
              </div>
            ))}
          </div>
        </div>

        {/* Predicted */}
        <div className="card">
          <div className="card-title">// PREDICTED (AI FORECAST)</div>
          <div className="step-list">
            {(fc.predicted ?? []).map((p, i) => (
              <div key={i} className="step-row pred">
                <span className="step-time">{p.time_label}</span>
                <span className="step-stage">{p.stage}</span>
                <span className="step-risk">{p.prob?.toFixed(1)}%</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Metrics */}
      <div className="card">
        <div className="card-title">// KEY METRICS</div>
        <div className="metric-row">
          {[
            ['LEAD TIME', `${fc.lead_time_seconds ?? '—'}s`],
            ['PEAK RISK', `${fc.max_risk_score ?? '—'}%`],
            ['FORECAST K', 'K = 5'],
            ['WINDOW', '2.0s'],
          ].map(([l, v]) => (
            <div key={l} className="metric-box">
              <span className="metric-label">{l}</span>
              <span className="metric-val">{v}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
