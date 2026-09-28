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
    background: '#111a11', border: '1px solid #1f3320',
    fontFamily: 'JetBrains Mono', fontSize: '0.65rem', color: '#c8e6c8',
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
        <ResponsiveContainer width="100%" height={240}>
          <AreaChart data={combined} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
            <defs>
              <linearGradient id="gHist" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%"  stopColor="#00c832" stopOpacity={0.2} />
                <stop offset="95%" stopColor="#00c832" stopOpacity={0}   />
              </linearGradient>
              <linearGradient id="gPred" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%"  stopColor="#ef4444" stopOpacity={0.2} />
                <stop offset="95%" stopColor="#ef4444" stopOpacity={0}   />
              </linearGradient>
            </defs>
            <CartesianGrid stroke="#1f3320" strokeDasharray="3 3" />
            <XAxis dataKey="time" tick={{ fill: '#3a5a3a', fontFamily: 'JetBrains Mono', fontSize: 10 }} />
            <YAxis domain={[0, 105]} tickFormatter={v => `${v}%`} tick={{ fill: '#3a5a3a', fontFamily: 'JetBrains Mono', fontSize: 10 }} />
            <Tooltip contentStyle={tooltipStyle} formatter={v => `${v?.toFixed(1)}%`} />
            <ReferenceLine x="NOW" stroke="#3a5a3a" strokeDasharray="4 4" label={{ value: 'NOW', fill: '#3a5a3a', fontFamily: 'JetBrains Mono', fontSize: 9 }} />
            <Area type="monotone" dataKey="hist" name="Observed"   stroke="#00c832" fill="url(#gHist)" strokeWidth={2} dot={{ fill: '#00c832', r: 3 }} connectNulls />
            <Area type="monotone" dataKey="pred" name="AI Forecast" stroke="#ef4444" fill="url(#gPred)" strokeWidth={2} strokeDasharray="6 3" dot={{ fill: '#ef4444', r: 3 }} connectNulls />
            <Legend wrapperStyle={{ fontFamily: 'JetBrains Mono', fontSize: '0.65rem', color: '#6b9b6b' }} />
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
