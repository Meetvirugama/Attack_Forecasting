import { useState } from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, ReferenceLine } from 'recharts';
import api from '../api/cyberlens';

export default function Simulate() {
  const [synRate,  setSynRate]  = useState(5.2);
  const [entropy,  setEntropy]  = useState(3.5);
  const [kSteps,   setKSteps]   = useState(5);
  const [result,   setResult]   = useState(null);
  const [loading,  setLoading]  = useState(false);
  const [error,    setError]    = useState(null);

  const run = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.simulate({ syn_rate: synRate, port_entropy: entropy, k_steps: kSteps });
      setResult(res);
    } catch {
      setError('Could not reach API. Is the backend running?');
    } finally {
      setLoading(false);
    }
  };

  const chartData = result?.trajectory?.map(s => ({
    step:  `S${s.step}`,
    risk:  s.prob_pct,
    stage: s.stage,
  })) ?? [];

  const tooltipStyle = {
    background: '#131f13', border: '1px solid #233823',
    fontFamily: 'JetBrains Mono', fontSize: '0.65rem', color: '#b8dbb8',
    borderRadius: '4px',
  };

  return (
    <div>
      <div className="panel-header">
        <span className="panel-title">// WHAT-IF SIMULATOR</span>
        <span className="panel-sub">custom K-step rollout with your parameters</span>
      </div>

      <div className="two-col">
        {/* Inputs */}
        <div className="card">
          <div className="card-title">// INPUT PARAMETERS</div>

          <div className="slider-group">
            <label>
              SYN Flood Rate
              <span className="slider-readout">{synRate.toFixed(1)}</span>
            </label>
            <input type="range" min={0} max={20} step={0.1} value={synRate}
              onChange={e => setSynRate(parseFloat(e.target.value))} />
          </div>

          <div className="slider-group">
            <label>
              Port Entropy
              <span className="slider-readout">{entropy.toFixed(1)}</span>
            </label>
            <input type="range" min={0} max={8} step={0.1} value={entropy}
              onChange={e => setEntropy(parseFloat(e.target.value))} />
          </div>

          <div className="slider-group">
            <label>
              Forecast Steps (K)
              <span className="slider-readout">{kSteps}</span>
            </label>
            <input type="range" min={1} max={10} step={1} value={kSteps}
              onChange={e => setKSteps(parseInt(e.target.value))} />
          </div>

          <button className="run-btn" onClick={run} disabled={loading}>
            {loading ? '// running...' : '▶ RUN SIMULATION'}
          </button>
        </div>

        {/* Results */}
        <div className="card">
          <div className="card-title">// SIMULATION RESULTS</div>
          {error && <div style={{ color: 'var(--red)', fontFamily: 'var(--mono)', fontSize: '0.68rem' }}>// {error}</div>}
          {!result && !error && <div className="muted">// run simulation to see results</div>}
          {result && (
            <>
              {[
                ['SYN RATE',     result.syn_rate_input,     false],
                ['PORT ENTROPY', result.port_entropy_input, false],
                ['PEAK RISK',    `${result.peak_risk_pct}%`, result.peak_risk_pct > 65],
                ['LEAD TIME',    result.lead_time_seconds != null ? `${result.lead_time_seconds}s` : 'N/A', false],
              ].map(([l, v, hi]) => (
                <div key={l} className="sim-row">
                  <span className="sim-label">{l}</span>
                  <span className={`sim-val${hi ? ' danger' : ''}`}>{v}</span>
                </div>
              ))}
              {result.trajectory?.map(s => (
                <div key={s.step} className="sim-row">
                  <span className="sim-label">STEP {s.step}</span>
                  <span className={`sim-val${s.prob_pct > 65 ? ' danger' : ''}`}>{s.prob_pct}%</span>
                  <span className="sim-label" style={{flex: 1, textAlign: 'right'}}>{s.stage}</span>
                </div>
              ))}
            </>
          )}
        </div>
      </div>

      {/* Trajectory Chart */}
      {chartData.length > 0 && (
        <div className="card" style={{ marginTop: '0.65rem' }}>
          <div className="card-title">// TRAJECTORY PREVIEW</div>
          <ResponsiveContainer width="100%" height={200}>
            <LineChart data={chartData} margin={{ top: 15, right: 20, left: -20, bottom: 5 }}>
              <CartesianGrid stroke="#1a2e1a" strokeDasharray="3 3" />
              <XAxis dataKey="step" tick={{ fill: '#5a8a5a', fontFamily: 'JetBrains Mono', fontSize: 10 }} />
              <YAxis domain={[0, 105]} tickFormatter={v => `${v}%`} tick={{ fill: '#5a8a5a', fontFamily: 'JetBrains Mono', fontSize: 10 }} />
              <Tooltip contentStyle={tooltipStyle} formatter={v => `${v}%`} />
              <ReferenceLine y={65} stroke="#ff3b3b" strokeDasharray="4 4" label={{ value: 'Alert', fill: '#ff3b3b', fontFamily: 'JetBrains Mono', fontSize: 9 }} />
              <Line type="monotone" dataKey="risk" stroke="#00ff41" strokeWidth={2} dot={{ fill: '#00ff41', r: 4 }} activeDot={{ r: 6, fill: '#00ff41', stroke: '#00ff41', strokeWidth: 2 }} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  );
}
