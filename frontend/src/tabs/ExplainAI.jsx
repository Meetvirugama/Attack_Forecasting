import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, Cell,
} from 'recharts';

export default function ExplainAI({ data }) {
  if (!data) return <div className="loading-pulse">// Loading explainability...</div>;

  const exp      = data.explainability ?? {};
  const features = exp.top_features      ?? [];
  const attn     = exp.attention_weights ?? Array(10).fill(0.1);
  const maxAttn  = Math.max(...attn, 0.001);

  const chartData = features.map(f => ({
    name:       f.feature,
    importance: f.importance,
    category:   f.category,
  }));

  const tooltipStyle = {
    background: '#131f13', border: '1px solid #233823',
    fontFamily: 'JetBrains Mono', fontSize: '0.65rem', color: '#b8dbb8',
    borderRadius: '4px',
  };

  const ATTN_LABELS = ['T-9','T-8','T-7','T-6','T-5','T-4','T-3','T-2','T-1','NOW'];

  return (
    <div>
      <div className="panel-header">
        <span className="panel-title">// EXPLAINABLE AI</span>
        <span className="panel-sub">gradient saliency + temporal attention</span>
      </div>

      <div className="two-col">
        {/* Feature importance chart */}
        <div className="card">
          <div className="card-title">// TOP FEATURES DRIVING ALERT</div>
          <ResponsiveContainer width="100%" height={260}>
            <BarChart
              layout="vertical"
              data={chartData}
              margin={{ top: 15, right: 30, left: 110, bottom: 5 }}
            >
              <CartesianGrid stroke="#1a2e1a" strokeDasharray="3 3" horizontal={false} />
              <XAxis type="number" tick={{ fill: '#5a8a5a', fontFamily: 'JetBrains Mono', fontSize: 9 }} />
              <YAxis
                type="category"
                dataKey="name"
                tick={{ fill: '#b8dbb8', fontFamily: 'JetBrains Mono', fontSize: 9 }}
                width={110}
              />
              <Tooltip contentStyle={tooltipStyle} formatter={v => v.toFixed(4)} />
              <Bar dataKey="importance" radius={[0, 4, 4, 0]}>
                {chartData.map((d, i) => (
                  <Cell
                    key={i}
                    fill={d.importance > chartData[0]?.importance * 0.6 ? '#f59e0b' : '#00ff41'}
                  />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Attention heatmap */}
        <div className="card">
          <div className="card-title">// TEMPORAL ATTENTION HEATMAP</div>
          <div className="attn-grid">
            {attn.map((w, i) => {
              const alpha = (w / maxAttn).toFixed(2);
              return (
                <div
                  key={i}
                  className="attn-cell"
                  style={{ background: `rgba(0, 255, 65, ${alpha * 0.8})` }}
                  title={`${ATTN_LABELS[i]}: ${w.toFixed(3)}`}
                />
              );
            })}
          </div>
          <div className="attn-labels">
            {ATTN_LABELS.map(l => <span key={l}>{l}</span>)}
          </div>
          <div className="attn-note">
            Each cell shows how much a past time window influenced the prediction.
            Brighter green = stronger influence on the AI's decision.
          </div>
        </div>
      </div>

      {/* Outcome */}
      <div className="card">
        <div className="card-title">// PREDICTED OUTCOME</div>
        <div className="outcome-box">
          ▶ {exp.target_prediction ?? '—'}
        </div>
      </div>
    </div>
  );
}
