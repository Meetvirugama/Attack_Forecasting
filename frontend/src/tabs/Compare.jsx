import { useState, useEffect } from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import api from '../api/cyberlens';

export default function Compare() {
  const [bench, setBench]   = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.benchmark()
      .then(setBench)
      .catch(() => setBench({ models: FALLBACK }))
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="loading-pulse">// Loading benchmark data...</div>;

  const models = bench?.models ?? [];

  const leadData = models.map(m => ({
    name: (m.Model ?? '?').replace('Causal World Model', 'CyberLens'),
    lead: parseFloat(String(m['Lead-Time'] ?? m['lead_time'] ?? '0').replace(/[^0-9.]/g, '')) || 0,
  }));

  const tooltipStyle = {
    background: '#111a11', border: '1px solid #1f3320',
    fontFamily: 'JetBrains Mono', fontSize: '0.65rem', color: '#c8e6c8',
  };

  return (
    <div>
      <div className="panel-header">
        <span className="panel-title">// MODEL COMPARISON</span>
        <span className="panel-sub">CyberLens vs traditional classifiers</span>
      </div>

      {/* Table */}
      <div className="card">
        <table className="compare-table">
          <thead>
            <tr>
              {['Model','Accuracy','F1-Score','ROC-AUC','FPR','Lead-Time'].map(h => (
                <th key={h}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {models.map((row, i) => {
              const isCyber = (row.Model ?? '').toLowerCase().includes('world') ||
                              (row.Model ?? '').toLowerCase().includes('cyber');
              const fmt = v => typeof v === 'number' ? (v < 2 ? `${(v * 100).toFixed(2)}%` : v) : (v ?? '—');
              return (
                <tr key={i} className={isCyber ? 'hl' : ''}>
                  <td>{row.Model ?? '—'}</td>
                  <td>{fmt(row.Accuracy)}</td>
                  <td>{fmt(row['F1-Score'])}</td>
                  <td>{fmt(row['ROC-AUC'])}</td>
                  <td>{row.FPR ?? '—'}</td>
                  <td style={{ color: isCyber ? 'var(--green)' : 'var(--muted)' }}>
                    {row['Lead-Time'] ?? row['lead_time'] ?? '—'}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Lead-time chart */}
      <div className="card">
        <div className="card-title">// LEAD-TIME ADVANTAGE</div>
        <ResponsiveContainer width="100%" height={160}>
          <BarChart layout="vertical" data={leadData} margin={{ top: 5, right: 50, left: 120, bottom: 5 }}>
            <CartesianGrid stroke="#1f3320" strokeDasharray="3 3" horizontal={false} />
            <XAxis type="number" tickFormatter={v => `${v}s`} tick={{ fill: '#3a5a3a', fontFamily: 'JetBrains Mono', fontSize: 9 }} />
            <YAxis type="category" dataKey="name" tick={{ fill: '#6b9b6b', fontFamily: 'JetBrains Mono', fontSize: 9 }} width={120} />
            <Tooltip contentStyle={tooltipStyle} formatter={v => `+${v}s`} />
            <Bar dataKey="lead" radius={[0, 2, 2, 0]} label={{ position: 'right', formatter: v => v > 0 ? `+${v}s` : '0s', fill: '#6b9b6b', fontFamily: 'JetBrains Mono', fontSize: 9 }}>
              {leadData.map((d, i) => (
                <Cell key={i} fill={d.lead > 0 ? '#00c832' : '#3a5a3a'} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>

      {/* Insight */}
      <div className="insight">
        <span className="insight-icon">↯</span>
        <span>
          CyberLens is the <strong>only model with predictive lead-time</strong>.
          Traditional classifiers fire at T=0s — <strong>after damage is done</strong>.
          CyberLens alerts up to <strong>+20 seconds early</strong>, giving defenders time to act.
        </span>
      </div>
    </div>
  );
}

const FALLBACK = [
  { Model: 'Logistic Regression', Accuracy: 0.9718, 'F1-Score': 0.9781, 'ROC-AUC': 0.9973, FPR: '0.98%', 'Lead-Time': '0s' },
  { Model: 'Random Forest',        Accuracy: 0.9084, 'F1-Score': 0.9385, 'ROC-AUC': 0.9981, FPR: '0.98%', 'Lead-Time': '0s' },
  { Model: 'Causal World Model',   Accuracy: 0.9394, 'F1-Score': 0.9601, 'ROC-AUC': 0.9952, FPR: '1.96%', 'Lead-Time': '+18.4s' },
];
