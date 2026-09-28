export default function Overview({ data }) {
  if (!data) return <div className="loading-pulse">// Loading threat overview...</div>;

  // Support both direct /api/status response AND wrapped {overview: ...} response
  const d    = data.overview ?? data ?? {};
  const risk = parseFloat(d.infiltration_probability ?? 0);

  const tagColor = risk > 70 ? 'var(--red)'
    : risk > 40 ? 'var(--amber)'
    : 'var(--green-dim)';

  const riskColor = risk > 70 ? 'var(--red)'
    : risk > 40 ? 'var(--amber)'
    : 'var(--green)';

  return (
    <div>
      <div className="panel-header">
        <span className="panel-title">// THREAT OVERVIEW</span>
        <span className="panel-sub">CASE: {d.case_id ?? '—'}</span>
      </div>

      {/* Stat Grid */}
      <div className="stat-grid">
        <div className={`stat-card ${risk > 40 ? 'danger' : ''}`}>
          <div className="stat-label">INFILTRATION RISK</div>
          <div className="stat-value" style={{ color: riskColor, textShadow: `0 0 20px ${riskColor}40` }}>
            {risk.toFixed(1)}%
          </div>
          <div className="risk-bar-bg">
            <div className="risk-bar" style={{
              width: `${Math.min(risk, 100)}%`,
              background: riskColor,
              boxShadow: `0 0 8px ${riskColor}80`,
            }} />
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-label">CURRENT STAGE</div>
          <div className="stat-value sm">{d.current_stage ?? '—'}</div>
          <div className="stat-hint">Next → {d.predicted_next_stage ?? '—'}</div>
        </div>

        <div className="stat-card">
          <div className="stat-label">LEAD TIME</div>
          <div className="stat-value">
            {d.lead_time_seconds != null ? `${d.lead_time_seconds}s` : '—'}
          </div>
          <div className="stat-hint">advance warning</div>
        </div>

        <div className="stat-card">
          <div className="stat-label">ACTIVE FLOWS</div>
          <div className="stat-value">{(d.active_flows ?? 0).toLocaleString()}</div>
          <div className="stat-hint">{d.suspicious_nodes ?? '—'} suspicious</div>
        </div>
      </div>

      <div className="two-col">
        {/* Metadata table */}
        <div className="card">
          <div className="card-title">// THREAT METADATA</div>
          <table className="info-table">
            <tbody>
              {[
                ['Status',         d.status           ?? '—'],
                ['Model',          d.model_name        ?? '—'],
                ['Dataset',        d.dataset           ?? '—'],
                ['Confidence',     `${d.model_confidence ?? '—'}%`],
                ['MITRE (Now)',    d.mitre_tactic_current   ?? '—'],
                ['MITRE (Next)',   d.mitre_tactic_predicted ?? '—'],
                ['SYN/ACK Ratio', d.syn_ack_ratio     ?? '—'],
                ['Horizon',       d.forecast_horizon  ?? '—'],
                ['Threat Level',  d.threat_level      ?? '—'],
              ].map(([k, v]) => (
                <tr key={k}>
                  <td>{k}</td>
                  <td style={k === 'Threat Level' ? { color: tagColor, fontWeight: 700 } : {}}>
                    {v}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Campaigns + Threat meter */}
        <div className="card">
          <div className="card-title">// OBSERVED CAMPAIGNS</div>
          <div className="tag-row" style={{ marginBottom: '1rem' }}>
            {(d.observed_campaigns ?? []).length > 0
              ? (d.observed_campaigns).map(c => (
                  <span key={c} className="tag">{c}</span>
                ))
              : <span className="muted">// No campaigns detected</span>
            }
          </div>

          <div className="card-title" style={{ marginTop: '0.5rem' }}>// THREAT LEVEL</div>
          <div className="threat-bar-wrap">
            <div className="threat-bar-marker" style={{ width: `${Math.min(risk, 100)}%` }} />
          </div>
          <div className="threat-labels">
            <span>LOW</span><span>MEDIUM</span><span>HIGH</span><span>CRITICAL</span>
          </div>
          <div style={{ textAlign: 'center', marginTop: '0.7rem' }}>
            <span
              className="threat-tag"
              style={{ color: tagColor, borderColor: tagColor, boxShadow: `0 0 12px ${tagColor}30` }}
            >
              {d.threat_level ?? '—'}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
