import { useState, useEffect } from 'react';
import api from '../api/cyberlens';

const STAGE_DEFS = [
  { idx: 0, name: 'Normal',      tactic: '—'      },
  { idx: 1, name: 'Recon',       tactic: 'TA0043' },
  { idx: 2, name: 'Init Access', tactic: 'TA0001' },
  { idx: 3, name: 'Lateral Mvt', tactic: 'TA0008' },
  { idx: 4, name: 'C2',          tactic: 'TA0011' },
  { idx: 5, name: 'Exfil',       tactic: 'TA0010' },
];

export default function KillChain({ data }) {
  const [mitreData, setMitreData] = useState(null);

  const tactic = data?.overview?.mitre_tactic_current ?? 'TA0001';
  const nextTactic = data?.overview?.mitre_tactic_predicted ?? 'TA0008';

  useEffect(() => {
    api.mitre(tactic).then(setMitreData).catch(() => {});
  }, [tactic]);

  if (!data) return <div className="loading-pulse">// Loading kill chain...</div>;

  return (
    <div>
      <div className="panel-header">
        <span className="panel-title">// MITRE ATT&amp;CK KILL CHAIN</span>
        <span className="panel-sub">39 real-world campaign priors</span>
      </div>

      {/* Stage pipeline */}
      <div className="card">
        <div className="card-title">// ATTACK PROGRESSION</div>
        <div className="chain-stages">
          {STAGE_DEFS.map((s, i) => {
            const isActive = s.tactic === tactic;
            const isPred   = s.tactic === nextTactic;
            return (
              <div key={s.idx} className="stage-block">
                <div className={`stage-box${isActive ? ' active' : isPred ? ' predicted' : ''}`}>
                  <div className="stage-idx">[{String(s.idx).padStart(2, '0')}]</div>
                  <div className="stage-name">{s.name}</div>
                  <div className="stage-tactic">{s.tactic}</div>
                </div>
                {i < STAGE_DEFS.length - 1 && <span className="stage-arrow">→</span>}
              </div>
            );
          })}
        </div>
      </div>

      <div className="two-col">
        {/* Next tactics */}
        <div className="card">
          <div className="card-title">// NEXT PREDICTED TACTICS</div>
          <div className="tactic-list">
            {mitreData?.next_tactics?.slice(0, 6).map((t, i) => (
              <div key={i} className="tactic-row">
                <span className="tactic-id">{t.tactic_id ?? '—'}</span>
                <span className="tactic-name">{t.name ?? '—'}</span>
                <span className="tactic-prob">{((t.probability ?? 0) * 100).toFixed(0)}%</span>
              </div>
            )) ?? <span className="loading-pulse">// Loading...</span>}
          </div>
        </div>

        {/* Forecast chains */}
        <div className="card">
          <div className="card-title">// FORECAST CHAINS (TOP 3)</div>
          <div className="chain-list">
            {mitreData?.forecast_chains?.slice(0, 3).map((ch, i) => {
              const steps = Array.isArray(ch.chain) ? ch.chain.join(' → ') : (ch.chain ?? '—');
              const prob  = ((ch.probability ?? 0) * 100).toFixed(1);
              return (
                <div key={i} className="chain-row">
                  [{i + 1}] {steps} <span className="chain-prob">({prob}%)</span>
                </div>
              );
            }) ?? <span className="loading-pulse">// Loading...</span>}
          </div>
        </div>
      </div>

      {/* Campaign context */}
      {mitreData?.campaign_context && (
        <div className="card">
          <div className="card-title">// CAMPAIGN CONTEXT</div>
          <div className="context-text">
            Tactic: <span style={{ color: 'var(--green-dim)', fontWeight: 600 }}>
              {mitreData.campaign_context.tactic_id ?? '—'}
            </span>
            &nbsp;|&nbsp;
            Matching Campaigns: <span style={{ color: 'var(--green-dim)', fontWeight: 600 }}>
              {mitreData.campaign_context.campaign_count ?? '—'}
            </span>
            &nbsp;|&nbsp;
            Avg Severity: <span style={{ color: 'var(--amber)', fontWeight: 600 }}>
              {mitreData.campaign_context.avg_severity ?? '—'}/100
            </span>
            <br />
            Examples: {(mitreData.campaign_context.example_campaigns ?? []).join(', ') || '—'}
          </div>
        </div>
      )}
    </div>
  );
}
