const SCENARIOS = [
  { id: 'portscan',     label: '⬡ PORT SCAN'    },
  { id: 'patator',      label: '⬡ BRUTE FORCE'  },
  { id: 'infiltration', label: '⬡ INFILTRATION' },
  { id: 'dos',          label: '⬡ DoS ATTACK'   },
  { id: 'ddos',         label: '⬡ DDoS FLOOD'   },
];

export default function Toolbar({ scenario, onScenario, onRefresh, loading }) {
  return (
    <div className="cl-toolbar">
      <span className="toolbar-label">// LOAD SCENARIO:</span>
      {SCENARIOS.map(s => (
        <button
          key={s.id}
          id={`btn-scenario-${s.id}`}
          className={`scenario-btn ${scenario === s.id ? 'active' : ''}`}
          onClick={() => onScenario(s.id)}
          disabled={loading}
          title={`Load ${s.label.replace('⬡ ', '')} scenario`}
        >
          {s.label}
        </button>
      ))}
      <span className="spacer" />
      <button
        className="refresh-btn"
        onClick={onRefresh}
        disabled={loading}
        id="btn-refresh"
        title="Refresh AI inference"
      >
        {loading ? '↺ …' : '↺ REFRESH'}
      </button>
    </div>
  );
}
