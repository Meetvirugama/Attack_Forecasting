const SCENARIOS = [
  { id: 'portscan',     label: 'PORT SCAN'   },
  { id: 'patator',      label: 'BRUTE FORCE' },
  { id: 'infiltration', label: 'INFILTRATION' },
  { id: 'dos',          label: 'DoS ATTACK'  },
  { id: 'ddos',         label: 'DDoS FLOOD'  },
];

export default function Toolbar({ scenario, onScenario, onRefresh }) {
  return (
    <div className="cl-toolbar">
      <span className="toolbar-label">// LOAD SCENARIO:</span>
      {SCENARIOS.map(s => (
        <button
          key={s.id}
          className={`scenario-btn ${scenario === s.id ? 'active' : ''}`}
          onClick={() => onScenario(s.id)}
        >
          {s.label}
        </button>
      ))}
      <span className="spacer" />
      <button className="refresh-btn" onClick={onRefresh}>↺ REFRESH</button>
    </div>
  );
}
