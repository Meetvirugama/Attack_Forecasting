const TABS = [
  { id: 'overview',  label: 'Overview'   },
  { id: 'forecast',  label: 'Forecast'   },
  { id: 'killchain', label: 'Kill Chain' },
  { id: 'explain',   label: 'Explain AI' },
  { id: 'simulate',  label: 'Simulate'   },
  { id: 'compare',   label: 'Compare'    },
];

export default function Sidebar({ activeTab, onTab }) {
  return (
    <nav className="cl-sidebar">
      {TABS.map(t => (
        <button
          key={t.id}
          className={`nav-btn ${activeTab === t.id ? 'active' : ''}`}
          onClick={() => onTab(t.id)}
        >
          <span className="nav-icon">{activeTab === t.id ? '◈' : '⬡'}</span>
          {t.label}
        </button>
      ))}

      <div className="nav-divider" />

      <div className="nav-meta">
        <div className="nav-meta-row"><span>MODEL</span><span>LSTM+ATT</span></div>
        <div className="nav-meta-row"><span>DATA</span><span>CIC-IDS17</span></div>
        <div className="nav-meta-row"><span>CAMPAIGNS</span><span>39</span></div>
        <div className="nav-meta-row"><span>STAGES</span><span>6</span></div>
      </div>
    </nav>
  );
}
