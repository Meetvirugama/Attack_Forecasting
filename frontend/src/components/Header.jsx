import { useState, useEffect } from 'react';

const SCENARIO_LABELS = {
  portscan:     'PORT SCAN',
  patator:      'BRUTE FORCE',
  infiltration: 'INFILTRATION',
  dos:          'DoS ATTACK',
  ddos:         'DDoS FLOOD',
};

export default function Header({ online, scenario }) {
  const [time, setTime] = useState('');

  useEffect(() => {
    const tick = () =>
      setTime(new Date().toLocaleTimeString('en-GB', { hour12: false }));
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, []);

  return (
    <header className="cl-header">
      <div className="cl-logo">
        <span className="cl-logo-bracket">[</span>
        <span className="cl-logo-text">CYBERLENS</span>
        <span className="cl-logo-bracket">]</span>
        <span className="cl-logo-sub">// network threat forecasting engine v2.0</span>
      </div>

      <div className="cl-header-right">
        {scenario && (
          <div className="cl-scenario-badge">
            SCENARIO: <span>{SCENARIO_LABELS[scenario] ?? scenario.toUpperCase()}</span>
          </div>
        )}
        <div className="cl-status">
          <span className={`status-dot ${online ? '' : 'offline'}`} />
          <span className={`status-label ${online ? '' : 'offline'}`}>
            {online ? '● LIVE' : '○ DEMO'}
          </span>
          <span className="status-time">{time}</span>
        </div>
      </div>
    </header>
  );
}
