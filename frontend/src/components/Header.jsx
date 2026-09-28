import { useState, useEffect } from 'react';

export default function Header({ online, scenario }) {
  const [time, setTime] = useState('');

  useEffect(() => {
    const tick = () => setTime(new Date().toLocaleTimeString('en-GB', { hour12: false }));
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
        <span className="cl-logo-sub">// network threat predictor v1.0</span>
      </div>
      <div className="cl-status">
        <span className={`status-dot ${online ? '' : 'offline'}`} />
        <span className={`status-label ${online ? '' : 'offline'}`}>
          {online ? 'LIVE' : 'DEMO MODE'}
        </span>
        <span className="status-time">{time}</span>
      </div>
    </header>
  );
}
