import { useState } from 'react';
import './index.css';

import Header    from './components/Header';
import Toolbar   from './components/Toolbar';
import Sidebar   from './components/Sidebar';
import Overview  from './tabs/Overview';
import Forecast  from './tabs/Forecast';
import KillChain from './tabs/KillChain';
import ExplainAI from './tabs/ExplainAI';
import Simulate  from './tabs/Simulate';
import Compare   from './tabs/Compare';

import { useScenario } from './hooks/useScenario';

const TABS = {
  overview:  Overview,
  forecast:  Forecast,
  killchain: KillChain,
  explain:   ExplainAI,
  simulate:  Simulate,
  compare:   Compare,
};

export default function App() {
  const [scenario, setScenario] = useState('infiltration');
  const [activeTab, setTab]     = useState('overview');

  const { data, loading, online, refresh } = useScenario(scenario);

  const handleScenario = (s) => {
    setScenario(s);
    setTab('overview');
  };

  const TabComponent = TABS[activeTab];

  return (
    <div className="app-shell">
      <Header online={online} scenario={scenario} />

      <Toolbar
        scenario={scenario}
        onScenario={handleScenario}
        onRefresh={refresh}
        loading={loading}
      />

      <div className="cl-body">
        <Sidebar activeTab={activeTab} onTab={setTab} />

        <main className="cl-content">
          {loading
            ? <div className="loading-pulse">// Fetching AI inference from backend...</div>
            : <TabComponent data={data} />
          }
        </main>
      </div>

      <footer className="cl-footer">
        <span>CyberLens // SIH PS #26153 // React + Vite + Python + PyTorch</span>
        <span>Fully Offline &nbsp;|&nbsp; No Cloud Dependencies &nbsp;|&nbsp; MIT License</span>
      </footer>
    </div>
  );
}
