/**
 * useScenario.js — Custom React hook
 * 1. Tries /api/switch (synthetic AI scenario, always works)
 * 2. Falls back to assembling /api/status + /api/forecast + /api/explain
 * 3. Last resort: offline DEMO_DATA
 */
import { useState, useEffect, useCallback, useRef } from 'react';
import api from '../api/cyberlens';
import { DEMO_DATA } from './demoData';

async function fetchLive(scenario) {
  // Primary: /api/switch — sets scenario history + returns all data in one call
  try {
    const res = await api.switch(scenario);
    if (res && !res.error) return { ...res, _source: 'switch' };
  } catch (_) { /* fall through */ }

  // Fallback: assemble from individual endpoints
  const [overview, forecast, explainability] = await Promise.all([
    api.status().catch(() => null),
    api.forecast(5).catch(() => null),
    api.explain().catch(() => null),
  ]);

  if (!overview) throw new Error('Backend unreachable');

  return {
    scenario,
    records_analyzed: overview?.active_flows ?? 0,
    overview,
    forecast:       forecast      ?? {},
    explainability: explainability ?? {},
    _source: 'live',
  };
}

export function useScenario(scenario) {
  const [data, setData]       = useState(null);
  const [loading, setLoading] = useState(true);
  const [online, setOnline]   = useState(true);
  const abortRef = useRef(null);

  const load = useCallback(async () => {
    setLoading(true);
    if (abortRef.current) abortRef.current = false;
    const token = {};
    abortRef.current = token;

    try {
      const res = await fetchLive(scenario);
      if (token !== abortRef.current) return;
      setData(res);
      setOnline(true);
    } catch {
      if (token !== abortRef.current) return;
      setData(DEMO_DATA);
      setOnline(false);
    } finally {
      if (token === abortRef.current) setLoading(false);
    }
  }, [scenario]);

  useEffect(() => { load(); }, [load]);

  return { data, loading, online, refresh: load };
}
