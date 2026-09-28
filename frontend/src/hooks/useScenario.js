/**
 * useScenario.js — Custom React hook
 * Manages scenario state, data fetching, and loading/error state.
 */
import { useState, useEffect, useCallback, useRef } from 'react';
import api from '../api/cyberlens';
import { DEMO_DATA } from './demoData';

export function useScenario(scenario) {
  const [data, setData]       = useState(null);
  const [loading, setLoading] = useState(true);
  const [online, setOnline]   = useState(true);
  const abortRef = useRef(null);

  const load = useCallback(async () => {
    setLoading(true);
    // Cancel any in-flight request
    if (abortRef.current) abortRef.current = false;
    const token = {};
    abortRef.current = token;

    try {
      const res = await api.scenario(scenario);
      if (token !== abortRef.current) return; // stale
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
