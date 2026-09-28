/**
 * cyberlens.js — API service layer
 * All calls to the Python backend go through this module.
 */

const BASE = 'http://localhost:8000/api';

const get = async (path) => {
  const r = await fetch(BASE + path);
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
};

const post = async (path, body) => {
  const r = await fetch(BASE + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
};

export const api = {
  scenario:  (name)  => get(`/scenario?name=${name}`),
  forecast:  (k = 5) => get(`/forecast?k=${k}`),
  explain:   ()      => get('/explain'),
  mitre:     (tactic) => get(`/mitre?tactic=${tactic}`),
  benchmark: ()      => get('/benchmark'),
  simulate:  (body)  => post('/simulate', body),
};

export default api;
