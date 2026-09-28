/**
 * demoData.js — Offline fallback data
 * Used when the Python backend is not running.
 */
export const DEMO_DATA = {
  scenario: 'infiltration',
  records_analyzed: 1842,
  overview: {
    case_id: 'CL-DEMO-001',
    status: 'DEMO MODE',
    model_name: 'LSTM+ATTENTION',
    dataset: 'CIC-IDS-2017',
    infiltration_probability: 74.2,
    threat_level: 'HIGH RISK',
    forecast_horizon: '+10s (K=5)',
    lead_time_seconds: 18.4,
    active_flows: 2841,
    suspicious_nodes: 7,
    syn_ack_ratio: 4.7,
    model_confidence: 94.2,
    current_stage: 'EXECUTION',
    predicted_next_stage: 'LATERAL MOVEMENT',
    mitre_tactic_current: 'TA0002',
    mitre_tactic_predicted: 'TA0008',
    observed_campaigns: ['Conti', 'SolarWinds', 'FIN13', 'NotPetya'],
  },
  forecast: {
    historical: [
      { time: 'T-30m', prob: 18.0, stage: 'Normal' },
      { time: 'T-20m', prob: 22.5, stage: 'Recon' },
      { time: 'T-10m', prob: 28.0, stage: 'Recon' },
      { time: 'T-5m',  prob: 36.0, stage: 'Init Access' },
      { time: 'NOW',   prob: 44.0, stage: 'Execution' },
    ],
    predicted: [
      { step: 1, time_label: '+5m',  prob: 58.0, stage: 'Lateral Mvt' },
      { step: 2, time_label: '+10m', prob: 71.0, stage: 'Lateral Mvt' },
      { step: 3, time_label: '+15m', prob: 82.0, stage: 'C2' },
      { step: 4, time_label: '+20m', prob: 91.0, stage: 'C2' },
      { step: 5, time_label: '+25m', prob: 96.0, stage: 'Exfil' },
    ],
    lead_time_seconds: 18.4,
    max_risk_score: 96.0,
  },
  explainability: {
    top_features: [
      { feature: 'syn_flag_count',   importance: 0.36, category: 'TCP FLAGS' },
      { feature: 'ack_flag_count',   importance: 0.21, category: 'TCP FLAGS' },
      { feature: 'dst_port_entropy', importance: 0.18, category: 'PORT SCAN' },
      { feature: 'psh_flag_count',   importance: 0.15, category: 'TCP FLAGS' },
      { feature: 'flow_count',       importance: 0.12, category: 'VOLUME' },
      { feature: 'total_fwd_bytes',  importance: 0.09, category: 'VOLUME' },
      { feature: 'syn_ack_ratio',    importance: 0.08, category: 'TCP FLAGS' },
      { feature: 'iat_std',          importance: 0.07, category: 'TIMING' },
      { feature: 'ttl_variance',     importance: 0.05, category: 'NETWORK' },
      { feature: 'unique_dst_ports', importance: 0.04, category: 'PORT SCAN' },
    ],
    attention_weights: [0.04, 0.04, 0.06, 0.08, 0.09, 0.11, 0.13, 0.16, 0.14, 0.15],
    target_prediction: 'LATERAL MOVEMENT (TA0008)',
  },
};
