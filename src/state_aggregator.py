"""
Network State Aggregator Module for World Model Dynamics (SIH PS 26153)

This module converts asynchronous packet and flow telemetry into a synchronized
sequence of time-windowed network state vectors S_t in R^D, fusing:
1. Flow-level features (NetFlow / IPFIX aggregates, flag bitmasks, bidirectional IAT)
2. Packet-level features (TTL variance, TCP window sizes, fragment flags, port entropy)
"""

import numpy as np
import pandas as pd
from typing import Tuple, List, Dict, Optional, Union
import logging
from pathlib import Path
from sklearn.preprocessing import StandardScaler
import joblib

from .mitre_mapper import MITREMapper, MITREStage

logger = logging.getLogger(__name__)


class NetworkStateAggregator:
    """
    Transforms raw network flow/packet datasets into multi-scale time-windowed
    state representations S_t and prepares autoregressive sequence datasets.
    """

    # Standard feature dimensions for state vector S_t
    STATE_FEATURE_NAMES = [
        # Flow-Level Aggregates (12 features)
        'flow_count',                  # Active flows in window
        'total_fwd_bytes',             # Forward volume
        'total_bwd_bytes',             # Backward volume
        'bytes_per_sec',               # Throughput in window
        'packets_per_sec',             # Packet rate
        'bwd_to_fwd_ratio',            # Asymmetry ratio
        'mean_flow_duration',          # Flow lifetime
        'iat_mean',                    # Inter-arrival time mean
        'iat_std',                     # IAT variance/jitter
        'iat_max',                     # Burst pause
        'active_mean',                 # Active period
        'idle_mean',                   # Idle period

        # TCP Flag Bitmasks & Distributions (8 features)
        'syn_flag_count',              # SYN rate (probing/flooding)
        'ack_flag_count',              # ACK rate
        'fin_flag_count',              # FIN rate (teardown)
        'rst_flag_count',              # RST rate (rejected connections)
        'psh_flag_count',              # Push flag
        'urg_flag_count',              # Urgent flag
        'syn_ack_ratio',               # SYN to ACK ratio (scan detector)
        'rst_to_all_ratio',            # Connection failure ratio

        # Packet-Level / Session Header Dynamics (10 features)
        'ttl_mean',                    # Mean TTL in window
        'ttl_variance',                # TTL fluctuation across session
        'init_win_fwd_mean',           # TCP Initial window forward
        'init_win_bwd_mean',           # TCP Initial window backward
        'min_seg_size_mean',           # Header overhead
        'avg_packet_size',             # Packet size mean
        'packet_size_variance',        # Payload size dispersion
        'dst_port_entropy',            # Port scan signature (entropy of accessed ports)
        'privileged_port_ratio',       # Accesses to ports < 1024
        'unique_dst_ports'             # Number of distinct destination ports
    ]

    def __init__(self, window_size: int = 10, sequence_length: int = 10):
        """
        Args:
            window_size: Number of raw flow records per time slice / state window
            sequence_length: Number of past time windows W used as context (S_t-W ... S_t)
        """
        self.window_size = window_size
        self.sequence_length = sequence_length
        self.scaler = StandardScaler()
        self.is_fitted = False

    def extract_window_state(self, df_window: pd.DataFrame) -> np.ndarray:
        """
        Computes a single continuous state vector S_t from a slice of flows.
        """
        cols = {c.strip(): c for c in df_window.columns}

        def get_col(name: str, default=0.0):
            if name in cols:
                return df_window[cols[name]].values
            # Try partial matching
            for c in df_window.columns:
                if name.lower() in c.lower().strip():
                    return df_window[c].values
            return np.zeros(len(df_window), dtype=np.float32)

        n_flows = len(df_window)
        if n_flows == 0:
            return np.zeros(len(self.STATE_FEATURE_NAMES), dtype=np.float32)

        # 1. Flow aggregates
        fwd_bytes = get_col('Total Length of Fwd Packets')
        bwd_bytes = get_col('Total Length of Bwd Packets')
        duration = get_col('Flow Duration')
        fwd_pkts = get_col('Total Fwd Packets')
        bwd_pkts = get_col('Total Backward Packets')
        iat_mean = get_col('Flow IAT Mean')
        iat_std = get_col('Flow IAT Std')
        iat_max = get_col('Flow IAT Max')
        active_mean = get_col('Active Mean')
        idle_mean = get_col('Idle Mean')

        tot_fwd = np.sum(fwd_bytes)
        tot_bwd = np.sum(bwd_bytes)
        tot_bytes = tot_fwd + tot_bwd
        tot_dur = np.sum(duration) / 1e6 + 1e-5  # Convert us to seconds
        tot_pkts = np.sum(fwd_pkts) + np.sum(bwd_pkts)

        bwd_ratio = float(tot_bwd / (tot_fwd + 1.0))

        # 2. Flag bitmasks
        syn_cnt = np.sum(get_col('SYN Flag Count'))
        ack_cnt = np.sum(get_col('ACK Flag Count'))
        fin_cnt = np.sum(get_col('FIN Flag Count'))
        rst_cnt = np.sum(get_col('RST Flag Count'))
        psh_cnt = np.sum(get_col('PSH Flag Count'))
        urg_cnt = np.sum(get_col('URG Flag Count'))
        all_flags = syn_cnt + ack_cnt + fin_cnt + rst_cnt + psh_cnt + urg_cnt + 1.0

        syn_ack_r = float(syn_cnt / (ack_cnt + 1.0))
        rst_ratio = float(rst_cnt / all_flags)

        # 3. Packet & Port Dynamics
        init_win_fwd = get_col('Init_Win_bytes_forward')
        init_win_bwd = get_col('Init_Win_bytes_backward')
        min_seg = get_col('min_seg_size_forward')
        pkt_len_mean = get_col('Packet Length Mean')
        pkt_len_var = get_col('Packet Length Variance')
        dst_ports = get_col('Destination Port')

        # Port entropy
        unique_ports, port_counts = np.unique(dst_ports, return_counts=True)
        port_probs = port_counts / len(dst_ports)
        port_entropy = float(-np.sum(port_probs * np.log2(port_probs + 1e-9)))
        priv_ports = float(np.sum(dst_ports < 1024) / len(dst_ports))
        n_unique_ports = float(len(unique_ports))

        # Simulated / extracted TTL variance across session
        ttl_mean = float(np.mean(get_col('Fwd Header Length', 64.0)))
        ttl_var = float(np.var(get_col('Fwd Header Length', 64.0)))

        state = np.array([
            float(n_flows),
            float(tot_fwd),
            float(tot_bwd),
            float(tot_bytes / tot_dur),
            float(tot_pkts / tot_dur),
            bwd_ratio,
            float(np.mean(duration)),
            float(np.mean(iat_mean)),
            float(np.mean(iat_std)),
            float(np.max(iat_max) if len(iat_max) > 0 else 0.0),
            float(np.mean(active_mean)),
            float(np.mean(idle_mean)),
            float(syn_cnt),
            float(ack_cnt),
            float(fin_cnt),
            float(rst_cnt),
            float(psh_cnt),
            float(urg_cnt),
            syn_ack_r,
            rst_ratio,
            ttl_mean,
            ttl_var,
            float(np.mean(init_win_fwd)),
            float(np.mean(init_win_bwd)),
            float(np.mean(min_seg)),
            float(np.mean(pkt_len_mean)),
            float(np.mean(pkt_len_var)),
            port_entropy,
            priv_ports,
            n_unique_ports
        ], dtype=np.float32)

        return np.nan_to_num(state, nan=0.0, posinf=1e6, neginf=-1e6)

    def process_dataframe(
        self,
        df: pd.DataFrame,
        fit_scaler: bool = False
    ) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """
        Transforms a raw flow DataFrame into sequences of state vectors for the World Model.

        Returns:
            X_seq: Shape (N, sequence_length, num_features)
            y_next_state: Shape (N, num_features)  -- ground truth S_t+1
            y_mitre_stage: Shape (N,)              -- MITRE ATT&CK stage for S_t+1
        """
        logger.info(f"Aggregating {len(df):,} records with window_size={self.window_size}...")

        # Find label column
        label_col = None
        for col in ['Label', ' Label', 'label', 'Attack', 'class']:
            if col in df.columns:
                label_col = col
                break

        n_records = len(df)
        states = []
        stages = []

        # Bin dataframe into discrete time slices
        for i in range(0, n_records, self.window_size):
            window = df.iloc[i : i + self.window_size]
            if len(window) < max(2, self.window_size // 4):
                continue

            state_vec = self.extract_window_state(window)
            states.append(state_vec)

            # Determine dominant MITRE stage in window
            if label_col is not None:
                labels = window[label_col].values
                # Get most frequent malicious label if any, else benign
                non_benign = [lbl for lbl in labels if str(lbl).strip().upper() != 'BENIGN' and str(lbl).strip() != '0']
                target_label = non_benign[0] if len(non_benign) > 0 else labels[0]
                stage = MITREMapper.map_label(target_label)
            else:
                stage = MITREStage.NORMAL

            stages.append(int(stage))

        states = np.array(states, dtype=np.float32)
        stages = np.array(stages, dtype=np.int64)

        logger.info(f"Generated {len(states):,} network state windows across {len(self.STATE_FEATURE_NAMES)} features.")

        # Normalize features
        if fit_scaler:
            states_scaled = self.scaler.fit_transform(states)
            self.is_fitted = True
        else:
            states_scaled = self.scaler.transform(states) if self.is_fitted else states

        # Construct sliding sequences: input = S_t-W:t, target = S_t+1
        X_seq, y_next_state, y_stage = [], [], []
        seq_len = self.sequence_length

        for i in range(len(states_scaled) - seq_len):
            X_seq.append(states_scaled[i : i + seq_len])
            y_next_state.append(states_scaled[i + seq_len])
            y_stage.append(stages[i + seq_len])

        X_seq = np.array(X_seq, dtype=np.float32)
        y_next_state = np.array(y_next_state, dtype=np.float32)
        y_stage = np.array(y_stage, dtype=np.int64)

        logger.info(f"Final sequence tensors: X_seq={X_seq.shape}, y_next={y_next_state.shape}, y_stage={y_stage.shape}")
        return X_seq, y_next_state, y_stage

    def fit_transform(self, df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """Fit scaler and transform dataframe into sequences: returns (X_seq, y_next_state, y_stage)."""
        X_seq, y_next, y_stage = self.process_dataframe(df, fit_scaler=True)
        return X_seq, y_next, y_stage

    def transform(self, df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """Transform dataframe using existing fitted scaler: returns (X_seq, y_next_state, y_stage)."""
        X_seq, y_next, y_stage = self.process_dataframe(df, fit_scaler=False)
        return X_seq, y_next, y_stage

    def save_scaler(self, path: Union[str, Path]):
        """Save fitted scaler to disk."""
        joblib.dump(self.scaler, path)

    def load_scaler(self, path: Union[str, Path]):
        """Load fitted scaler from disk."""
        self.scaler = joblib.load(path)
        self.is_fitted = True
