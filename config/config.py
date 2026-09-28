"""
Configuration Module for AI Network Attack Forecasting
SIH Problem Statement #26153

Centralised configuration for all project components.
Supports environment variable overrides via .env file (python-dotenv).

Author: Attack Forecasting Team
Date: 2025
"""

import os
import logging
from pathlib import Path

# ── Project Root ────────────────────────────────────────────────────────────
# config.py lives in config/, so root is one level up
BASE_DIR = Path(__file__).resolve().parent.parent

# ── Core Directory Paths ─────────────────────────────────────────────────────
DATA_DIR           = BASE_DIR / "data"
RAW_DATA_DIR       = DATA_DIR / "raw"
PROCESSED_DATA_DIR = DATA_DIR / "processed"
MITRE_DATA_DIR     = DATA_DIR / "mitre"

MODELS_DIR   = BASE_DIR / "models"
LOGS_DIR     = BASE_DIR / "logs"
RESULTS_DIR  = BASE_DIR / "results"
ML_DIR       = BASE_DIR / "ml"
BACKEND_DIR  = BASE_DIR / "backend"
CONFIG_DIR   = BASE_DIR / "config"
FRONTEND_DIR = BASE_DIR / "frontend"

# Auto-create writable directories (data/raw and frontend are pre-populated)
for _dir in [RAW_DATA_DIR, PROCESSED_DATA_DIR, MODELS_DIR, LOGS_DIR, RESULTS_DIR]:
    _dir.mkdir(parents=True, exist_ok=True)

# ── Server Configuration ─────────────────────────────────────────────────────
SERVER_CONFIG = {
    "host": os.environ.get("NIDS_HOST", "localhost"),
    "port": int(os.environ.get("NIDS_PORT", "8000")),
    "debug": os.environ.get("NIDS_DEBUG", "false").lower() == "true",
}

# ── Dataset Configuration ────────────────────────────────────────────────────
DATASET_CONFIG = {
    "type": "CICIDS2017",                        # Options: 'CICIDS2017', 'NSL-KDD'
    "file_path": RAW_DATA_DIR / "dataset.csv",
    "test_size": 0.2,
    "random_state": 42,
    "stratify": True,
}

# ── Preprocessing Configuration ───────────────────────────────────────────────
PREPROCESSING_CONFIG = {
    "handle_missing": "drop",     # Options: 'drop', 'mean', 'median', 'mode'
    "remove_duplicates": True,
    "encoding_method": "label",   # Options: 'label', 'onehot'
    "scaling_method": "standard", # Options: 'standard', 'minmax'
    "apply_smote": True,
    "smote_sampling_strategy": "auto",
    "smote_k_neighbors": 5,
}

# ── Feature Selection Configuration ──────────────────────────────────────────
FEATURE_SELECTION_CONFIG = {
    "method": "tree_based",       # Options: 'correlation', 'univariate', 'rfe', 'tree_based', 'mi'
    "n_features": 20,
    "correlation_threshold": 0.95,
    "use_pca": False,
    "pca_variance": 0.95,
}

# ── World Model Architecture Configuration ───────────────────────────────────
WORLD_MODEL_CONFIG = {
    "input_dim": 30,               # State vector dimensionality (NetworkStateAggregator)
    "hidden_dim": 128,             # LSTM hidden size
    "num_lstm_layers": 2,          # Stacked LSTM depth
    "num_mitre_stages": 6,         # Output classes: 0-Normal ... 5-Exfiltration
    "dropout": 0.2,
    "window_size": 20,             # Flow records per time window
    "sequence_length": 10,         # Past windows used as context (W)
    "compromise_threshold": 0.65,  # Risk probability above which an alert fires
    "window_duration_seconds": 2.0,
}

# ── Training Configuration ────────────────────────────────────────────────────
TRAINING_CONFIG = {
    "epochs": 8,
    "batch_size": 128,
    "learning_rate": 3e-3,
    "weight_decay": 1e-4,
    "train_ratio": 0.70,
    "val_ratio": 0.15,              # remaining 0.15 goes to test
    "max_samples_per_file": 50_000,
}

# ── Baseline Model Configuration ──────────────────────────────────────────────
BASELINE_MODEL_CONFIG = {
    "logistic_regression": {
        "max_iter": 1000,
        "C": 1.0,
        "solver": "lbfgs",
        "random_state": 42,
    },
    "random_forest": {
        "n_estimators": 100,
        "max_depth": 12,
        "min_samples_split": 5,
        "random_state": 42,
        "n_jobs": -1,
    },
}

# ── Explainability (SHAP) Configuration ──────────────────────────────────────
SHAP_CONFIG = {
    "explainer_type": "tree",       # Options: 'tree', 'kernel', 'linear', 'deep'
    "background_samples": 100,
    "plot_format": "png",
    "max_display": 20,
}

# ── Logging Configuration ─────────────────────────────────────────────────────
LOGGING_CONFIG = {
    "level": os.environ.get("LOG_LEVEL", "INFO"),
    "format": "%(asctime)s — %(name)s — %(levelname)s — %(message)s",
    "files": {
        "training": LOGS_DIR / "world_model_training.log",
        "api":      LOGS_DIR / "api_server.log",
        "preprocessing": LOGS_DIR / "preprocessing.log",
        "explainability": LOGS_DIR / "explainability.log",
    },
}

# ── CICIDS-2017 Feature Reference ─────────────────────────────────────────────
CICIDS_FEATURES = [
    "Destination Port", "Flow Duration", "Total Fwd Packets",
    "Total Backward Packets", "Total Length of Fwd Packets",
    "Total Length of Bwd Packets", "Fwd Packet Length Max",
    "Fwd Packet Length Min", "Fwd Packet Length Mean",
    "Fwd Packet Length Std", "Bwd Packet Length Max",
    "Bwd Packet Length Min", "Bwd Packet Length Mean",
    "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s",
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max",
    "Fwd IAT Min", "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std",
    "Bwd IAT Max", "Bwd IAT Min", "Fwd PSH Flags", "Bwd PSH Flags",
    "Fwd URG Flags", "Bwd URG Flags", "Fwd Header Length",
    "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s",
    "Min Packet Length", "Max Packet Length", "Packet Length Mean",
    "Packet Length Std", "Packet Length Variance", "FIN Flag Count",
    "SYN Flag Count", "RST Flag Count", "PSH Flag Count",
    "ACK Flag Count", "URG Flag Count", "CWE Flag Count",
    "ECE Flag Count", "Down/Up Ratio", "Average Packet Size",
    "Avg Fwd Segment Size", "Avg Bwd Segment Size",
    "Fwd Header Length.1", "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate", "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate", "Subflow Fwd Packets", "Subflow Fwd Bytes",
    "Subflow Bwd Packets", "Subflow Bwd Bytes", "Init_Win_bytes_forward",
    "Init_Win_bytes_backward", "act_data_pkt_fwd", "min_seg_size_forward",
    "Active Mean", "Active Std", "Active Max", "Active Min",
    "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
]

# ── Attack Labels (CICIDS-2017) ───────────────────────────────────────────────
ATTACK_LABELS = [
    "BENIGN",
    "DDoS",
    "PortScan",
    "Bot",
    "Infiltration",
    "Web Attack – Brute Force",
    "Web Attack – XSS",
    "Web Attack – Sql Injection",
    "FTP-Patator",
    "SSH-Patator",
    "DoS slowloris",
    "DoS Slowhttptest",
    "DoS Hulk",
    "DoS GoldenEye",
    "Heartbleed",
]

# ── Dashboard Colour Palette ──────────────────────────────────────────────────
COLOR_SCHEME = {
    "primary":   "#1f77b4",
    "secondary": "#ff7f0e",
    "success":   "#2ca02c",
    "danger":    "#d62728",
    "warning":   "#ff7f0e",
    "info":      "#17becf",
    "benign":    "#2ca02c",
    "attack":    "#d62728",
}


if __name__ == "__main__":
    print("Configuration loaded successfully!")
    print(f"Base Directory : {BASE_DIR}")
    print(f"Data Directory : {DATA_DIR}")
    print(f"Models Directory: {MODELS_DIR}")
    print(f"Server          : {SERVER_CONFIG['host']}:{SERVER_CONFIG['port']}")
