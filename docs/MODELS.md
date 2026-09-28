# Models Directory

This directory stores all serialized model artifacts produced by the training pipeline (`train.py`).

---

## Contents

```
models/
├── world_model.pt              # Trained PyTorch World Model weights (~1.5 MB)
├── world_model_config.json     # Architecture configuration (input_dim, hidden_dim, etc.)
└── world_model_scaler.pkl      # Fitted StandardScaler for the 30-D state vector
```

---

## Model Architecture Summary

| Parameter | Value |
|:---|:---|
| Architecture | 2-Layer LSTM + Multi-Head Temporal Attention |
| Input Dimension | 30 (Network State Vector) |
| Hidden Dimension | 128 |
| LSTM Layers | 2 |
| Attention Heads | 4 |
| Output Heads | 3 (State Dynamics, MITRE Stage, Infiltration Risk) |
| Training Data | CIC-IDS-2017 (multi-stage attack slices) |
| Model Size | ~1.5 MB |
| Inference Latency | <15ms on standard CPU |

---

## Loading the Model

```python
import torch
import json
import joblib
from src.world_model_core import WorldModelDynamics

# Load config
with open("models/world_model_config.json", "r") as f:
    cfg = json.load(f)

# Instantiate and load weights
model = WorldModelDynamics(
    input_dim=cfg["input_dim"],
    hidden_dim=cfg["hidden_dim"],
    num_mitre_stages=cfg.get("num_mitre_stages", 6)
)
model.load_state_dict(torch.load("models/world_model.pt", map_location="cpu", weights_only=True))
model.eval()

# Load scaler
scaler = joblib.load("models/world_model_scaler.pkl")
```

---

## Regenerating Artifacts

To retrain and regenerate all model artifacts:

```bash
# Place CIC-IDS-2017 files in data/raw/ first
python train.py
```

This will overwrite:
- `models/world_model.pt`
- `models/world_model_config.json`
- `models/world_model_scaler.pkl`
- `results/world_model_benchmark.csv`

---

## Notes

- Model weights are tracked in git (at ~1.5 MB they are within GitHub's limit)
- The `app/api.py` server automatically loads these artifacts on startup
- `world_model_config.json` must match the architecture used to produce `world_model.pt`
