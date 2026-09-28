# Scripts — Utility & Maintenance Tools

This directory contains helper scripts for data preparation, model analysis, and deployment utilities.

---

## Usage

Run any script from the project root:

```bash
python scripts/<script_name>.py
```

---

## Planned / Available Scripts

| Script | Status | Purpose |
|:---|:---|:---|
| `download_dataset.py` | Planned | Download and convert CIC-IDS-2017 CSVs to Parquet via Kaggle API |
| `export_onnx.py` | Planned | Export trained World Model to ONNX format for edge deployment |
| `generate_report.py` | Planned | Generate a PDF benchmark report from `results/world_model_benchmark.csv` |
| `inspect_attack_flows.py` | Planned | Parse and summarize all 39 MITRE STIX bundles in `data/mitre/attack_flows/` |

---

## Adding a New Script

1. Create your script in this directory (e.g. `scripts/my_util.py`)
2. Add project root to `sys.path` at the top:

```python
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
```

3. Import from `src` or `app` as needed:

```python
from src.mitre_mapper import MITREMapper
from app.config import MODELS_DIR, DATA_DIR
```
