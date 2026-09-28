# Quickstart Guide — AI Network Attack Forecasting (SIH #26153)

## ⚡ 1-Minute Launch

```bash
# 1. Clone the repository
git clone https://github.com/Meetvirugama/Attack_Forecasting.git
cd Attack_Forecasting

# 2. Install dependencies
pip install -r requirements.txt

# 3. Launch the AI Defense Console (REST API + Web UI)
python run_server.py
```

Your default browser will automatically open `http://localhost:8000/`.

---

## 🛠️ Project Structure at a Glance

```
Attack_Forecasting/
├── src/           Core ML/AI modules (World Model, Forecaster, MITRE Mapper, XAI)
├── app/           REST API server (api.py) & configuration (config.py)
├── frontend/      Web Dashboard (index.html, css/style.css, js/app.js)
├── data/          CIC-IDS-2017 raw slices + 39 MITRE campaign flow JSONs
├── models/        Trained PyTorch weights, config, and feature scaler
├── results/       Benchmark CSV and evaluation plots
├── tests/         Unit tests — run with: python -m pytest tests/ -v
├── train.py       End-to-end retraining script
├── run_server.py  Boots the backend API and opens the dashboard
└── setup.py       Editable package install (pip install -e .)
```

---

## 🔧 Optional: Retrain the Model

1. Download **CIC-IDS-2017** Parquet/CSV files and place them in `data/raw/`.
2. Run:
   ```bash
   python train.py
   ```
3. This will re-generate `models/world_model.pt`, `models/world_model_scaler.pkl`, and `results/world_model_benchmark.csv`.

---

## 🧪 Run Unit Tests

```bash
python -m pytest tests/ -v
```

---

## 🌐 API Endpoints (Port 8000)

| Method | Endpoint | Description |
|:---|:---|:---|
| `GET` | `/api/threat-overview` | Live infiltration risk, MITRE stage, lead-time |
| `GET` | `/api/forecast?k=5` | K-step forward trajectory (historical + predicted) |
| `GET` | `/api/explainability` | Top-10 feature attribution & attention weights |
| `GET` | `/api/mitre?tactic=TA0001` | Markov next-tactic predictions from 39 campaigns |
| `GET` | `/api/scenario?name=infiltration` | Analyze a real CIC-IDS-2017 scenario slice |
| `GET` | `/api/benchmark` | Model comparison benchmark results |
| `POST` | `/api/simulate` | Custom K-step rollout with `syn_rate`, `port_entropy`, `k_steps` |
