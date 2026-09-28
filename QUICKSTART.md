# Quickstart Guide — AI Network Attack Forecasting (SIH 26153)

## ⚡ 1-Minute Launch

```powershell
# 1. Install dependencies
pip install -r requirements.txt

# 2. Launch the AI Defense Console (Backend Server + Web UI)
python run_server.py
```
Your default browser will automatically open `http://localhost:8000/`.

---

## 🛠️ Project Structure at a Glance

- **`frontend/`**: The Neo-Brutalist Cyber Forensics Dashboard (`index.html`, `css/style.css`, `js/app.js`).
- **`backend/`**: Python REST API Server (`api.py`) and PyTorch World Model engine (`world_model/`).
- **`data/`**: Multi-stage attack slices (`data/raw/`) and 39 MITRE campaign flow JSONs (`data/mitre/`).
- **`models/`**: Serialized PyTorch model weights (`world_model.pt`) and scalers.
- **`results/`**: Benchmark CSV and evaluation metrics.
- **`train.py`**: End-to-end retraining script.
- **`run_server.py`**: Boots the backend server and opens the dashboard.
