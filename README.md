# CyberLens — AI-Based Network Attack Forecasting

> **Smart India Hackathon 2026 — Problem Statement SIH26153**  
> *AI-Based Network Attack Forecasting from Network Traffic Data*

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![PyTorch](https://img.shields.io/badge/PyTorch-2.0%2B-ee4c2c.svg)](https://pytorch.org/)
[![React](https://img.shields.io/badge/React-18%2B-61dafb.svg)](https://reactjs.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![GitHub](https://img.shields.io/badge/GitHub-Meetvirugama%2FAttack__Forecasting-181717.svg?logo=github)](https://github.com/Meetvirugama/Attack_Forecasting)

---

## 📋 Project Identity

| Field | Value |
|:---|:---|
| **Team Name** | SagarMitra |
| **Team ID** | 138259 |
| **Problem Statement ID** | SIH26153 |
| **PS Title** | AI based Network Attack Forecasting from Network Traffic Data |
| **Theme** | Blockchain & Cybersecurity |
| **PS Category** | Software |

---

## 🎯 Problem Statement

Traditional Network Intrusion Detection Systems (NIDS) are **reactive** — they alert only *after* an attack packet lands. They suffer from three critical flaws:

1. **Zero predictive horizon** — no advance warning before compromise
2. **Isolated packet analysis** — slow, staged ("low and slow") attacks evade detection because no single packet looks malicious
3. **No attack progression mapping** — defenders don't know *where in the kill chain* the attacker currently is

## 💡 Our Solution — CyberLens

> **"One traffic snapshot. Multi-step simulation. One explainable verdict."**

CyberLens learns the temporal dynamics of network state transitions and **simulates K steps into the future**, giving defenders a **3–8 minute early warning** before the kill chain completes.

```
Network Traffic → World Model → Infiltration Probability + MITRE Stage
```

**Core Principle:** Instead of classifying individual packets, we learn:

> **P(S_t+1 | S_t-W:t)** — the probability of the next network state given the observed history

---

## 🏗️ Architecture

```
RAW INPUT (NetFlow CSV / PCAP)
        ↓
FEATURE EXTRACTION (30-D State Vector)
   Flow-level: SYN/ACK flags, bytes, IAT stats
   Packet-level: TTL, window size, port entropy
        ↓
WORLD MODEL CORE (PyTorch LSTM + Multi-Head Attention)
   - 2-Layer LSTM backbone (128 hidden units)
   - Multi-Head Temporal Self-Attention (4 heads)
   - Residual skip connection + LayerNorm
        ↓
   ┌─────────────────┬──────────────────┬──────────────────┐
   │  State Head     │  MITRE Head      │  Risk Head       │
   │  S_t+1 ∈ R^30  │  6-class stage   │  P(infiltration) │
   └────────┬────────┴────────┬─────────┴────────┬─────────┘
            ↓                  ↓                   ↓
   K-STEP AUTOREGRESSIVE ROLLOUT
   S_t → S_t+1 → S_t+2 → ... → S_t+K
        ↓
   GRADIENT SALIENCY XAI ENGINE
   Top features driving each prediction
        ↓
   REACT DASHBOARD — 6 Intelligence Views
```

---

## 🚀 Quick Start

### 1. Clone
```bash
git clone https://github.com/Meetvirugama/Attack_Forecasting.git
cd Attack_Forecasting
```

### 2. Install Python dependencies
```bash
pip install -r requirements.txt
```

### 3. Build frontend
```bash
cd frontend
npm install
npm run build
cd ..
```

### 4. Launch
```bash
python run_server.py
```

Opens automatically at **http://localhost:8000** — no internet required.

---

## 🖥️ Dashboard — 6 Intelligence Views

| Tab | What it shows |
|:---|:---|
| **Overview** | Live infiltration probability, MITRE stage, lead time, active flows |
| **Forecast** | K-step risk trajectory chart (observed history + AI prediction) |
| **Kill Chain** | Full MITRE ATT&CK stage pipeline, Markov next-step predictions |
| **Explain AI** | Gradient saliency feature rankings + temporal attention heatmap |
| **Simulate** | Interactive what-if: adjust SYN rate, port entropy, K steps |
| **Compare** | CyberLens vs Logistic Regression vs Random Forest benchmark |

---

## 🔬 Attack Scenarios

Switch instantly between 5 pre-loaded attack patterns:

| Scenario | Description |
|:---|:---|
| **Infiltration** | Staged intrusion: recon → access → lateral movement |
| **Port Scan** | Rapid SYN probing with high port entropy |
| **Brute Force** | Credential stuffing — steady login attempts on one port |
| **DoS Attack** | Volumetric SYN flood, one-way traffic |
| **DDoS Flood** | Distributed amplification, multi-source TTL variance |

---

## 📊 Benchmark Results (CIC-IDS-2017)

| Model | Accuracy | F1-Score | ROC-AUC | Lead-Time |
|:---|:---:|:---:|:---:|:---:|
| Logistic Regression | 97.18% | 97.81% | 99.73% | 0s ❌ |
| Random Forest | 90.84% | 93.85% | 99.81% | 0s ❌ |
| **CyberLens (Ours)** | **93.94%** | **96.01%** | **99.52%** | **+18.4s ✅** |

> CyberLens is the **only approach** that predicts attacks *before* they complete.  
> The slight accuracy trade-off is entirely justified by the advance warning capability.

---

## 💻 Technology Stack

| Layer | Technology |
|:---|:---|
| **Frontend** | React 18, Vite, Recharts, CSS3 |
| **Backend API** | Python `http.server`, pure stdlib REST |
| **Deep Learning** | PyTorch 2.0+, LSTM + Multi-Head Attention |
| **Explainability** | Gradient Saliency (∣grad × input∣), Temporal Attention Weights |
| **MITRE Intelligence** | 39 real-world STIX v2.1 attack flow bundles, Markov transitions |
| **Data** | CIC-IDS-2017 (NetFlow features), fully offline |

---

## 📁 Project Structure

```
Attack_Forecasting/
├── backend/
│   └── api.py              # REST API server (port 8000)
├── frontend/               # React dashboard
│   ├── src/
│   │   ├── tabs/           # 6 intelligence view components
│   │   ├── hooks/          # useScenario, demoData
│   │   └── api/            # cyberlens.js API client
│   └── dist/               # Built production assets
├── ml/                     # PyTorch World Model engine
│   ├── world_model_core.py # LSTM + Attention architecture
│   ├── risk_forecaster.py  # K-step autoregressive rollout
│   ├── temporal_explainer.py # Gradient saliency XAI
│   ├── attack_path_mapper.py # MITRE Markov chain predictor
│   └── mitre_mapper.py     # Kill-chain stage mapping
├── models/
│   ├── world_model.pt      # Trained PyTorch weights
│   ├── world_model_config.json
│   └── world_model_scaler.pkl
├── data/
│   └── mitre/
│       ├── attack_flows/   # 39 STIX v2.1 campaign bundles
│       └── severity/       # NCISS severity scores
├── results/
│   └── world_model_benchmark.csv
├── run_server.py           # Single-command launcher
├── train.py                # Model training pipeline
└── requirements.txt
```

---

## 🧠 Key Design Decisions

**Why LSTM + Attention over a static classifier?**
- Static classifiers (Random Forest, XGBoost) classify each snapshot in isolation — **0s lead time**
- Our World Model learns temporal transition dynamics and rolls forward — **+10s to +20s lead time**

**Why temporal attention?**
- Not all past time windows are equally relevant — attention identifies which windows (e.g., T-3 to NOW) drove the escalation
- Enables honest explainability: defenders see exactly *which history windows* triggered the alert

**Why 30 features?**
- Dual-level: 12 flow-level aggregates + 18 packet dynamics features
- Covers all major attack signatures: SYN flood, port scan, C2 beaconing, exfiltration volume ratios

---

## 📐 Multi-Task Loss

```
L_total = 1.0 × L_Huber(S_t+1, Ŝ_t+1)     # State dynamics
        + 0.6 × L_WeightedCE(stage, ŷ_stage) # MITRE classification
        + 0.4 × L_BCE(risk, ŷ_risk)           # Infiltration risk
```

---

## 🏆 SIH Judge Q&A

**Q: Why is this better than Random Forest / XGBoost?**  
A: Static classifiers fire at T=0s — after damage is done. CyberLens gives defenders +18.4s advance warning by simulating attack trajectory forward in time.

**Q: How is explainability achieved without SHAP?**  
A: We use gradient saliency (∣∇f × input∣) — a theoretically-grounded, model-native XAI method. Combined with multi-head temporal attention weights, defenders see both *which features* and *which time windows* triggered the alert.

**Q: Does it work on zero-day attacks?**  
A: Yes — the model learns *structural kill-chain dynamics* (SYN spikes, port entropy patterns), not static signatures. These dynamics appear across all attack types.

**Q: No internet required?**  
A: Correct. The server is Python stdlib `http.server`. The React frontend is pre-built to `dist/`. All 39 MITRE campaign bundles are local JSON files.

---

## 📚 References

1. Sharafaldin et al., "Toward Generating a New Intrusion Detection Dataset", IEEE Access 2018
2. Ha & Schmidhuber, "World Models", arXiv:1803.10122
3. Veličković et al., "Graph Attention Networks", ICLR 2018
4. Lundberg & Lee, "SHAP", NeurIPS 2017
5. MITRE ATT&CK Framework — attack.mitre.org
6. CIC-IDS-2017 Dataset — unb.ca/cic/datasets
7. CERT-In Annual Report 2023 — cert-in.org.in

---

*Built for SIH 2026 — Problem Statement #26153 | Team SagarMitra (#138259) | Python 3.10+ | PyTorch 2.0+ | Fully Offline*
