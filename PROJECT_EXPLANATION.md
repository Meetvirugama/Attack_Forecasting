# AI Network Attack Forecasting — Complete Codebase & Architecture Guide
**SIH Problem Statement #26153 | GitHub: [Meetvirugama/Attack_Forecasting](https://github.com/Meetvirugama/Attack_Forecasting)**

---

## 1. Project in One Sentence

> **Attack Forecasting is an open-source, fully offline Causal World Model that learns network state transition dynamics P(S_{t+1} | S_{t-W:t}) from temporal traffic telemetry, predicting multi-step attacker progression and MITRE ATT&CK kill-chain transitions up to 20 seconds before compromise is completed — backed by dual-mode explainability (attention heatmaps + gradient saliency) and verified against 39 real-world cyber campaigns.**

---

## 2. The Problem in Simple Terms

### The Reality of Modern Cyber Attacks

A cyber attack unfolds in a phased, sequential manner — exactly like a burglar casing a bank vault:

| Phase | Burglar Analogy | Network Attack |
|:---|:---|:---|
| **Reconnaissance** | Walking around, checking camera angles | Port scanning (PortScan) |
| **Initial Access** | Picking the side lock | SSH/FTP Brute Force (Patator) |
| **Lateral Movement** | Crawling through ventilation shafts | Internal host-to-host pivoting (Infiltration) |
| **Command & Control** | Radio link to outside team | Botnet C2 beaconing |
| **Exfiltration / Impact** | Cracking the vault | Ransomware / Data theft (DDoS) |

An intrusion is **not a single packet or flow** — it is a **continuous temporal trajectory** unfolding over minutes or hours.

---

## 3. Why Traditional IDS Is Not Enough

```
TRADITIONAL IDS (Reactive):
[Single Flow] ──▶ [Static ML Classifier] ──▶ "Benign / Malicious?"
                                                      │
                                                      ▼
                                        (Alert fires AFTER damage is done)
                                        (0.0 seconds advance warning)
```

Three fundamental flaws:

1. **Memoryless (Point-in-Time):** Treats every flow in isolation. 5,000 sequential SYN packets across different ports is a reconnaissance scan — but each individual SYN looks harmless.
2. **Strictly Reactive (Zero Lead-Time):** A static classifier only fires when the malicious exploit is already executing on the server. Data is already encrypted or leaked.
3. **Black-Box Alert Fatigue:** SOCs receive 10,000+ alerts/day without context on *where the attacker is going next* or *what network behaviors caused the alert*.

---

## 4. Our Core Idea: The World Model Approach

Instead of asking: *"Is this single flow malicious?"*

Our World Model asks: **"Given the sequence of network conditions observed over the last 10 time windows, how will the network state evolve in the next 5 windows — and will that trajectory lead to compromise?"**

```
OUR CAUSAL WORLD MODEL (Predictive):
[Past 10 State Windows: S_t-9 ... S_t] ──▶ [Neural World Model P(S_t+1 | S_t)]
                                                          │
                     ┌────────────────────────────────────┼────────────────────────────────────┐
                     ▼                                    ▼                                    ▼
           Predict Next States               MITRE Kill-Chain Stage              Infiltration Risk &
        (S_t+1, S_t+2, ..., S_t+5)       (Recon → Access → Lateral)            Lead-Time (+18.4s)
```

**World Model Definition:** An AI model that constructs an internal causal simulation of its environment dynamics. By rolling this simulation forward in time, defenders gain **10 to 20 seconds of proactive lead-time** to block IPs or isolate subnets before the kill chain completes.

---

## 5. Complete Architecture & System Components

```
[TELEMETRY INGESTION]
  ├─ Raw Datasets: data/raw/*.parquet  (CIC-IDS-2017 multi-stage attacks)
  └─ Live API Scenario Ingestion       (/api/scenario in app/api.py)
          │
          ▼
[NETWORK STATE AGGREGATION & FEATURE EXTRACTION]  (src/state_aggregator.py)
  ├─ Class: NetworkStateAggregator(window_size=20, sequence_length=10)
  ├─ Computes 30-D continuous state vector S_t across:
  │    • 12 Flow-Level Aggregates (volume, throughput, IAT jitter, duration)
  │    • 8 TCP Flag Distributions (SYN, ACK, RST ratios, teardown rates)
  │    • 10 Packet & Port Dynamics (TTL variance, window size, port entropy)
  └─ Standardized via StandardScaler (models/world_model_scaler.pkl)
          │
          ▼
[AUTOREGRESSIVE TEMPORAL SEQUENCE FORMATION]
  └─ Input Tensor X_seq: (Batch, 10 timesteps, 30 features)
          │
          ▼
[NEURAL WORLD MODEL DYNAMICS CORE]  (src/world_model_core.py)
  ├─ Class: WorldModelDynamics(nn.Module)
  │    • Input Projection: Linear(30→128) + LayerNorm + GELU + Dropout(0.2)
  │    • Sequence Backbone: 2-Layer LSTM (hidden_dim=128)
  │    • Temporal Attention: MultiHeadTemporalAttention (4 heads, scaled dot-product)
  │    • Residual Normalization: LayerNorm(latest_h + attention_context)
  │
  └─ Multi-Task Output Heads:
       1. state_head  → Predicts S_t+1 in R^30   (Smooth L1 Huber Loss)
       2. mitre_head  → 6-Class Kill-Chain Logits (Class-Weighted Cross-Entropy)
       3. risk_head   → Infiltration Probability [0,1] (Binary Cross-Entropy)
          │
          ├──────────────────────────────┬──────────────────────────────┐
          ▼                              ▼                              ▼
[K-STEP FORWARD ROLLOUT]    [MITRE CAMPAIGN PREDICTOR]       [TEMPORAL EXPLAINER]
(src/forecaster.py)         (src/attack_chain_predictor.py)  (src/temporal_explainer.py)
• KStepForecaster            • AttackChainPredictor           • TemporalExplainer
• Recursive autoregressive   • 1st-order Markov transitions   • Multi-Head Attention Weights
  rollout K=5 steps          • 39 Real Campaigns (STIX JSONs) • Gradient Saliency (|grad×x|)
• Lead-time calc (~18.4s)    • NCISS Severity Scoring (0-100) • Top-10 driving features
          │                              │                              │
          └──────────────────────────────┼──────────────────────────────┘
                                         │
                                         ▼
                            [PYTHON REST API]  (app/api.py)
                              ├─ HTTPServer on Port 8000
                              ├─ GET  /api/threat-overview
                              ├─ GET  /api/forecast?k=5
                              ├─ GET  /api/explainability
                              ├─ GET  /api/mitre?tactic=TA0001
                              ├─ GET  /api/scenario?name=infiltration
                              ├─ GET  /api/benchmark
                              └─ POST /api/simulate
                                         │
                                         ▼
                       [CYBER DEFENSE DASHBOARD]  (frontend/)
                         ├─ 10 Interactive Intelligence Tabs (index.html + app.js)
                         ├─ SVG Network Topology Graph
                         ├─ Forward Infiltration Probability Curve
                         ├─ Interactive What-If Parameter Sliders
                         ├─ Formal Baseline Comparison Table
                         └─ 1-Click JSON Incident Dossier Export
```

---

## 6. Data Flow: Telemetry to Decision Support

1. **Ingestion:** Raw NetFlow telemetry (e.g. `Thursday-WorkingHours-Afternoon-Infilteration.parquet`) enters the system.
2. **Windowing:** `NetworkStateAggregator` groups raw flows into discrete slices of W=20 flows per window.
3. **Feature Computation:** For each window, 30 mathematical and behavioral metrics are computed (flow rates, flag ratios, port Shannon entropy, TTL variances).
4. **Standardization:** The 30 features are normalized using `StandardScaler` to ensure zero mean and unit variance.
5. **Sliding Sequence Construction:** 10 consecutive state vectors are stacked → shape `(1, 10, 30)` = `[S_{t-9}, ..., S_t]`.
6. **Model Forward Pass:** The tensor passes through `WorldModelDynamics` → outputs `Ŝ_{t+1}`, MITRE stage probabilities, and risk score.
7. **Recursive Rollout (K-Step):** `Ŝ_{t+1}` is appended to the sequence (oldest state dropped). The model re-runs for k=2,3,4,5 → simulates future conditions 10–20 seconds ahead.
8. **Campaign Correlation:** The predicted MITRE stage is matched against the 39-campaign Markov transition matrix to forecast which adversary techniques are expected.
9. **Explainability Extraction:** Attention weights and gradient saliencies highlight the specific time step and top features (e.g. `syn_flag_count`, `dst_port_entropy`) driving the alert.
10. **Dashboard Rendering:** The REST API serializes outputs as JSON; the frontend renders live SVG curves, threat badges, and recommended defense playbooks.

---

## 7. Network State Representation (S_t)

The network state S_t is a **30-dimensional continuous feature vector** computed by `src/state_aggregator.py`:

### Flow-Level Aggregates (Features 1–12)

| # | Feature | Cybersecurity Meaning |
|:---:|:---|:---|
| 1 | `flow_count` | Active concurrent flows — spikes indicate DDoS or scanning |
| 2 | `total_fwd_bytes` | Outbound volume — high values indicate data staging |
| 3 | `total_bwd_bytes` | Inbound volume — high values indicate database dumps |
| 4 | `bytes_per_sec` | Overall byte throughput |
| 5 | `packets_per_sec` | Distinguishes high-packet low-byte attacks (SYN floods) from file transfers |
| 6 | `bwd_to_fwd_ratio` | Normal web traffic: high backward; C2 beaconing: symmetric |
| 7 | `mean_flow_duration` | Very short → port scan; very long → C2 tunnel |
| 8 | `iat_mean` | Measures packet pacing and cadence |
| 9 | `iat_std` | Attackers introduce jitter to evade timing-based signatures |
| 10 | `iat_max` | Detects periodic beaconing (e.g. bot checking in every 60s) |
| 11 | `active_mean` | Burstiness of malicious scripts |
| 12 | `idle_mean` | Sleeper backdoors and persistent sessions |

### TCP Flag Dynamics (Features 13–20)

| # | Feature | Cybersecurity Meaning |
|:---:|:---|:---|
| 13 | `syn_flag_count` | High SYN count → port probing or SYN flood DoS |
| 14 | `ack_flag_count` | Normal sessions have high ACK; scan attempts lack completed ACKs |
| 15 | `fin_flag_count` | High FIN count → stealth FIN port scanning |
| 16 | `rst_flag_count` | High RST → target closed ports rejecting active scan |
| 17 | `psh_flag_count` | Active payload delivery (e.g. shellcode execution) |
| 18 | `urg_flag_count` | Rare in benign traffic; used in specific evasion tools |
| 19 | `syn_ack_ratio` | If SYN >> ACK → attacker scanning closed ports |
| 20 | `rst_to_all_ratio` | Classic signature of aggressive network scanning |

### Packet & Port Dynamics (Features 21–30)

| # | Feature | Cybersecurity Meaning |
|:---:|:---|:---|
| 21 | `ttl_mean` | OS fingerprinting and route changes |
| 22 | `ttl_variance` | Non-zero variance → IP spoofing or multi-hop routing |
| 23 | `init_win_fwd_mean` | OS fingerprinting; tools like Nmap use unique window sizes |
| 24 | `init_win_bwd_mean` | Response characteristics of target services |
| 25 | `min_seg_size_mean` | Detects malformed packet evasion |
| 26 | `avg_packet_size` | Probes: 40–60 bytes; exfiltration: >1000 bytes |
| 27 | `packet_size_variance` | Normal browsing: high variance; bots: uniform sizes |
| 28 | `dst_port_entropy` | **Critical:** High entropy → attacker hitting many different ports (scan) |
| 29 | `privileged_port_ratio` | Attacks focus on admin services (SSH 22, SMB 445, HTTP 80) |
| 30 | `unique_dst_ports` | Direct measurement of scan breadth |

---

## 8. Temporal Sequence Construction

A single state vector S_t shows a frozen moment. To model **speed and direction of change**, we construct a sliding sequence of 10 consecutive time windows:

```
X_seq = [S_{t-9}, S_{t-8}, S_{t-7}, ..., S_{t-1}, S_t]  ∈ R^{10 × 30}
```

### Why Temporal Sequences Matter

```
T-30m:  dst_port_entropy increases slightly      → Reconnaissance begins
T-15m:  syn_flag_count spikes on Port 22/445     → Initial Access attempt
T-5m:   psh_flag_count + total_fwd_bytes rise    → Script executing
T=0:    Internal lateral traffic begins           → Lateral Movement
```

The sequence enables the model to connect these separate clues into an unmistakable **adversary trajectory**.

---

## 9. What Makes This a True World Model?

In AI literature (Ha & Schmidhuber 2018; LeCun 2022), a World Model must satisfy three conditions:

1. **Environment State Representation** → Compresses observations into state space S_t ✅
2. **Transition Dynamics Function** → Learns P(S_{t+1} | S_{t-W:t}) ✅
3. **Forward Simulation (Rollout)** → Iterates `Ŝ_{t+1} → Ŝ_{t+2} → Ŝ_{t+3}` without real-world observations ✅

### How the Code Implements This (src/world_model_core.py + src/forecaster.py)

```
State Transition:
  Ŝ_{t+1} = StateHead( LayerNorm( h_t^LSTM + AttentionContext(H) ) )

K-Step Rollout:
  Ŝ_{t+1} = M(S_{t-9:t})
  Ŝ_{t+2} = M(S_{t-8:t}, Ŝ_{t+1})
  Ŝ_{t+3} = M(S_{t-7:t}, Ŝ_{t+1:t+2})
  ...
```

This is **not a static classifier with a temporal label** — it is a **continuous autoregressive transition dynamics model**.

---

## 10. AI Model Architecture (Layer-by-Layer)

Implemented in `WorldModelDynamics` ([`src/world_model_core.py`](src/world_model_core.py)):

```
Input Tensor: X_seq (Shape: Batch × 10 timesteps × 30 features)
  │
  ▼
[1. Input Feature Projection & Normalization]
  ├─ nn.Linear(30, 128)
  ├─ nn.LayerNorm(128)
  ├─ nn.GELU()
  └─ nn.Dropout(p=0.2)
  │  Output: Batch × 10 × 128
  │
  ▼
[2. Recurrent Sequence Encoder]
  └─ nn.LSTM(input_size=128, hidden_size=128, num_layers=2, batch_first=True, dropout=0.2)
     Output: H of Batch × 10 × 128, last hidden state h_n
  │
  ▼
[3. Multi-Head Temporal Self-Attention]
  ├─ MultiHeadTemporalAttention(hidden_dim=128, num_heads=4)
  ├─ Q, K, V Linear Projections (128 → 4 heads × 32 dim)
  ├─ Scaled Dot-Product: Softmax( (Q·K^T) / sqrt(32) )
  └─ Temporal attention weights across 10 time windows
  │  Output: context Batch × 128,  avg_weights Batch × 10
  │
  ▼
[4. Residual Skip Connection & Layer Normalization]
  └─ fused = LayerNorm( latest_LSTM_h + attention_context )
  │  Output: Batch × 128
  │
  ├────────────────────────┬────────────────────────┐
  ▼                        ▼                        ▼
[HEAD 1: State Dynamics] [HEAD 2: MITRE Stage]  [HEAD 3: Risk]
• Linear(128, 128)        • Linear(128, 64)       • Linear(128, 64)
• LayerNorm + GELU        • LayerNorm + GELU       • LayerNorm + GELU
• Dropout(0.2)            • Dropout(0.2)           • Linear(64, 1)
• Linear(128, 30)         • Linear(64, 6)          • Sigmoid()
  │                         │                        │
  ▼                         ▼                        ▼
Ŝ_{t+1} ∈ R^30        Kill-Chain Logits         Risk ∈ [0, 1]
                       (6 MITRE Stages)
```

### Multi-Task Loss Function

```
L_total = 1.0 × L_Huber(Ŝ_{t+1}, S_{t+1})          ← robust continuous state dynamics
        + 0.6 × L_WeightedCE(ŷ_stage, y_stage)       ← rare attack stage correction
        + 0.4 × L_BCE(p̂_risk, y_risk)                ← calibrated infiltration probability
```

- **Smooth L1 (Huber) Loss:** Robust to extreme outlier network bursts
- **Class-Weighted Cross-Entropy:** Accounts for rare attack stages (Initial Access, Lateral Movement) using inverse class frequency weighting
- **Binary Cross-Entropy:** Calibrates the scalar risk probability

---

## 11. Training Pipeline & Parameters

Defined in [`train.py`](train.py) and [`app/config.py`](app/config.py):

| Parameter | Value | Location |
|:---|:---|:---|
| **Dataset Source** | CIC-IDS-2017 multi-stage slices | `data/raw/*.parquet` |
| **Window Size (W)** | 20 raw flows per state window | `NetworkStateAggregator(window_size=20)` |
| **Sequence Length (L)** | 10 historical timesteps per sample | `NetworkStateAggregator(sequence_length=10)` |
| **Input Features** | 30 continuous engineered metrics | `src/state_aggregator.py` `STATE_FEATURE_NAMES` |
| **Split Ratio** | 70% Train / 15% Val / 15% Test (Chronological) | `train.py` |
| **Optimizer** | AdamW (lr=3e-3, weight_decay=1e-4) | `src/world_model_core.py` |
| **LR Scheduler** | CosineAnnealingWarmRestarts (η_min=1e-5) | `src/world_model_core.py` |
| **Batch Size** | 128 | `train.py` |
| **Epochs** | 8 | `train.py` |
| **Gradient Clipping** | max_norm=0.5 | `src/world_model_core.py` |

---

## 12. MITRE ATT&CK Integration

### Kill-Chain Stage Mapping (src/mitre_mapper.py)

| Stage Index | Stage Name | Tactic ID | CIC-IDS-2017 Labels |
|:---:|:---|:---|:---|
| 0 | Normal / Baseline | — | BENIGN |
| 1 | Reconnaissance | TA0043 | PortScan |
| 2 | Initial Access | TA0001 | FTP-Patator, SSH-Patator, Web Attacks |
| 3 | Lateral Movement | TA0008 | Infiltration |
| 4 | Command & Control | TA0011 | Bot, Heartbleed |
| 5 | Exfiltration & Impact | TA0010/TA0040 | DDoS, DoS variants |

### 39-Campaign Markov Model (src/attack_chain_predictor.py)

The `AttackChainPredictor` parses all STIX v2.1 bundles from `data/mitre/attack_flows/` and builds:

1. **Tactic Transition Matrix:** `{from_tactic_id → {to_tactic_id → count}}` — normalized to probabilities
2. **Technique Transition Matrix:** `{from_technique_id → {to_technique_id → count}}`
3. **Campaign Metadata:** NCISS severity scores (0–100) per campaign

**Beam Search Chain Prediction:**
```python
predictor.predict_chain("TA0001", horizon=4, beam_width=3)
# Returns top-3 most likely 4-step attack chains with cumulative probabilities
```

---

## 13. Explainability Engine (src/temporal_explainer.py)

The `TemporalExplainer` provides two complementary XAI mechanisms:

### 1. Temporal Attention Weights
- Output: `attn_weights ∈ R^{10}` — one weight per historical time window
- Shows which of the past 10 observations (e.g. t-7, t-4, t-1) most influenced the current prediction
- Rendered as a heatmap in Dashboard Tab 07

### 2. Gradient Saliency (Input × Gradient)
- Computes `|∂output/∂input| × |input|` for all 30 features across the sequence
- Identifies the exact network features (e.g. `syn_flag_count`, `dst_port_entropy`) driving the alert
- Rendered as a ranked bar chart in Dashboard Tab 07

---

## 14. REST API Endpoints (app/api.py)

| Method | Endpoint | Parameters | Description |
|:---|:---|:---|:---|
| `GET` | `/api/threat-overview` | — | Live infiltration risk, MITRE stage, lead-time, campaign context |
| `GET` | `/api/forecast` | `k` (int, default 5) | K-step forward trajectory (historical + predicted points) |
| `GET` | `/api/explainability` | — | Top-10 features, attention weights, target prediction |
| `GET` | `/api/mitre` | `tactic` (e.g. `TA0001`) | Markov next-tactic predictions, beam-search chains, severity |
| `GET` | `/api/scenario` | `name` (e.g. `infiltration`) | Load and analyze a real CIC-IDS-2017 scenario slice |
| `GET` | `/api/benchmark` | — | Model comparison results from `results/world_model_benchmark.csv` |
| `POST` | `/api/simulate` | `syn_rate`, `port_entropy`, `k_steps` | Custom K-step rollout with user-defined parameters |

---

## 15. Frontend Dashboard (10 Intelligence Tabs)

Served from `frontend/` by `app/api.py` at `http://localhost:8000/`:

| Tab | Name | Key Metric |
|:---|:---|:---|
| **01** | Threat Overview | Infiltration % · Current Stage · Lead-Time |
| **02** | Network Topology | Live node compromise status (SVG) |
| **03** | Forecast Timeline | NOW divider · future probability curve |
| **04** | Incident Chronology | Timestamped kill-chain progression |
| **05** | Traffic Forensics | Per-flow SYN/ACK flags · byte volumes |
| **06** | MITRE ATT&CK Matrix | Markov probabilities · NCISS severity (85–95/100) |
| **07** | Model Explainability | PSH Flag +0.36 · Attention heatmap |
| **08** | K-Step Simulation | Drag sliders → live neural inference |
| **09** | Benchmark Metrics | F1-score · +10s–20s Lead-Time vs 0.0s |
| **10** | Incident Dossier | PDF print · JSON export |

---

## 16. Benchmark Results

```
=======================================================================================================================
                         BENCHMARK EVALUATION REPORT (SIH PS #26153)
=======================================================================================================================
Model                           Accuracy  Precision  Recall  F1-Score  ROC-AUC  FPR      Lead-Time
-----------------------------------------------------------------------------------------------------------------------
Logistic Regression (Baseline)   0.9718    0.9890    0.9718   0.9781   0.9973  0.98%    0.0s (Reactive Only)
Random Forest (Static ML)        0.9084    0.9840    0.9084   0.9385   0.9981  0.98%    0.0s (Reactive Only)
Causal World Model (Ours)        0.9394    0.9878    0.9394   0.9601   0.9952  1.96%   +10.0s – 20.0s (Predictive)
=======================================================================================================================
```

**The definitive differentiator: +10.0s to +20.0s advance predictive lead-time** that static classifiers can never achieve because they cannot simulate future network states.

---

## 17. Source Package Overview (src/)

| Module | Class(es) | Responsibility |
|:---|:---|:---|
| [`src/mitre_mapper.py`](src/mitre_mapper.py) | `MITREStage`, `MITREMapper` | Maps raw dataset labels → MITRE ATT&CK kill-chain stages |
| [`src/state_aggregator.py`](src/state_aggregator.py) | `NetworkStateAggregator` | Computes 30-D state vectors and builds sequence datasets |
| [`src/world_model_core.py`](src/world_model_core.py) | `WorldModelDynamics`, `WorldModelTrainer` | PyTorch LSTM + Attention model, training loop |
| [`src/forecaster.py`](src/forecaster.py) | `KStepForecaster` | K-step autoregressive forward rollout engine |
| [`src/temporal_explainer.py`](src/temporal_explainer.py) | `TemporalExplainer` | Attention heatmap + gradient saliency XAI |
| [`src/attack_chain_predictor.py`](src/attack_chain_predictor.py) | `AttackChainPredictor` | 39-campaign Markov model + NCISS severity |
| [`src/benchmark.py`](src/benchmark.py) | `WorldModelBenchmark` | Formal evaluation vs LR & RF baselines |

## 18. Application Layer (app/)

| Module | Responsibility |
|:---|:---|
| [`app/api.py`](app/api.py) | REST API server, `ModelService` singleton, static frontend serving |
| [`app/config.py`](app/config.py) | All directory paths, hyperparameters, environment variable support |

---

## 19. Running the Full System

```bash
# Clone
git clone https://github.com/Meetvirugama/Attack_Forecasting.git
cd Attack_Forecasting

# Install
pip install -r requirements.txt

# Launch server + open dashboard
python run_server.py

# (Optional) Retrain model on fresh CIC-IDS-2017 data in data/raw/
python train.py

# Run unit tests
python -m pytest tests/ -v
```

---

## 20. Key Design Decisions

| Decision | Rationale |
|:---|:---|
| **LSTM over Transformer** | Causal autoregressive rollout requires sequential hidden state; LSTMs are more efficient at inference for short sequences (10 timesteps) |
| **Multi-Task Loss** | State dynamics (Huber) + stage classification (Weighted CE) + risk (BCE) jointly constrain the latent representation |
| **Class Weights in CE** | Lateral Movement and Initial Access are rare (<2% of flows) but critical — inverse-frequency weighting prevents false negative suppression |
| **Gradient Saliency over SHAP** | SHAP TreeExplainer doesn't apply to PyTorch; gradient × input provides model-native attribution without a surrogate |
| **Offline-Only Architecture** | No cloud, no external API calls — safe for air-gapped Critical Information Infrastructure deployment |
| **src/ + app/ separation** | src/ contains pure ML logic (no I/O); app/ owns all server and config concerns — enables easy testing of ML modules in isolation |
