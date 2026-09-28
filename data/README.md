# Data Directory

This directory contains all datasets and threat intelligence resources for the Attack Forecasting project.

---

## Directory Structure

```
data/
├── raw/                              # CIC-IDS-2017 multi-stage attack slices
│   ├── Thursday-WorkingHours-Afternoon-Infilteration.parquet
│   ├── Tuesday_Patator.parquet
│   ├── PortScan.parquet
│   ├── WebAttacks.parquet
│   ├── Wednesday_DoS.parquet
│   └── Friday_DDoS.parquet
│
├── mitre/                            # MITRE ATT&CK threat intelligence data
│   ├── attack_flows/                 # 39 real-world STIX v2.1 campaign bundles
│   │   ├── SolarWinds.json
│   │   ├── Conti Ransomware.json
│   │   ├── NotPetya.json
│   │   ├── FIN13 Case 1.json
│   │   ├── Black Basta Ransomware.json
│   │   └── ... (34 more campaigns)
│   └── severity/
│       └── MITRE_Campaign_Severity_Scores.csv   # NCISS severity scores (0–100)
│
└── README.md                         # This file
```

---

## Dataset Information

### CIC-IDS-2017 (Network Telemetry — `data/raw/`)

The primary training and evaluation dataset. Raw files are **NOT tracked by git** (see `.gitignore`) due to size.

- **Source:** [Canadian Institute for Cybersecurity](https://www.unb.ca/cic/datasets/ids-2017.html)
- **Description:** Realistic multi-stage network intrusion dataset generated with realistic background traffic
- **Features:** 80+ NetFlow network traffic features
- **Attack Types Covered:**
  - Port Scan (Reconnaissance)
  - FTP-Patator & SSH-Patator (Initial Access / Brute Force)
  - Infiltration (Lateral Movement)
  - Web Attacks: Brute Force, XSS, SQL Injection
  - DoS: slowloris, Slowhttptest, Hulk, GoldenEye
  - DDoS (Exfiltration & Impact)
  - Botnet (Command & Control)
- **Size:** ~2.8 million records across all attack scenario files

**To obtain the dataset:**

```bash
# Download from UNB CIC (requires registration)
# https://www.unb.ca/cic/datasets/ids-2017.html

# Or via Kaggle (requires kaggle CLI)
kaggle datasets download -d cicdataset/cicids2017
```

Place Parquet or CSV files in `data/raw/` before running `train.py`.

---

### MITRE ATT&CK Attack Flows (`data/mitre/attack_flows/`)

39 real-world adversary campaign STIX v2.1 bundles from the [MITRE Attack Flow](https://center-for-threat-informed-defense.github.io/attack-flow/) project.

These are used by [`src/attack_chain_predictor.py`](../src/attack_chain_predictor.py) to build a first-order Markov transition model over MITRE ATT&CK tactic sequences.

**Included Campaigns (39 total):**

| Campaign | Threat Actor Type | NCISS Severity |
|:---|:---|:---:|
| SolarWinds | Nation-State APT (Supply Chain) | 95 |
| Conti Ransomware | Ransomware Group | 85 |
| NotPetya | Destructive Nation-State | 91 |
| Black Basta Ransomware | Ransomware Group | 83 |
| REvil | Ransomware-as-a-Service | 82 |
| Ivanti Vulnerabilities | Exploit-Focused APT | 82 |
| WhisperGate | Nation-State Wiper | 80 |
| Maastricht University Ransomware | Ransomware | 79 |
| Shamoon | Destructive Malware | 78 |
| Ragnar Locker | Ransomware Group | 77 |
| Cobalt Kitty Campaign | APT | 76 |
| FIN13 (Cases 1 & 2) | Financial Threat Actor | 74 |
| Turla (Carbon & Snake) | Nation-State Espionage | 74 |
| ... | *(and 25 more)* | |

---

### Severity Scores (`data/mitre/severity/`)

`MITRE_Campaign_Severity_Scores.csv` maps campaign names to their **NCISS (National Cyber Incident Scoring System) severity scores** on a 0–100 scale.

This is used to weight and contextualize MITRE ATT&CK chain predictions in the SOC dashboard.

---

## Notes

- `data/raw/*.parquet` and `data/raw/*.csv` files are **excluded from git** (see `.gitignore`)
- `data/mitre/` JSON files and the severity CSV **are tracked** in git (lightweight, essential for offline operation)
- The `src/attack_chain_predictor.py` module auto-discovers attack flow JSONs from `data/mitre/attack_flows/`
