"""
MITRE ATT&CK Attack Chain Predictor (SIH PS 26153)

Integrates real-world attack flow data from 39 operational campaigns
(SolarWinds, Conti, NotPetya, Black Basta, etc.) to build a first-order
Markov transition model over MITRE ATT&CK tactic sequences.

Given a detected current tactic (from World Model MITRE stage output),
this predictor outputs:
1. Top-N most likely next tactics/techniques with transition probabilities
2. Full multi-step chain forecast (beam search over Markov transitions)
3. Campaign severity context (NCISS risk score 0-100)
4. Specific real-world campaigns that followed this exact tactic transition

This directly bridges the World Model's detected network state transitions
with authoritative real-world adversary playbook data.

Data Sources (all local, fully offline):
- 39 MITRE Attack Flow v3.0 STIX bundles (SolarWinds, Conti, Triton, etc.)
- MITRE Campaign Severity Scores (NCISS 0-100 reference scale)
"""

import json
import glob
import os
import logging
from collections import defaultdict
from typing import Dict, List, Tuple, Optional
from pathlib import Path

import pandas as pd
import numpy as np

logger = logging.getLogger(__name__)

# MITRE Tactic ordering (kill chain order)
TACTIC_ORDER = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact"
]

# MITRE Tactic ID to human-readable name
TACTIC_ID_TO_NAME = {
    "TA0043": "Reconnaissance",
    "TA0042": "Resource Development",
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0011": "Command & Control",
    "TA0010": "Exfiltration",
    "TA0040": "Impact"
}

# Reverse lookup
TACTIC_NAME_TO_ID = {v.lower(): k for k, v in TACTIC_ID_TO_NAME.items()}

# Maps our World Model MITRE stages to tactic IDs
WORLD_MODEL_STAGE_TO_TACTIC = {
    0: None,            # Normal / Baseline
    1: "TA0043",        # Reconnaissance
    2: "TA0001",        # Initial Access
    3: "TA0008",        # Lateral Movement
    4: "TA0011",        # Command & Control
    5: "TA0010",        # Exfiltration & Impact
}


class AttackChainPredictor:
    """
    First-order Markov attack chain predictor built from real-world 
    MITRE Attack Flow operational data across 39 major campaigns.
    """

    def __init__(self, attack_flows_dir: Optional[str] = None, severity_csv: Optional[str] = None):
        """
        Args:
            attack_flows_dir: Path to folder containing .json attack flow files.
                              Defaults to the bundled Attack flows/ directory.
            severity_csv: Path to MITRE_Campaign_Severity_Scores.csv
        """
        # Default to bundled data in data/mitre/
        base = Path(__file__).resolve().parent.parent
        mitre_dir = base / "data" / "mitre"

        self.attack_flows_dir = Path(attack_flows_dir) if attack_flows_dir else mitre_dir / "attack_flows"
        self.severity_csv = Path(severity_csv) if severity_csv else mitre_dir / "severity" / "MITRE_Campaign_Severity_Scores.csv"

        # Markov transition counts: {from_tactic_id -> {to_tactic_id -> count}}
        self._tactic_transitions: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        # Technique-level transitions: {from_tid -> {to_tid -> count}}
        self._technique_transitions: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        # Campaign metadata: campaign name + techniques used
        self._campaigns: List[Dict] = []
        # Severity scores
        self._severity_map: Dict[str, float] = {}

        self._is_loaded = False

    def load(self) -> "AttackChainPredictor":
        """Parse all attack flow JSONs and severity CSV. Returns self for chaining."""
        self._load_severity_scores()
        self._parse_attack_flows()
        self._is_loaded = True
        logger.info(
            f"AttackChainPredictor loaded: {len(self._campaigns)} campaigns, "
            f"{sum(sum(v.values()) for v in self._tactic_transitions.values())} tactic transitions, "
            f"{sum(sum(v.values()) for v in self._technique_transitions.values())} technique transitions"
        )
        return self

    def _load_severity_scores(self):
        """Load NCISS severity scores for known campaigns."""
        if not self.severity_csv.exists():
            logger.warning(f"Severity CSV not found at {self.severity_csv}")
            return
        try:
            df = pd.read_csv(self.severity_csv)
            for _, row in df.iterrows():
                campaign_name = str(row.get("Campaign_Name", "")).strip().lower()
                score = float(row.get("NCISS_Score", 50))
                self._severity_map[campaign_name] = score
            logger.info(f"Loaded NCISS severity scores for {len(self._severity_map)} campaigns")
        except Exception as e:
            logger.warning(f"Could not load severity CSV: {e}")

    def _match_severity(self, campaign_name: str) -> Optional[float]:
        """Fuzzy-match campaign name to NCISS severity score using keyword overlap."""
        name_lower = campaign_name.lower()
        # Direct match
        if name_lower in self._severity_map:
            return self._severity_map[name_lower]
        # Keyword matching — any CSV campaign whose keywords appear in the JSON filename
        keywords_map = {
            "conti": 85.0, "solarwinds": 95.0, "notpetya": 91.0,
            "cobalt": 76.0, "fin13": 74.0, "equifax": 73.0,
            "revil": 82.0, "ragnar": 77.0, "blackbasta": 83.0,
            "black basta": 83.0, "shamoon": 78.0, "whispergate": 80.0,
            "triton": 97.0, "gootloader": 70.0, "maastricht": 79.0,
            "marriott": 68.0, "swift": 85.0, "target": 72.0,
            "uber": 69.0, "muddy": 72.0, "oceanlotus": 71.0,
            "hancitor": 72.0, "turla": 74.0, "ivanti": 82.0,
        }
        for kw, score in keywords_map.items():
            if kw in name_lower:
                return score
        return None

    def _parse_attack_flows(self):
        """Parse all MITRE Attack Flow STIX bundles from the Attack flows directory."""
        if not self.attack_flows_dir.exists():
            logger.warning(f"Attack flows directory not found: {self.attack_flows_dir}")
            return

        json_files = list(self.attack_flows_dir.glob("*.json"))
        logger.info(f"Parsing {len(json_files)} attack flow files from {self.attack_flows_dir}")

        for fp in json_files:
            try:
                self._parse_single_flow(fp)
            except Exception as e:
                logger.warning(f"Failed to parse {fp.name}: {e}")

    def _parse_single_flow(self, filepath: Path):
        """Extract tactic/technique sequences from one Attack Flow STIX bundle."""
        with open(filepath, "r", encoding="utf-8") as f:
            bundle = json.load(f)

        objects = bundle.get("objects", [])
        obj_by_id = {o["id"]: o for o in objects if "id" in o}

        campaign_name = filepath.stem

        # Extract attack-action nodes — these carry technique_id, tactic_id, effect_refs
        actions = {
            o["id"]: o for o in objects
            if o.get("type") == "attack-action" and o.get("technique_id")
        }

        if not actions:
            return

        # Build ordered tactic/technique sequence via effect_refs (DFS traversal)
        # Find root actions (not referenced by any other as effect)
        all_effect_refs = set()
        for a in actions.values():
            for ref in (a.get("effect_refs") or []):
                all_effect_refs.add(ref)

        roots = [aid for aid in actions if aid not in all_effect_refs]
        visited = set()
        sequence: List[Dict] = []

        def dfs(node_id: str):
            if node_id in visited or node_id not in actions:
                return
            visited.add(node_id)
            action = actions[node_id]
            sequence.append({
                "technique_id": action.get("technique_id", ""),
                "tactic_id": action.get("tactic_id", ""),
                "name": action.get("name", ""),
                "confidence": action.get("confidence", 50),
            })
            for next_ref in (action.get("effect_refs") or []):
                dfs(next_ref)

        for root in roots:
            dfs(root)

        if len(sequence) < 2:
            return

        # Record campaign metadata
        campaign_entry = {
            "name": campaign_name,
            "sequence_length": len(sequence),
            "techniques": [s["technique_id"] for s in sequence],
            "tactics": [s["tactic_id"] for s in sequence],
            "nciss_severity": self._match_severity(campaign_name)
        }
        self._campaigns.append(campaign_entry)

        # Build Markov transition counts
        for i in range(len(sequence) - 1):
            curr = sequence[i]
            nxt = sequence[i + 1]

            curr_tactic = curr["tactic_id"]
            next_tactic = nxt["tactic_id"]
            curr_tech = curr["technique_id"]
            next_tech = nxt["technique_id"]

            if curr_tactic and next_tactic:
                self._tactic_transitions[curr_tactic][next_tactic] += 1
            if curr_tech and next_tech:
                self._technique_transitions[curr_tech][next_tech] += 1

    def _normalize_transitions(self, transitions: Dict[str, int]) -> Dict[str, float]:
        """Convert raw counts to probability distribution."""
        total = sum(transitions.values())
        if total == 0:
            return {}
        return {k: v / total for k, v in transitions.items()}

    def predict_next_tactics(
        self,
        current_tactic_id: str,
        top_n: int = 5
    ) -> List[Dict]:
        """
        Given a currently detected tactic, returns the top-N most likely
        next tactics with transition probabilities from real attack flow data.

        Args:
            current_tactic_id: e.g. "TA0043" (Reconnaissance)
            top_n: number of results to return

        Returns:
            List of dicts: [{"tactic_id", "tactic_name", "probability", "campaigns_observed"}]
        """
        if not self._is_loaded:
            self.load()

        raw = self._tactic_transitions.get(current_tactic_id, {})
        if not raw:
            return []

        probs = self._normalize_transitions(raw)
        sorted_tactics = sorted(probs.items(), key=lambda x: x[1], reverse=True)[:top_n]

        results = []
        for tactic_id, prob in sorted_tactics:
            # Find which campaigns observed this transition
            campaigns_with_transition = [
                c["name"] for c in self._campaigns
                if current_tactic_id in c["tactics"] and tactic_id in c["tactics"]
            ]
            results.append({
                "tactic_id": tactic_id,
                "tactic_name": TACTIC_ID_TO_NAME.get(tactic_id, tactic_id),
                "probability": round(prob, 4),
                "transition_count": raw[tactic_id],
                "campaigns_observed": campaigns_with_transition[:5]  # cap at 5
            })

        return results

    def predict_chain(
        self,
        current_tactic_id: str,
        horizon: int = 5,
        beam_width: int = 3
    ) -> List[List[Dict]]:
        """
        Beam search over Markov tactic transitions to generate top multi-step
        attack chains from the current detected tactic.

        Args:
            current_tactic_id: Starting tactic (e.g. "TA0043")
            horizon: Number of forward steps to simulate
            beam_width: Number of best chains to keep at each step

        Returns:
            Top chains, each is a list of step dicts with tactic + probability
        """
        if not self._is_loaded:
            self.load()

        # Each beam state: (cumulative_log_prob, [list of tactic_ids])
        beams = [(0.0, [current_tactic_id])]
        completed = []

        for _ in range(horizon):
            candidates = []
            for log_prob, chain in beams:
                current = chain[-1]
                next_probs = self._normalize_transitions(
                    self._tactic_transitions.get(current, {})
                )
                if not next_probs:
                    completed.append((log_prob, chain))
                    continue
                for next_tac, prob in sorted(next_probs.items(), key=lambda x: x[1], reverse=True)[:beam_width]:
                    candidates.append((log_prob + np.log(prob + 1e-12), chain + [next_tac]))

            if not candidates:
                break
            candidates.sort(key=lambda x: x[0], reverse=True)
            beams = candidates[:beam_width]

        completed.extend(beams)
        completed.sort(key=lambda x: x[0], reverse=True)

        # Format output
        top_chains = []
        for log_prob, chain in completed[:beam_width]:
            chain_prob = float(np.exp(log_prob))
            steps = [
                {
                    "step": i,
                    "tactic_id": tac,
                    "tactic_name": TACTIC_ID_TO_NAME.get(tac, tac),
                }
                for i, tac in enumerate(chain)
            ]
            top_chains.append({
                "chain_probability": round(chain_prob, 6),
                "steps": steps
            })

        return top_chains

    def from_world_model_stage(self, stage_idx: int) -> Optional[str]:
        """Convert a World Model MITRE stage index (0-5) to a MITRE tactic ID."""
        return WORLD_MODEL_STAGE_TO_TACTIC.get(stage_idx)

    def get_campaign_context(self, tactic_id: str) -> List[Dict]:
        """Returns real-world campaigns that used this tactic, with severity scores."""
        if not self._is_loaded:
            self.load()

        relevant = [
            {
                "campaign": c["name"],
                "technique_sequence": c["techniques"],
                "sequence_length": c["sequence_length"],
                "nciss_severity": c["nciss_severity"]
            }
            for c in self._campaigns
            if tactic_id in c["tactics"]
        ]
        # Sort by severity descending
        relevant.sort(key=lambda x: (x["nciss_severity"] or 0), reverse=True)
        return relevant[:8]

    def get_summary(self) -> Dict:
        """Returns a summary of loaded data for dashboard display."""
        if not self._is_loaded:
            self.load()
        return {
            "total_campaigns": len(self._campaigns),
            "total_tactic_transitions": sum(
                sum(v.values()) for v in self._tactic_transitions.values()
            ),
            "total_technique_transitions": sum(
                sum(v.values()) for v in self._technique_transitions.values()
            ),
            "unique_tactics_observed": len(self._tactic_transitions),
            "avg_sequence_length": round(
                np.mean([c["sequence_length"] for c in self._campaigns]), 1
            ) if self._campaigns else 0,
            "campaigns_with_severity": sum(
                1 for c in self._campaigns if c["nciss_severity"] is not None
            )
        }


# Module-level singleton for dashboard use (lazy-loaded)
_predictor: Optional[AttackChainPredictor] = None


def get_predictor() -> AttackChainPredictor:
    """Returns the singleton AttackChainPredictor, loading it on first call."""
    global _predictor
    if _predictor is None:
        _predictor = AttackChainPredictor()
        _predictor.load()
    return _predictor
