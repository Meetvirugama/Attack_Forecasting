"""
CyberLens — ML Package
SIH Problem Statement #26153

This package contains the core AI/ML modules for network threat prediction.

Modules:
  threat_predictor    — LSTM + Multi-Head Attention model
  traffic_analyzer    — 30-D network state vector computation
  risk_forecaster     — K-step autoregressive rollout engine
  feature_insight     — Explainability (attention + gradient saliency)
  attack_path_mapper  — 39-campaign MITRE Markov model
  threat_stage_mapper — CIC-IDS-2017 label → MITRE ATT&CK stage mapping
  model_comparison    — Benchmark vs Logistic Regression / Random Forest
"""

from .threat_predictor    import ThreatPredictor, ThreatTrainer
from .traffic_analyzer    import TrafficAnalyzer
from .risk_forecaster     import RiskForecaster
from .feature_insight     import FeatureInsight
from .attack_path_mapper  import AttackPathMapper, get_path_mapper
from .threat_stage_mapper import ThreatStage, ThreatStageMapper
from .model_comparison    import ModelComparison

__all__ = [
    "ThreatPredictor",
    "ThreatTrainer",
    "TrafficAnalyzer",
    "RiskForecaster",
    "FeatureInsight",
    "AttackPathMapper",
    "get_path_mapper",
    "ThreatStage",
    "ThreatStageMapper",
    "ModelComparison",
]
