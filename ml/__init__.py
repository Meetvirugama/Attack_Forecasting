"""
Attack Forecasting — Source Package
SIH Problem Statement #26153

This package contains the core ML/AI logic for:
- MITRE ATT&CK kill-chain stage mapping
- Network state aggregation and feature engineering
- Causal World Model dynamics (LSTM + Multi-Head Temporal Attention)
- K-step forward rollout forecasting engine
- Temporal attention explainability and feature attribution
- MITRE attack chain prediction (Markov model over 39 campaigns)
- Benchmarking against static ML baselines
"""

from .mitre_mapper import MITREStage, MITREMapper
from .state_aggregator import NetworkStateAggregator
from .world_model_core import WorldModelDynamics, WorldModelTrainer
from .forecaster import KStepForecaster
from .temporal_explainer import TemporalExplainer
from .benchmark import WorldModelBenchmark
from .attack_chain_predictor import AttackChainPredictor, get_predictor

__all__ = [
    "MITREStage",
    "MITREMapper",
    "NetworkStateAggregator",
    "WorldModelDynamics",
    "WorldModelTrainer",
    "KStepForecaster",
    "TemporalExplainer",
    "WorldModelBenchmark",
    "AttackChainPredictor",
    "get_predictor",
]
