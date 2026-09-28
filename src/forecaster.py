"""
K-Step Forward Rollout & Attack Forecasting Engine for SIH PS 26153

This module implements autoregressive forward simulation:
Given observed network traffic state history S_t-W:t, it simulates future
environment transitions K steps into the future, computing:
1. Time-series Infiltration Probability score P(Infiltration_t+1 ... P_t+K)
2. Predicted MITRE ATT&CK Kill-Chain progression
3. Early warning Lead-Time metric (seconds before compromise threshold)
4. Feature contribution attribution driving each forward rollout step
"""

import torch
import numpy as np
from typing import Dict, List, Any, Optional, Tuple, Union
import logging

from .mitre_mapper import MITREMapper, MITREStage
from .world_model_core import WorldModelDynamics
from .state_aggregator import NetworkStateAggregator

logger = logging.getLogger(__name__)


class KStepForecaster:
    """
    Forecasting Engine that executes recursive K-step forward simulation
    using a trained World Model dynamics network.
    """

    def __init__(
        self,
        model: WorldModelDynamics,
        device: Optional[str] = None,
        compromise_threshold: float = 0.65,
        window_duration_seconds: float = 2.0
    ):
        self.device = torch.device(device if device else ('cuda' if torch.cuda.is_available() else 'cpu'))
        self.model = model.to(self.device)
        self.model.eval()
        self.compromise_threshold = compromise_threshold
        self.window_duration_seconds = window_duration_seconds

    def forecast_trajectory(
        self,
        current_history: np.ndarray,
        k_steps: int = 5
    ) -> Dict[str, Any]:
        """
        Roll out K steps into the future from current observed history.

        Args:
            current_history: Tensor/Array of shape (Seq_len, Input_dim) representing S_t-W:t
            k_steps: Number of forward lookahead time windows (default: 5)

        Returns:
            Dictionary containing:
            - timeline_steps: [1, 2, ..., K]
            - time_offsets_seconds: [2s, 4s, 6s, ...]
            - infiltration_probabilities: [p_1, p_2, ..., p_K]
            - predicted_stages: [MITREStage.RECON, MITREStage.INITIAL_ACCESS, ...]
            - stage_names: ['Reconnaissance', 'Initial Access', ...]
            - stage_colors: ['#17becf', '#ff7f0e', ...]
            - lead_time_seconds: Seconds until threshold crossing (or None if benign)
            - top_driving_features: list of top features per step
            - attention_weights: latest attention distribution over past history
        """
        assert len(current_history.shape) == 2, "current_history must be (Seq_len, Input_dim)"

        # Working buffer for autoregressive rollout
        buffer = torch.tensor(current_history, dtype=torch.float32).unsqueeze(0).to(self.device) # (1, Seq_len, Input_dim)

        infiltration_probs = []
        predicted_stages = []
        stage_names = []
        stage_colors = []
        simulated_states = []
        lead_time_seconds = None
        latest_attention = None

        with torch.no_grad():
            for step in range(1, k_steps + 1):
                # Predict transition S_t+step
                pred_next_state, mitre_logits, risk_score, attn_weights = self.model(buffer)

                if step == 1:
                    latest_attention = attn_weights.squeeze(0).cpu().numpy().tolist()

                # Extract risk probability
                prob = float(risk_score.item())
                infiltration_probs.append(prob)

                # Extract MITRE stage
                stage_idx = int(torch.argmax(mitre_logits, dim=-1).item())
                predicted_stages.append(stage_idx)
                stage_names.append(MITREMapper.get_stage_name(stage_idx))
                stage_colors.append(MITREMapper.get_stage_color(stage_idx))

                # Check lead time
                if prob >= self.compromise_threshold and lead_time_seconds is None:
                    lead_time_seconds = round(step * self.window_duration_seconds, 1)

                sim_state = pred_next_state.squeeze(0).cpu().numpy()
                simulated_states.append(sim_state)

                # Slide window: drop oldest state, append predicted next state
                next_state_tensor = pred_next_state.unsqueeze(1) # (1, 1, Input_dim)
                buffer = torch.cat([buffer[:, 1:, :], next_state_tensor], dim=1)

        time_offsets = [round(i * self.window_duration_seconds, 1) for i in range(1, k_steps + 1)]

        # Determine top driving feature deviations from simulated states
        feature_names = NetworkStateAggregator.STATE_FEATURE_NAMES
        top_driving_features = []
        for state in simulated_states:
            # Rank top magnitude features
            top_indices = np.argsort(np.abs(state))[-5:][::-1]
            step_features = [
                {'feature': feature_names[idx] if idx < len(feature_names) else f'feat_{idx}',
                 'impact_score': float(abs(state[idx]))}
                for idx in top_indices
            ]
            top_driving_features.append(step_features)

        # Overall threat trajectory status
        max_prob = max(infiltration_probs) if infiltration_probs else 0.0
        final_stage = predicted_stages[-1] if predicted_stages else 0

        is_critical = max_prob >= self.compromise_threshold

        return {
            'timeline_steps': list(range(1, k_steps + 1)),
            'time_offsets_seconds': time_offsets,
            'infiltration_probabilities': infiltration_probs,
            'predicted_stages': predicted_stages,
            'stage_names': stage_names,
            'stage_colors': stage_colors,
            'lead_time_seconds': lead_time_seconds,
            'is_critical_threat': is_critical,
            'max_risk_score': max_prob,
            'final_mitre_stage': final_stage,
            'final_stage_name': MITREMapper.get_stage_name(final_stage),
            'top_driving_features': top_driving_features,
            'attention_weights': latest_attention
        }
