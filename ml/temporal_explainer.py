"""
Temporal Explainability & Feature Attribution Module for SIH PS 26153

Provides dual-mode interpretability for World Model dynamic predictions:
1. Temporal Self-Attention Heatmaps: identifies critical historical time windows
2. Feature Attribution via Gradient/Perturbation and SHAP integration
"""

import numpy as np
import torch
import matplotlib.pyplot as plt
try:
    import seaborn as sns
except ImportError:
    sns = None
from typing import Dict, List, Optional, Tuple, Union, Any
from pathlib import Path
import logging

from .state_aggregator import NetworkStateAggregator
from .world_model_core import WorldModelDynamics

logger = logging.getLogger(__name__)


class TemporalExplainer:
    """
    Computes and plots temporal attention distributions and feature importance
    driving the World Model's attack forecasting decisions.
    """

    def __init__(self, model: WorldModelDynamics, feature_names: Optional[List[str]] = None):
        self.model = model
        self.feature_names = feature_names or NetworkStateAggregator.STATE_FEATURE_NAMES
        self.device = next(model.parameters()).device

    def explain_sequence(
        self,
        x_seq: np.ndarray,
        target_stage: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Computes temporal attention weights and integrated feature saliency.

        Args:
            x_seq: Shape (Seq_len, Input_dim)
            target_stage: Optional MITRE stage index to explain
        """
        self.model.eval()
        tensor_x = torch.tensor(x_seq, dtype=torch.float32).unsqueeze(0).to(self.device)
        tensor_x.requires_grad_(True)

        pred_next, mitre_logits, risk_score, attn_weights = self.model(tensor_x)

        # 1. Attention distribution across past time steps
        attn_dist = attn_weights.squeeze(0).detach().cpu().numpy() # (Seq_len,)

        # 2. Gradient-based Saliency over input features
        if target_stage is not None:
            score = mitre_logits[0, target_stage]
        else:
            score = risk_score[0, 0]

        self.model.zero_grad()
        score.backward()

        # Feature saliency = |grad * input| summed over sequence
        grad = tensor_x.grad.squeeze(0).detach().cpu().numpy()
        saliency = np.abs(grad * x_seq) # (Seq_len, Input_dim)

        overall_feature_importance = np.mean(saliency, axis=0) # (Input_dim,)
        top_indices = np.argsort(overall_feature_importance)[-10:][::-1]

        top_features = [
            {
                'feature': self.feature_names[i] if i < len(self.feature_names) else f'feature_{i}',
                'importance': float(overall_feature_importance[i]),
                'index': int(i)
            }
            for i in top_indices
        ]

        return {
            'attention_weights': attn_dist.tolist(),
            'top_features': top_features,
            'saliency_matrix': saliency,
            'predicted_risk': float(risk_score.item()),
            'predicted_stage_idx': int(torch.argmax(mitre_logits, dim=-1).item())
        }

    def plot_attention_heatmap(
        self,
        attention_weights: List[float],
        save_path: Optional[Union[str, Path]] = None,
        title: str = "World Model Temporal Attention"
    ) -> plt.Figure:
        """
        Visualizes attention weights over the sequence history windows.
        """
        fig, ax = plt.subplots(figsize=(10, 2.5))
        data = np.array(attention_weights).reshape(1, -1)
        steps = [f"t-{len(attention_weights)-1-i}" for i in range(len(attention_weights))]

        sns.heatmap(
            data,
            annot=True,
            fmt=".3f",
            cmap="YlOrRd",
            xticklabels=steps,
            yticklabels=["Attention"],
            cbar=True,
            ax=ax
        )
        ax.set_title(title, fontsize=12, fontweight='bold')
        ax.set_xlabel("Historical Time Windows", fontsize=10)
        plt.tight_layout()

        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            plt.close(fig)

        return fig
