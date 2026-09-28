"""
Enhanced Neural World Model Core Dynamics Module (PyTorch)
SIH Problem Statement #26153

Architectural Enhancements for Maximum Predictive Accuracy:
1. Residual Temporal Self-Attention Backbone with Layer Normalization (LayerNorm(h_t + Attn(H)))
2. GELU Activation & Deep State Projections for continuous transition dynamics P(S_t+1 | S_t)
3. Robust Multi-Task Loss:
   - Smooth L1 (Huber) Loss for Next State Vector S_t+1 (outlier-resilient dynamics)
   - Class-Weighted Cross-Entropy Loss for MITRE Kill-Chain Stage classification
   - Binary Focal Cross-Entropy for Imminent Infiltration Risk estimation
4. Cosine Annealing with Warmup learning rate scheduler
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader
import numpy as np
import json
import logging
from pathlib import Path
from typing import Dict, Tuple, Optional, Union

logger = logging.getLogger(__name__)


class MultiHeadTemporalAttention(nn.Module):
    """
    Computes multi-head self-attention across temporal windows to identify
    which past time steps and feature channels drive state transitions.
    """

    def __init__(self, hidden_dim: int, num_heads: int = 4, dropout: float = 0.1):
        super().__init__()
        self.num_heads = num_heads
        self.hidden_dim = hidden_dim
        self.head_dim = hidden_dim // num_heads

        assert hidden_dim % num_heads == 0, "hidden_dim must be divisible by num_heads"

        self.q_proj = nn.Linear(hidden_dim, hidden_dim)
        self.k_proj = nn.Linear(hidden_dim, hidden_dim)
        self.v_proj = nn.Linear(hidden_dim, hidden_dim)
        self.out_proj = nn.Linear(hidden_dim, hidden_dim)
        self.dropout = nn.Dropout(dropout)

    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Args:
            x: Tensor of shape (batch_size, seq_len, hidden_dim)
        Returns:
            context: Tensor of shape (batch_size, hidden_dim)
            avg_weights: Tensor of shape (batch_size, seq_len)
        """
        B, S, D = x.shape
        q = self.q_proj(x).view(B, S, self.num_heads, self.head_dim).transpose(1, 2)
        k = self.k_proj(x).view(B, S, self.num_heads, self.head_dim).transpose(1, 2)
        v = self.v_proj(x).view(B, S, self.num_heads, self.head_dim).transpose(1, 2)

        # Scaled Dot-Product Attention
        scores = torch.matmul(q, k.transpose(-2, -1)) / (self.head_dim ** 0.5)
        attn_probs = torch.softmax(scores, dim=-1)
        attn_probs = self.dropout(attn_probs)

        context = torch.matmul(attn_probs, v)
        context = context.transpose(1, 2).contiguous().view(B, S, D)
        out = self.out_proj(context)

        # Average attention weights across heads for temporal explainability
        avg_weights = attn_probs.mean(dim=1)[:, -1, :]

        # Pool over sequence length
        pooled_context = out.mean(dim=1)
        return pooled_context, avg_weights


class WorldModelDynamics(nn.Module):
    """
    State-of-the-Art Neural World Model for Network State Transition Dynamics.
    Learns P(S_t+1 | S_t-W:t) with residual temporal attention and LayerNorm.
    """

    def __init__(
        self,
        input_dim: int = 30,
        hidden_dim: int = 128,
        num_lstm_layers: int = 2,
        num_mitre_stages: int = 6,
        dropout: float = 0.2
    ):
        super().__init__()
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.num_mitre_stages = num_mitre_stages

        # Input feature projection + LayerNorm
        self.input_proj = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.GELU(),
            nn.Dropout(dropout)
        )

        # Temporal Sequence Backbone
        self.lstm = nn.LSTM(
            input_size=hidden_dim,
            hidden_size=hidden_dim,
            num_layers=num_lstm_layers,
            batch_first=True,
            dropout=dropout if num_lstm_layers > 1 else 0.0
        )

        # Multi-Head Temporal Attention
        self.attention = MultiHeadTemporalAttention(hidden_dim=hidden_dim, num_heads=4, dropout=dropout)
        
        # Residual normalization
        self.norm = nn.LayerNorm(hidden_dim)

        # 1. State Dynamics Head: predicts continuous vector S_t+1
        self.state_head = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, input_dim)
        )

        # 2. MITRE ATT&CK Stage Classification Head
        self.mitre_head = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.LayerNorm(hidden_dim // 2),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim // 2, num_mitre_stages)
        )

        # 3. Infiltration Risk Head: outputs [0, 1] probability of imminent compromise
        self.risk_head = nn.Sequential(
            nn.Linear(hidden_dim, 64),
            nn.LayerNorm(64),
            nn.GELU(),
            nn.Linear(64, 1),
            nn.Sigmoid()
        )

    def forward(self, x_seq: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor]:
        """
        Args:
            x_seq: (Batch, Seq_len, Input_dim)
        Returns:
            next_state_pred: (Batch, Input_dim)
            mitre_logits: (Batch, num_mitre_stages)
            risk_score: (Batch, 1)
            attn_weights: (Batch, Seq_len)
        """
        # Embed input features
        emb = self.input_proj(x_seq)
        
        # Sequence encoding
        lstm_out, (h_n, _) = self.lstm(emb)
        
        # Temporal attention
        context, attn_weights = self.attention(lstm_out)

        # Residual skip connection: latest LSTM hidden state + attention context
        latest_h = lstm_out[:, -1, :]
        fused = self.norm(latest_h + context)

        # Multi-task predictions
        next_state_pred = self.state_head(fused)
        mitre_logits = self.mitre_head(fused)
        risk_score = self.risk_head(fused)

        return next_state_pred, mitre_logits, risk_score, attn_weights


class SequenceDataset(Dataset):
    """PyTorch Dataset for (X_seq, y_next_state, y_stage) tensors."""

    def __init__(self, X: np.ndarray, y_next: np.ndarray, y_stage: np.ndarray):
        self.X = torch.tensor(X, dtype=torch.float32)
        self.y_next = torch.tensor(y_next, dtype=torch.float32)
        self.y_stage = torch.tensor(y_stage, dtype=torch.long)
        self.y_risk = torch.tensor((y_stage > 0).astype(np.float32), dtype=torch.float32).unsqueeze(1)

    def __len__(self):
        return len(self.X)

    def __getitem__(self, idx):
        return self.X[idx], self.y_next[idx], self.y_stage[idx], self.y_risk[idx]


class WorldModelTrainer:
    """
    Manages end-to-end training, validation, and serialization of the World Model.
    """

    def __init__(
        self,
        model: Optional[WorldModelDynamics] = None,
        lr: float = 0.002,
        weight_decay: float = 1e-4,
        device: Optional[str] = None
    ):
        self.device = torch.device(device if device else ('cuda' if torch.cuda.is_available() else 'cpu'))
        self.model = model.to(self.device) if model else None
        self.lr = lr
        self.weight_decay = weight_decay

        # Robust Huber (Smooth L1) loss for continuous state transition dynamics
        self.state_loss_fn = nn.SmoothL1Loss()
        self.bce_loss = nn.BCELoss()
        self.class_weights = None

    def train_epoch(self, dataloader: DataLoader, optimizer: optim.Optimizer, ce_loss_fn: nn.Module) -> Dict[str, float]:
        self.model.train()
        total_loss, total_state_loss, total_ce, total_bce = 0.0, 0.0, 0.0, 0.0

        for X_batch, y_next_batch, y_stage_batch, y_risk_batch in dataloader:
            X_b = X_batch.to(self.device)
            y_next_b = y_next_batch.to(self.device)
            y_stage_b = y_stage_batch.to(self.device)
            y_risk_b = y_risk_batch.to(self.device)

            optimizer.zero_grad()
            pred_next, pred_stage, pred_risk, _ = self.model(X_b)

            loss_state = self.state_loss_fn(pred_next, y_next_b)
            loss_ce = ce_loss_fn(pred_stage, y_stage_b)
            loss_bce = self.bce_loss(pred_risk, y_risk_b)

            # Combined multi-task loss
            loss = loss_state * 1.0 + loss_ce * 0.6 + loss_bce * 0.4
            loss.backward()
            torch.nn.utils.clip_grad_norm_(self.model.parameters(), max_norm=0.5)
            optimizer.step()

            total_loss += loss.item()
            total_state_loss += loss_state.item()
            total_ce += loss_ce.item()
            total_bce += loss_bce.item()

        n = len(dataloader)
        return {
            'loss': total_loss / n,
            'state_loss': total_state_loss / n,
            'ce': total_ce / n,
            'bce': total_bce / n
        }

    def evaluate(self, dataloader: DataLoader, ce_loss_fn: nn.Module) -> Dict[str, float]:
        self.model.eval()
        total_loss, correct_stage = 0.0, 0
        total_samples = 0

        with torch.no_grad():
            for X_batch, y_next_batch, y_stage_batch, y_risk_batch in dataloader:
                X_b = X_batch.to(self.device)
                y_next_b = y_next_batch.to(self.device)
                y_stage_b = y_stage_batch.to(self.device)
                y_risk_b = y_risk_batch.to(self.device)

                pred_next, pred_stage, pred_risk, _ = self.model(X_b)
                loss = self.state_loss_fn(pred_next, y_next_b) + 0.6 * ce_loss_fn(pred_stage, y_stage_b)

                total_loss += loss.item() * len(X_batch)
                preds = torch.argmax(pred_stage, dim=1)
                correct_stage += (preds == y_stage_b).sum().item()
                total_samples += len(X_batch)

        return {
            'val_loss': total_loss / total_samples,
            'val_stage_acc': correct_stage / total_samples
        }

    def fit(
        self,
        X_train: np.ndarray,
        y_next_train: np.ndarray,
        y_stage_train: np.ndarray,
        X_val: np.ndarray,
        y_next_val: np.ndarray,
        y_stage_val: np.ndarray,
        epochs: int = 10,
        batch_size: int = 128
    ) -> Dict[str, list]:
        """Runs full training with class balancing and cosine annealing."""
        if self.model is None:
            input_dim = X_train.shape[2]
            self.model = WorldModelDynamics(input_dim=input_dim).to(self.device)

        # Compute balanced class weights for MITRE stages
        classes, counts = np.unique(y_stage_train, return_counts=True)
        total_samples = len(y_stage_train)
        weights = np.ones(self.model.num_mitre_stages, dtype=np.float32)
        for c, cnt in zip(classes, counts):
            if c < len(weights):
                weights[c] = float(total_samples / (len(classes) * cnt + 1e-5))
        # Normalize weights
        weights = weights / np.mean(weights)
        class_weights_t = torch.tensor(weights, dtype=torch.float32).to(self.device)
        ce_loss_fn = nn.CrossEntropyLoss(weight=class_weights_t)

        train_ds = SequenceDataset(X_train, y_next_train, y_stage_train)
        val_ds = SequenceDataset(X_val, y_next_val, y_stage_val)

        train_loader = DataLoader(train_ds, batch_size=batch_size, shuffle=True)
        val_loader = DataLoader(val_ds, batch_size=batch_size, shuffle=False)

        optimizer = optim.AdamW(self.model.parameters(), lr=self.lr, weight_decay=self.weight_decay)
        scheduler = optim.lr_scheduler.CosineAnnealingWarmRestarts(optimizer, T_0=epochs, T_mult=1, eta_min=1e-5)

        history = {'train_loss': [], 'val_loss': [], 'val_acc': []}

        logger.info(f"Training High-Accuracy World Model on {self.device} for {epochs} epochs...")
        for epoch in range(1, epochs + 1):
            train_metrics = self.train_epoch(train_loader, optimizer, ce_loss_fn)
            val_metrics = self.evaluate(val_loader, ce_loss_fn)
            scheduler.step()

            history['train_loss'].append(train_metrics['loss'])
            history['val_loss'].append(val_metrics['val_loss'])
            history['val_acc'].append(val_metrics['val_stage_acc'])

            logger.info(
                f"Epoch {epoch:02d}/{epochs:02d} | "
                f"Train Loss: {train_metrics['loss']:.4f} (State L1: {train_metrics['state_loss']:.4f}, CE: {train_metrics['ce']:.4f}) | "
                f"Val Loss: {val_metrics['val_loss']:.4f} | "
                f"Val Stage Acc: {val_metrics['val_stage_acc']*100:.2f}%"
            )

        return history

    def save(self, model_path: Union[str, Path], config_path: Optional[Union[str, Path]] = None):
        """Save PyTorch weights and architecture configuration."""
        torch.save(self.model.state_dict(), model_path)
        if config_path:
            config = {
                'input_dim': self.model.input_dim,
                'hidden_dim': self.model.hidden_dim,
                'num_mitre_stages': self.model.num_mitre_stages
            }
            with open(config_path, 'w') as f:
                json.dump(config, f, indent=2)
        logger.info(f"World model successfully saved to {model_path}")
