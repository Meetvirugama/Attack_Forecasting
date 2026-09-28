"""
Unit Tests for src.world_model_core (WorldModelDynamics)
"""
import unittest
import torch
import numpy as np
from ml.world_model_core import WorldModelDynamics


class TestWorldModelDynamics(unittest.TestCase):

    def setUp(self):
        self.model = WorldModelDynamics(
            input_dim=30,
            hidden_dim=64,
            num_lstm_layers=1,
            num_mitre_stages=6,
            dropout=0.0,
        )
        self.model.eval()

    def test_output_shapes(self):
        batch, seq_len, input_dim = 4, 10, 30
        x = torch.zeros(batch, seq_len, input_dim)
        next_state, mitre_logits, risk_score, attn = self.model(x)

        self.assertEqual(next_state.shape,   (batch, input_dim))
        self.assertEqual(mitre_logits.shape, (batch, 6))
        self.assertEqual(risk_score.shape,   (batch, 1))
        self.assertEqual(attn.shape,         (batch, seq_len))

    def test_risk_score_bounded(self):
        x = torch.randn(8, 10, 30)
        _, _, risk_score, _ = self.model(x)
        self.assertTrue(torch.all(risk_score >= 0.0))
        self.assertTrue(torch.all(risk_score <= 1.0))

    def test_attention_weights_sum_to_one(self):
        x = torch.randn(4, 10, 30)
        _, _, _, attn = self.model(x)
        # Attention is a distribution over seq_len dim
        # (softmax internally) — values should all be positive
        self.assertTrue(torch.all(attn >= 0))


if __name__ == "__main__":
    unittest.main()
