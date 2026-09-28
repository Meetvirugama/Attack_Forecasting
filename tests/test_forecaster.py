"""
Unit Tests for src.forecaster (KStepForecaster)
"""
import unittest
import numpy as np
import torch
from src.world_model_core import WorldModelDynamics
from src.forecaster import KStepForecaster


class TestKStepForecaster(unittest.TestCase):

    def setUp(self):
        model = WorldModelDynamics(input_dim=30, hidden_dim=64, num_lstm_layers=1, dropout=0.0)
        model.eval()
        self.forecaster = KStepForecaster(model=model, compromise_threshold=0.65, window_duration_seconds=2.0)

    def test_forecast_returns_correct_k_steps(self):
        history = np.zeros((10, 30), dtype=np.float32)
        result = self.forecaster.forecast_trajectory(history, k_steps=5)
        self.assertEqual(len(result["infiltration_probabilities"]), 5)
        self.assertEqual(len(result["stage_names"]), 5)
        self.assertEqual(len(result["timeline_steps"]), 5)

    def test_infiltration_probs_bounded(self):
        history = np.random.rand(10, 30).astype(np.float32)
        result = self.forecaster.forecast_trajectory(history, k_steps=3)
        for p in result["infiltration_probabilities"]:
            self.assertGreaterEqual(p, 0.0)
            self.assertLessEqual(p, 1.0)

    def test_time_offsets_correct(self):
        history = np.zeros((10, 30), dtype=np.float32)
        result = self.forecaster.forecast_trajectory(history, k_steps=3)
        expected_offsets = [2.0, 4.0, 6.0]
        self.assertEqual(result["time_offsets_seconds"], expected_offsets)


if __name__ == "__main__":
    unittest.main()
