"""
Unit Tests for src.mitre_mapper
"""
import unittest
from ml.threat_stage_mapper import ThreatStage, ThreatStageMapper


class TestThreatStageMapper(unittest.TestCase):

    def test_benign_maps_to_normal(self):
        self.assertEqual(ThreatStageMapper.map_label("BENIGN"), ThreatStage.NORMAL)

    def test_portscan_maps_to_recon(self):
        self.assertEqual(ThreatStageMapper.map_label("PortScan"), ThreatStage.RECONNAISSANCE)

    def test_ftp_patator_maps_to_initial_access(self):
        self.assertEqual(ThreatStageMapper.map_label("FTP-Patator"), ThreatStage.INITIAL_ACCESS)

    def test_infiltration_maps_to_lateral_movement(self):
        self.assertEqual(ThreatStageMapper.map_label("Infiltration"), ThreatStage.LATERAL_MOVEMENT)

    def test_bot_maps_to_c2(self):
        self.assertEqual(ThreatStageMapper.map_label("Bot"), ThreatStage.COMMAND_AND_CONTROL)

    def test_ddos_maps_to_exfil_impact(self):
        self.assertEqual(ThreatStageMapper.map_label("DDoS"), ThreatStage.EXFILTRATION_IMPACT)

    def test_get_stage_name(self):
        name = ThreatStageMapper.get_stage_name(ThreatStage.RECONNAISSANCE)
        self.assertIn("Reconnaissance", name)

    def test_unknown_label_defaults_to_normal(self):
        self.assertEqual(ThreatStageMapper.map_label("UnknownXYZ"), ThreatStage.NORMAL)


if __name__ == "__main__":
    unittest.main()
