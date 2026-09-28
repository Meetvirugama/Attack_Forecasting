"""
Unit Tests for src.mitre_mapper
"""
import unittest
from ml.mitre_mapper import MITREStage, MITREMapper


class TestMITREMapper(unittest.TestCase):

    def test_benign_maps_to_normal(self):
        self.assertEqual(MITREMapper.map_label("BENIGN"), MITREStage.NORMAL)

    def test_portscan_maps_to_recon(self):
        self.assertEqual(MITREMapper.map_label("PortScan"), MITREStage.RECONNAISSANCE)

    def test_ftp_patator_maps_to_initial_access(self):
        self.assertEqual(MITREMapper.map_label("FTP-Patator"), MITREStage.INITIAL_ACCESS)

    def test_infiltration_maps_to_lateral_movement(self):
        self.assertEqual(MITREMapper.map_label("Infiltration"), MITREStage.LATERAL_MOVEMENT)

    def test_bot_maps_to_c2(self):
        self.assertEqual(MITREMapper.map_label("Bot"), MITREStage.COMMAND_AND_CONTROL)

    def test_ddos_maps_to_exfil_impact(self):
        self.assertEqual(MITREMapper.map_label("DDoS"), MITREStage.EXFILTRATION_IMPACT)

    def test_get_stage_name(self):
        name = MITREMapper.get_stage_name(MITREStage.RECONNAISSANCE)
        self.assertIn("Reconnaissance", name)

    def test_unknown_label_defaults_to_normal(self):
        self.assertEqual(MITREMapper.map_label("UnknownXYZ"), MITREStage.NORMAL)


if __name__ == "__main__":
    unittest.main()
