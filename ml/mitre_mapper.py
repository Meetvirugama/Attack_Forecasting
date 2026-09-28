"""
MITRE ATT&CK Mapping Module for Network Attack Forecasting

This module provides a unified taxonomy mapping raw flow/packet attack labels
to standardized MITRE ATT&CK enterprise kill-chain phases:
1. Normal (Benign baseline)
2. Reconnaissance (TA0043)
3. Initial Access (TA0001)
4. Lateral Movement (TA0008)
5. Command & Control (TA0011)
6. Exfiltration & Impact (TA0010 / TA0040)
"""

from enum import IntEnum
from typing import Dict, List, Union


class MITREStage(IntEnum):
    NORMAL = 0
    RECONNAISSANCE = 1
    INITIAL_ACCESS = 2
    LATERAL_MOVEMENT = 3
    COMMAND_AND_CONTROL = 4
    EXFILTRATION_IMPACT = 5


class MITREMapper:
    """
    Translates raw dataset labels and predicted state dynamics into MITRE ATT&CK stages.
    """

    STAGE_NAMES = {
        MITREStage.NORMAL: "Normal / Baseline",
        MITREStage.RECONNAISSANCE: "Reconnaissance (TA0043)",
        MITREStage.INITIAL_ACCESS: "Initial Access (TA0001)",
        MITREStage.LATERAL_MOVEMENT: "Lateral Movement (TA0008)",
        MITREStage.COMMAND_AND_CONTROL: "Command & Control (TA0011)",
        MITREStage.EXFILTRATION_IMPACT: "Exfiltration & Impact (TA0010/TA0040)"
    }

    STAGE_DESCRIPTIONS = {
        MITREStage.NORMAL: "Routine baseline enterprise traffic. No adversarial signatures detected.",
        MITREStage.RECONNAISSANCE: "Adversary probing IP ranges and scanning open ports to discover vulnerable services.",
        MITREStage.INITIAL_ACCESS: "Adversary attempting authentication bypass (FTP/SSH Patator) or web application exploitation.",
        MITREStage.LATERAL_MOVEMENT: "Adversary pivoting across network segments, probing internal servers and SMB shares.",
        MITREStage.COMMAND_AND_CONTROL: "Compromised host communicating with external command infrastructure / botmaster.",
        MITREStage.EXFILTRATION_IMPACT: "High-volume data transfer out of perimeter or volumetric resource exhaustion (DoS/DDoS)."
    }

    STAGE_COLORS = {
        MITREStage.NORMAL: "#2ca02c",         # Green
        MITREStage.RECONNAISSANCE: "#17becf", # Cyan
        MITREStage.INITIAL_ACCESS: "#ff7f0e", # Orange
        MITREStage.LATERAL_MOVEMENT: "#d62728",# Red
        MITREStage.COMMAND_AND_CONTROL: "#9467bd", # Purple
        MITREStage.EXFILTRATION_IMPACT: "#8c564b"  # Dark Red/Brown
    }

    # Label to MITRE Stage mapping dictionary
    LABEL_TO_STAGE_MAP: Dict[str, MITREStage] = {
        # Benign
        'BENIGN': MITREStage.NORMAL,
        'Normal': MITREStage.NORMAL,
        '0': MITREStage.NORMAL,
        0: MITREStage.NORMAL,

        # Reconnaissance
        'PortScan': MITREStage.RECONNAISSANCE,
        'Port Scan': MITREStage.RECONNAISSANCE,
        'IP Sweep': MITREStage.RECONNAISSANCE,

        # Initial Access
        'FTP-Patator': MITREStage.INITIAL_ACCESS,
        'SSH-Patator': MITREStage.INITIAL_ACCESS,
        'Web Attack – Brute Force': MITREStage.INITIAL_ACCESS,
        'Web Attack - Brute Force': MITREStage.INITIAL_ACCESS,
        'Web Attack – XSS': MITREStage.INITIAL_ACCESS,
        'Web Attack - XSS': MITREStage.INITIAL_ACCESS,
        'Web Attack – Sql Injection': MITREStage.INITIAL_ACCESS,
        'Web Attack - Sql Injection': MITREStage.INITIAL_ACCESS,
        'Brute Force': MITREStage.INITIAL_ACCESS,

        # Lateral Movement
        'Infiltration': MITREStage.LATERAL_MOVEMENT,
        'Infilteration': MITREStage.LATERAL_MOVEMENT,
        'Lateral Movement': MITREStage.LATERAL_MOVEMENT,

        # Command & Control
        'Bot': MITREStage.COMMAND_AND_CONTROL,
        'Botnet': MITREStage.COMMAND_AND_CONTROL,
        'Heartbleed': MITREStage.COMMAND_AND_CONTROL,
        'C2': MITREStage.COMMAND_AND_CONTROL,

        # Exfiltration & Impact
        'DDoS': MITREStage.EXFILTRATION_IMPACT,
        'DoS slowloris': MITREStage.EXFILTRATION_IMPACT,
        'DoS Slowhttptest': MITREStage.EXFILTRATION_IMPACT,
        'DoS Hulk': MITREStage.EXFILTRATION_IMPACT,
        'DoS GoldenEye': MITREStage.EXFILTRATION_IMPACT,
        'DoS/DDoS': MITREStage.EXFILTRATION_IMPACT,
        'Exfiltration': MITREStage.EXFILTRATION_IMPACT
    }

    @classmethod
    def map_label(cls, label: Union[str, int]) -> MITREStage:
        """Map a single string or integer label to a MITREStage."""
        if isinstance(label, (int, float)):
            if int(label) in MITREStage._value2member_map_:
                return MITREStage(int(label))
            return MITREStage.NORMAL if int(label) == 0 else MITREStage.LATERAL_MOVEMENT

        cleaned_label = str(label).strip()
        for key, stage in cls.LABEL_TO_STAGE_MAP.items():
            if str(key).lower() == cleaned_label.lower():
                return stage

        # Partial matching fallback
        lower = cleaned_label.lower()
        if 'port' in lower or 'scan' in lower:
            return MITREStage.RECONNAISSANCE
        elif 'patator' in lower or 'brute' in lower or 'web' in lower:
            return MITREStage.INITIAL_ACCESS
        elif 'infil' in lower:
            return MITREStage.LATERAL_MOVEMENT
        elif 'bot' in lower or 'c2' in lower:
            return MITREStage.COMMAND_AND_CONTROL
        elif 'dos' in lower or 'ddos' in lower or 'exfil' in lower:
            return MITREStage.EXFILTRATION_IMPACT
        elif 'benign' in lower or 'normal' in lower:
            return MITREStage.NORMAL

        return MITREStage.NORMAL

    @classmethod
    def get_stage_name(cls, stage: Union[MITREStage, int]) -> str:
        """Get human-readable name of stage."""
        stage_enum = MITREStage(int(stage)) if isinstance(stage, (int, float)) else stage
        return cls.STAGE_NAMES.get(stage_enum, "Unknown Stage")

    @classmethod
    def get_stage_color(cls, stage: Union[MITREStage, int]) -> str:
        """Get color code for stage badge."""
        stage_enum = MITREStage(int(stage)) if isinstance(stage, (int, float)) else stage
        return cls.STAGE_COLORS.get(stage_enum, "#6c757d")

    @classmethod
    def get_stage_description(cls, stage: Union[MITREStage, int]) -> str:
        """Get security description for stage."""
        stage_enum = MITREStage(int(stage)) if isinstance(stage, (int, float)) else stage
        return cls.STAGE_DESCRIPTIONS.get(stage_enum, "")
