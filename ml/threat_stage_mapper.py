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


class ThreatStage(IntEnum):
    NORMAL = 0
    RECONNAISSANCE = 1
    INITIAL_ACCESS = 2
    LATERAL_MOVEMENT = 3
    COMMAND_AND_CONTROL = 4
    EXFILTRATION_IMPACT = 5


class ThreatStageMapper:
    """
    Translates raw dataset labels and predicted state dynamics into MITRE ATT&CK stages.
    """

    STAGE_NAMES = {
        ThreatStage.NORMAL: "Normal / Baseline",
        ThreatStage.RECONNAISSANCE: "Reconnaissance (TA0043)",
        ThreatStage.INITIAL_ACCESS: "Initial Access (TA0001)",
        ThreatStage.LATERAL_MOVEMENT: "Lateral Movement (TA0008)",
        ThreatStage.COMMAND_AND_CONTROL: "Command & Control (TA0011)",
        ThreatStage.EXFILTRATION_IMPACT: "Exfiltration & Impact (TA0010/TA0040)"
    }

    STAGE_DESCRIPTIONS = {
        ThreatStage.NORMAL: "Routine baseline enterprise traffic. No adversarial signatures detected.",
        ThreatStage.RECONNAISSANCE: "Adversary probing IP ranges and scanning open ports to discover vulnerable services.",
        ThreatStage.INITIAL_ACCESS: "Adversary attempting authentication bypass (FTP/SSH Patator) or web application exploitation.",
        ThreatStage.LATERAL_MOVEMENT: "Adversary pivoting across network segments, probing internal servers and SMB shares.",
        ThreatStage.COMMAND_AND_CONTROL: "Compromised host communicating with external command infrastructure / botmaster.",
        ThreatStage.EXFILTRATION_IMPACT: "High-volume data transfer out of perimeter or volumetric resource exhaustion (DoS/DDoS)."
    }

    STAGE_COLORS = {
        ThreatStage.NORMAL: "#2ca02c",         # Green
        ThreatStage.RECONNAISSANCE: "#17becf", # Cyan
        ThreatStage.INITIAL_ACCESS: "#ff7f0e", # Orange
        ThreatStage.LATERAL_MOVEMENT: "#d62728",# Red
        ThreatStage.COMMAND_AND_CONTROL: "#9467bd", # Purple
        ThreatStage.EXFILTRATION_IMPACT: "#8c564b"  # Dark Red/Brown
    }

    # Label to MITRE Stage mapping dictionary
    LABEL_TO_STAGE_MAP: Dict[str, ThreatStage] = {
        # Benign
        'BENIGN': ThreatStage.NORMAL,
        'Normal': ThreatStage.NORMAL,
        '0': ThreatStage.NORMAL,
        0: ThreatStage.NORMAL,

        # Reconnaissance
        'PortScan': ThreatStage.RECONNAISSANCE,
        'Port Scan': ThreatStage.RECONNAISSANCE,
        'IP Sweep': ThreatStage.RECONNAISSANCE,

        # Initial Access
        'FTP-Patator': ThreatStage.INITIAL_ACCESS,
        'SSH-Patator': ThreatStage.INITIAL_ACCESS,
        'Web Attack – Brute Force': ThreatStage.INITIAL_ACCESS,
        'Web Attack - Brute Force': ThreatStage.INITIAL_ACCESS,
        'Web Attack – XSS': ThreatStage.INITIAL_ACCESS,
        'Web Attack - XSS': ThreatStage.INITIAL_ACCESS,
        'Web Attack – Sql Injection': ThreatStage.INITIAL_ACCESS,
        'Web Attack - Sql Injection': ThreatStage.INITIAL_ACCESS,
        'Brute Force': ThreatStage.INITIAL_ACCESS,

        # Lateral Movement
        'Infiltration': ThreatStage.LATERAL_MOVEMENT,
        'Infilteration': ThreatStage.LATERAL_MOVEMENT,
        'Lateral Movement': ThreatStage.LATERAL_MOVEMENT,

        # Command & Control
        'Bot': ThreatStage.COMMAND_AND_CONTROL,
        'Botnet': ThreatStage.COMMAND_AND_CONTROL,
        'Heartbleed': ThreatStage.COMMAND_AND_CONTROL,
        'C2': ThreatStage.COMMAND_AND_CONTROL,

        # Exfiltration & Impact
        'DDoS': ThreatStage.EXFILTRATION_IMPACT,
        'DoS slowloris': ThreatStage.EXFILTRATION_IMPACT,
        'DoS Slowhttptest': ThreatStage.EXFILTRATION_IMPACT,
        'DoS Hulk': ThreatStage.EXFILTRATION_IMPACT,
        'DoS GoldenEye': ThreatStage.EXFILTRATION_IMPACT,
        'DoS/DDoS': ThreatStage.EXFILTRATION_IMPACT,
        'Exfiltration': ThreatStage.EXFILTRATION_IMPACT
    }

    @classmethod
    def map_label(cls, label: Union[str, int]) -> ThreatStage:
        """Map a single string or integer label to a ThreatStage."""
        if isinstance(label, (int, float)):
            if int(label) in ThreatStage._value2member_map_:
                return ThreatStage(int(label))
            return ThreatStage.NORMAL if int(label) == 0 else ThreatStage.LATERAL_MOVEMENT

        cleaned_label = str(label).strip()
        for key, stage in cls.LABEL_TO_STAGE_MAP.items():
            if str(key).lower() == cleaned_label.lower():
                return stage

        # Partial matching fallback
        lower = cleaned_label.lower()
        if 'port' in lower or 'scan' in lower:
            return ThreatStage.RECONNAISSANCE
        elif 'patator' in lower or 'brute' in lower or 'web' in lower:
            return ThreatStage.INITIAL_ACCESS
        elif 'infil' in lower:
            return ThreatStage.LATERAL_MOVEMENT
        elif 'bot' in lower or 'c2' in lower:
            return ThreatStage.COMMAND_AND_CONTROL
        elif 'dos' in lower or 'ddos' in lower or 'exfil' in lower:
            return ThreatStage.EXFILTRATION_IMPACT
        elif 'benign' in lower or 'normal' in lower:
            return ThreatStage.NORMAL

        return ThreatStage.NORMAL

    @classmethod
    def get_stage_name(cls, stage: Union[ThreatStage, int]) -> str:
        """Get human-readable name of stage."""
        stage_enum = ThreatStage(int(stage)) if isinstance(stage, (int, float)) else stage
        return cls.STAGE_NAMES.get(stage_enum, "Unknown Stage")

    @classmethod
    def get_stage_color(cls, stage: Union[ThreatStage, int]) -> str:
        """Get color code for stage badge."""
        stage_enum = ThreatStage(int(stage)) if isinstance(stage, (int, float)) else stage
        return cls.STAGE_COLORS.get(stage_enum, "#6c757d")

    @classmethod
    def get_stage_description(cls, stage: Union[ThreatStage, int]) -> str:
        """Get security description for stage."""
        stage_enum = ThreatStage(int(stage)) if isinstance(stage, (int, float)) else stage
        return cls.STAGE_DESCRIPTIONS.get(stage_enum, "")
