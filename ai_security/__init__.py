"""
SplitSmart AI Security layer.

Adds machine-learning and behavioural defences on top of the cryptographic
protocol:

* ``ThreatClassifier``        - Naive Bayes + signature detection of injection payloads
* ``ExpenseAnomalyDetector``  - online behavioural baselines and anomaly scoring
* ``IntrusionDetector``       - decaying per-client risk score with adaptive response
* ``LLMSecurityAnalyst``      - optional Claude-backed incident explanations
* ``AISecurityEngine``        - facade used by the server and the web API
"""

from .anomaly_detector import AnomalyAssessment, ExpenseAnomalyDetector, risk_level_for
from .engine import (
    ACTION_ALLOW,
    ACTION_BLOCK,
    ACTION_FLAG,
    AISecurityEngine,
    ExpenseAssessment,
)
from .intrusion_detector import ClientVerdict, IntrusionDetector
from .llm_analyst import LLMSecurityAnalyst
from .threat_classifier import ThreatAssessment, ThreatClassifier

__all__ = [
    "ACTION_ALLOW",
    "ACTION_BLOCK",
    "ACTION_FLAG",
    "AISecurityEngine",
    "AnomalyAssessment",
    "ClientVerdict",
    "ExpenseAnomalyDetector",
    "ExpenseAssessment",
    "IntrusionDetector",
    "LLMSecurityAnalyst",
    "ThreatAssessment",
    "ThreatClassifier",
    "risk_level_for",
]
