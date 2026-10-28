"""
Configuration for the SplitSmart AI security layer.

Every threshold can be overridden with an environment variable so operators can
tune sensitivity for their deployment without touching code. Defaults are
chosen for a small, fixed group of users (roommates / friends) and favour
flagging over blocking: only clear-cut injection payloads and CRITICAL
anomalies are rejected outright.
"""

import os


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


ENGINE_NAME = "SplitSmart AI Security"
ENGINE_VERSION = "1.0"

# --------------------------------------------------------------------------
# Risk scoring (0-100) and the levels derived from it
# --------------------------------------------------------------------------
RISK_LEVEL_LOW = "LOW"
RISK_LEVEL_MEDIUM = "MEDIUM"
RISK_LEVEL_HIGH = "HIGH"
RISK_LEVEL_CRITICAL = "CRITICAL"

RISK_MEDIUM_THRESHOLD = _env_int("AI_SECURITY_RISK_MEDIUM", 30)
RISK_HIGH_THRESHOLD = _env_int("AI_SECURITY_RISK_HIGH", 60)
RISK_CRITICAL_THRESHOLD = _env_int("AI_SECURITY_RISK_CRITICAL", 85)

# Reject (instead of merely flag) expenses whose anomaly level is CRITICAL.
BLOCK_ON_CRITICAL_ANOMALY = _env_bool("AI_SECURITY_BLOCK_CRITICAL", True)

# --------------------------------------------------------------------------
# Behavioural anomaly detection
# --------------------------------------------------------------------------
# Number of samples a baseline needs before z-scores are trusted.
ANOMALY_MIN_HISTORY = _env_int("AI_SECURITY_MIN_HISTORY", 5)
# z-score of the amount against the user's (or the group's) spending baseline.
ANOMALY_Z_WARN = _env_float("AI_SECURITY_Z_WARN", 2.5)
ANOMALY_Z_CRITICAL = _env_float("AI_SECURITY_Z_CRITICAL", 4.0)
# Amount relative to the user's mean (e.g. 10x their usual expense).
ANOMALY_RATIO_WARN = _env_float("AI_SECURITY_RATIO_WARN", 10.0)
# Absolute amount guard-rails independent of any baseline.
ABSOLUTE_AMOUNT_WARN = _env_float("AI_SECURITY_AMOUNT_WARN", 5000.0)
ABSOLUTE_AMOUNT_CRITICAL = _env_float("AI_SECURITY_AMOUNT_CRITICAL", 50000.0)
# Submission velocity: entries per window from one user.
VELOCITY_WINDOW_SECONDS = _env_int("AI_SECURITY_VELOCITY_WINDOW", 60)
VELOCITY_WARN_COUNT = _env_int("AI_SECURITY_VELOCITY_WARN", 6)
VELOCITY_CRITICAL_COUNT = _env_int("AI_SECURITY_VELOCITY_CRITICAL", 15)
# Identical (description, amount) pairs inside the velocity window.
DUPLICATE_BURST_COUNT = _env_int("AI_SECURITY_DUPLICATE_BURST", 3)
# Samples before an unusual hour-of-day is considered meaningful.
HOUR_PROFILE_MIN_HISTORY = _env_int("AI_SECURITY_HOUR_MIN_HISTORY", 20)

# --------------------------------------------------------------------------
# Threat (injection payload) classification
# --------------------------------------------------------------------------
# Posterior probability required to reject a payload as malicious.
THREAT_BLOCK_CONFIDENCE = _env_float("AI_SECURITY_THREAT_CONFIDENCE", 0.85)
# Posterior probability required to merely mark a payload as suspicious.
THREAT_SUSPICIOUS_CONFIDENCE = _env_float("AI_SECURITY_THREAT_SUSPICIOUS", 0.75)
# Minimum gap between the top threat class and "benign" for the Naive Bayes
# model to override the benign default on its own (signatures bypass this).
THREAT_DECISION_MARGIN = _env_float("AI_SECURITY_THREAT_MARGIN", 0.50)

# --------------------------------------------------------------------------
# Intrusion detection / adaptive response
# --------------------------------------------------------------------------
CLIENT_ACTION_ALLOW = "allow"
CLIENT_ACTION_CHALLENGE = "challenge"
CLIENT_ACTION_THROTTLE = "throttle"
CLIENT_ACTION_BLOCK = "block"

INTRUSION_WINDOW_SECONDS = _env_int("AI_SECURITY_INTRUSION_WINDOW", 600)
# Exponential decay: an event loses half its weight every HALF_LIFE seconds.
INTRUSION_HALF_LIFE_SECONDS = _env_int("AI_SECURITY_INTRUSION_HALF_LIFE", 300)
INTRUSION_CHALLENGE_SCORE = _env_float("AI_SECURITY_CHALLENGE_SCORE", 40.0)
INTRUSION_THROTTLE_SCORE = _env_float("AI_SECURITY_THROTTLE_SCORE", 60.0)
INTRUSION_BLOCK_SCORE = _env_float("AI_SECURITY_BLOCK_SCORE", 80.0)
INTRUSION_BLOCK_DURATION_SECONDS = _env_int("AI_SECURITY_BLOCK_DURATION", 300)
# Distinct usernames with failed logins from one client before it is treated
# as credential stuffing.
CREDENTIAL_STUFFING_USERS = _env_int("AI_SECURITY_STUFFING_USERS", 3)
CREDENTIAL_STUFFING_BONUS = _env_float("AI_SECURITY_STUFFING_BONUS", 30.0)
# Seconds a throttled client is delayed on authentication endpoints (tarpit).
THROTTLE_DELAY_SECONDS = _env_float("AI_SECURITY_THROTTLE_DELAY", 2.0)

# Weight each security signal contributes to a client's intrusion score.
EVENT_WEIGHTS = {
    "login_failed": 22.0,
    "login_success": -10.0,
    "rate_limited": 15.0,
    "hmac_mismatch": 35.0,
    "replay_detected": 30.0,
    "signature_invalid": 40.0,
    "decryption_failed": 35.0,
    "invalid_session": 10.0,
    "injection_detected": 50.0,
    "anomaly_critical": 30.0,
    "anomaly_high": 10.0,
    "anomaly_medium": 0.0,
    "client_blocked": 0.0,
    "request_blocked": 5.0,
}

# --------------------------------------------------------------------------
# Optional LLM-assisted analyst (Claude). Disabled automatically when no
# credentials are configured; the rest of the engine never depends on it.
# --------------------------------------------------------------------------
LLM_ENABLED = _env_bool("AI_SECURITY_LLM_ENABLED", True)
LLM_MODEL = os.environ.get("AI_SECURITY_LLM_MODEL", "claude-opus-5-5")
LLM_TIMEOUT_SECONDS = _env_float("AI_SECURITY_LLM_TIMEOUT", 45.0)
LLM_MAX_FIELD_CHARS = _env_int("AI_SECURITY_LLM_MAX_FIELD_CHARS", 400)

# How many security events are kept in memory for the dashboard.
EVENT_MEMORY_SIZE = _env_int("AI_SECURITY_EVENT_MEMORY", 500)
