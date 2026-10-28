"""
Behavioural anomaly detection for expense submissions.

The detector maintains an online statistical profile for every user and for
the group as a whole (Welford's algorithm for the running mean and variance,
an hour-of-day histogram, known payers and a short window of recent
submissions). Each new expense is scored against those baselines:

* amount z-score against the user's own history (falls back to the group)
* amount relative to the user's typical expense (e.g. 10x their mean)
* absolute amount guard-rails
* submission velocity (entries per minute) and duplicate bursts
* unusual hour of day once enough history exists
* unknown or never-before-used payers

Scores are additive, capped at 100 and mapped to LOW / MEDIUM / HIGH /
CRITICAL. The assessment is side-effect free; call ``learn`` once an entry
has actually been accepted so the baselines keep adapting.
"""

import math
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Deque, Dict, Iterable, List, Optional, Tuple

from . import config as cfg

GLOBAL_PROFILE_KEY = "__group__"


def parse_timestamp(value: Optional[str]) -> float:
    """Convert an ISO-8601 timestamp (naive values are UTC) to epoch seconds."""
    if not value:
        return time.time()
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return time.time()
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def normalise_description(description: Optional[str]) -> str:
    return " ".join(str(description or "").lower().split())


def risk_level_for(score: float) -> str:
    if score >= cfg.RISK_CRITICAL_THRESHOLD:
        return cfg.RISK_LEVEL_CRITICAL
    if score >= cfg.RISK_HIGH_THRESHOLD:
        return cfg.RISK_LEVEL_HIGH
    if score >= cfg.RISK_MEDIUM_THRESHOLD:
        return cfg.RISK_LEVEL_MEDIUM
    return cfg.RISK_LEVEL_LOW


@dataclass
class BehaviourProfile:
    """Online statistics for one user (or the whole group)."""

    count: int = 0
    mean: float = 0.0
    m2: float = 0.0
    max_amount: float = 0.0
    hour_histogram: List[int] = field(default_factory=lambda: [0] * 24)
    payers: Counter = field(default_factory=Counter)
    recent: Deque[Tuple[float, float, str]] = field(default_factory=lambda: deque(maxlen=500))

    @property
    def std(self) -> float:
        if self.count < 2:
            return 0.0
        return math.sqrt(self.m2 / (self.count - 1))

    def update(self, amount: float, epoch: float, payer: str, description: str) -> None:
        self.count += 1
        delta = amount - self.mean
        self.mean += delta / self.count
        self.m2 += delta * (amount - self.mean)
        self.max_amount = max(self.max_amount, amount)
        hour = datetime.fromtimestamp(epoch, tz=timezone.utc).hour
        self.hour_histogram[hour] += 1
        self.payers[payer] += 1
        self.recent.append((epoch, amount, normalise_description(description)))

    def recent_within(self, epoch: float, window: float) -> List[Tuple[float, float, str]]:
        return [item for item in self.recent if 0 <= epoch - item[0] <= window]

    def to_dict(self) -> dict:
        return {
            "samples": self.count,
            "mean_amount": round(self.mean, 2),
            "std_amount": round(self.std, 2),
            "max_amount": round(self.max_amount, 2),
            "known_payers": sorted(self.payers),
        }


@dataclass
class AnomalySignal:
    name: str
    score: float
    detail: str

    def to_dict(self) -> dict:
        return {"name": self.name, "score": round(self.score, 1), "detail": self.detail}


@dataclass
class AnomalyAssessment:
    score: float
    level: str
    signals: List[AnomalySignal]
    baseline: dict
    cold_start: bool

    def to_dict(self) -> dict:
        return {
            "score": round(self.score, 1),
            "level": self.level,
            "signals": [s.to_dict() for s in self.signals],
            "baseline": self.baseline,
            "cold_start": self.cold_start,
        }


class ExpenseAnomalyDetector:
    """Scores expense submissions against learned behavioural baselines."""

    def __init__(self):
        self.profiles: Dict[str, BehaviourProfile] = {}
        self.known_users: set = set()
        self.trained_entries = 0

    # -- learning ----------------------------------------------------------
    def profile_for(self, key: str) -> BehaviourProfile:
        return self.profiles.setdefault(key, BehaviourProfile())

    def learn(self, user_id: str, payer: str, amount: float, description: str,
              timestamp: Optional[str] = None) -> None:
        epoch = parse_timestamp(timestamp)
        amount = float(amount)
        self.profile_for(user_id).update(amount, epoch, payer, description)
        self.profile_for(GLOBAL_PROFILE_KEY).update(amount, epoch, payer, description)
        self.known_users.update((user_id, payer))

    def train(self, entries: Iterable[dict]) -> int:
        """Build baselines from existing ledger entries (oldest first)."""
        count = 0
        for entry in sorted(entries, key=lambda e: str(e.get("timestamp", ""))):
            try:
                self.learn(entry["user_id"], entry["payer"], float(entry["amount"]),
                           entry.get("description", ""), entry.get("timestamp"))
                count += 1
            except (KeyError, TypeError, ValueError):
                continue
        self.trained_entries += count
        return count

    def register_users(self, users: Iterable[str]) -> None:
        self.known_users.update(users)

    # -- assessment --------------------------------------------------------
    def assess(self, user_id: str, payer: str, amount: float, description: str,
               timestamp: Optional[str] = None) -> AnomalyAssessment:
        signals: List[AnomalySignal] = []
        epoch = parse_timestamp(timestamp)
        try:
            amount = float(amount)
        except (TypeError, ValueError):
            amount = float("nan")

        user_profile = self.profiles.get(user_id, BehaviourProfile())
        group_profile = self.profiles.get(GLOBAL_PROFILE_KEY, BehaviourProfile())

        if math.isnan(amount) or amount <= 0:
            signals.append(AnomalySignal("invalid_amount", 50, "Amount is not a positive number"))
            amount = 0.0

        # 1. Statistical baseline (prefer the user's own history).
        baseline_profile, baseline_name = None, None
        if user_profile.count >= cfg.ANOMALY_MIN_HISTORY:
            baseline_profile, baseline_name = user_profile, "user"
        elif group_profile.count >= cfg.ANOMALY_MIN_HISTORY:
            baseline_profile, baseline_name = group_profile, "group"
        cold_start = baseline_profile is None

        if baseline_profile is not None and amount > 0:
            # Floor the deviation so a very consistent spender does not get
            # an astronomic z-score for a modest change.
            std_eff = max(baseline_profile.std, 0.15 * baseline_profile.mean, 1.0)
            z = (amount - baseline_profile.mean) / std_eff
            if z >= cfg.ANOMALY_Z_CRITICAL:
                signals.append(AnomalySignal(
                    "amount_outlier_extreme", 40,
                    f"${amount:,.2f} is {z:.1f} standard deviations above the {baseline_name} "
                    f"average of ${baseline_profile.mean:,.2f}"))
            elif z >= cfg.ANOMALY_Z_WARN:
                signals.append(AnomalySignal(
                    "amount_outlier", 25,
                    f"${amount:,.2f} is {z:.1f} standard deviations above the {baseline_name} "
                    f"average of ${baseline_profile.mean:,.2f}"))
            ratio = amount / baseline_profile.mean if baseline_profile.mean > 0 else 0.0
            if ratio >= cfg.ANOMALY_RATIO_WARN:
                signals.append(AnomalySignal(
                    "amount_ratio", 25,
                    f"${amount:,.2f} is {ratio:.0f}x the {baseline_name} average expense"))
            if baseline_profile.max_amount > 0 and amount > 3 * baseline_profile.max_amount:
                signals.append(AnomalySignal(
                    "exceeds_historical_max", 15,
                    f"Larger than three times the previous {baseline_name} maximum of "
                    f"${baseline_profile.max_amount:,.2f}"))

        # 2. Absolute guard-rails that never depend on history.
        if amount >= cfg.ABSOLUTE_AMOUNT_CRITICAL:
            signals.append(AnomalySignal(
                "absolute_amount_critical", 50,
                f"${amount:,.2f} exceeds the hard limit of ${cfg.ABSOLUTE_AMOUNT_CRITICAL:,.0f}"))
        elif amount >= cfg.ABSOLUTE_AMOUNT_WARN:
            signals.append(AnomalySignal(
                "absolute_amount_high", 20,
                f"${amount:,.2f} exceeds the review threshold of ${cfg.ABSOLUTE_AMOUNT_WARN:,.0f}"))

        # 3. Velocity and duplicate bursts.
        recent = user_profile.recent_within(epoch, cfg.VELOCITY_WINDOW_SECONDS)
        burst_size = len(recent) + 1  # include the submission being assessed
        if burst_size >= cfg.VELOCITY_CRITICAL_COUNT:
            signals.append(AnomalySignal(
                "velocity_critical", 45,
                f"{burst_size} submissions in {cfg.VELOCITY_WINDOW_SECONDS}s looks automated"))
        elif burst_size >= cfg.VELOCITY_WARN_COUNT:
            signals.append(AnomalySignal(
                "velocity_high", 20,
                f"{burst_size} submissions in {cfg.VELOCITY_WINDOW_SECONDS}s"))
        desc_norm = normalise_description(description)
        duplicates = sum(1 for _, amt, desc in recent if desc == desc_norm and abs(amt - amount) < 0.005) + 1
        if duplicates >= cfg.DUPLICATE_BURST_COUNT:
            signals.append(AnomalySignal(
                "duplicate_burst", 25,
                f"Identical expense submitted {duplicates} times within {cfg.VELOCITY_WINDOW_SECONDS}s"))

        # 4. Hour-of-day profile.
        if user_profile.count >= cfg.HOUR_PROFILE_MIN_HISTORY:
            hour = datetime.fromtimestamp(epoch, tz=timezone.utc).hour
            if user_profile.hour_histogram[hour] == 0:
                signals.append(AnomalySignal(
                    "unusual_hour", 10,
                    f"{user_id} has never submitted an expense around {hour:02d}:00 UTC"))

        # 5. Payer plausibility (the submitting user is registered by definition).
        if payer and payer != user_id and self.known_users and payer not in self.known_users:
            signals.append(AnomalySignal(
                "unknown_payer", 15, f"Payer '{payer}' is not a registered member of the group"))
        elif payer and payer != user_id and user_profile.count >= cfg.ANOMALY_MIN_HISTORY \
                and user_profile.payers.get(payer, 0) == 0:
            signals.append(AnomalySignal(
                "new_payer", 10, f"{user_id} has never recorded an expense paid by '{payer}'"))

        # 6. Large round numbers are a weak but classic fraud indicator.
        if amount >= 1000 and float(amount).is_integer() and int(amount) % 1000 == 0:
            signals.append(AnomalySignal("round_amount", 5, f"${amount:,.0f} is a large round number"))

        score = min(100.0, sum(s.score for s in signals))
        baseline = {
            "source": baseline_name or "none",
            "user": user_profile.to_dict(),
            "group": group_profile.to_dict(),
        }
        return AnomalyAssessment(score=score, level=risk_level_for(score), signals=signals,
                                 baseline=baseline, cold_start=cold_start)

    # -- information -------------------------------------------------------
    @property
    def info(self) -> dict:
        group = self.profiles.get(GLOBAL_PROFILE_KEY, BehaviourProfile())
        return {
            "model": "Online behavioural baselines (Welford mean/variance, velocity, hour-of-day, payer graph)",
            "users_profiled": len([k for k in self.profiles if k != GLOBAL_PROFILE_KEY]),
            "entries_learned": group.count,
            "group_mean_amount": round(group.mean, 2),
            "group_std_amount": round(group.std, 2),
            "min_history_for_zscore": cfg.ANOMALY_MIN_HISTORY,
        }

    def user_profiles(self) -> Dict[str, dict]:
        return {k: v.to_dict() for k, v in self.profiles.items() if k != GLOBAL_PROFILE_KEY}
