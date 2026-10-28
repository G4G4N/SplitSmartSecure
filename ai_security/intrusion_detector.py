"""
Adaptive intrusion detection.

Every security signal the application observes (failed logins, HMAC
mismatches, replayed requests, invalid signatures, injection attempts,
critical anomalies, ...) is attributed to a client identifier (an IP address
for the web API, a user or session id for the protocol layer). Signals are
weighted and decay exponentially, so a client's intrusion score reflects
*recent* behaviour. The score selects a graduated response:

    allow     -> nothing unusual
    challenge -> warn the UI, keep a close eye
    throttle  -> slow the client down (tarpit) on authentication endpoints
    block     -> reject state-changing requests for a cooling-off period

Credential stuffing (failed logins against many different usernames from
one client) is recognised explicitly and adds a bonus to the score.
"""

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional, Set, Tuple

from . import config as cfg


@dataclass
class ClientState:
    events: Deque[Tuple[float, str, float, Optional[str]]] = field(default_factory=lambda: deque(maxlen=1000))
    blocked_until: float = 0.0
    block_count: int = 0
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    total_events: int = 0


@dataclass
class ClientVerdict:
    client_id: str
    score: float
    action: str
    reasons: List[str] = field(default_factory=list)
    blocked_until: Optional[float] = None
    retry_after: int = 0
    newly_blocked: bool = False  # True only on the evaluation that started the block

    @property
    def blocked(self) -> bool:
        return self.action == cfg.CLIENT_ACTION_BLOCK

    @property
    def throttled(self) -> bool:
        return self.action == cfg.CLIENT_ACTION_THROTTLE

    def to_dict(self) -> dict:
        return {
            "client_id": self.client_id,
            "score": round(min(self.score, 100.0), 1),
            "raw_score": round(self.score, 1),
            "action": self.action,
            "reasons": list(self.reasons),
            "blocked_until": self.blocked_until,
            "retry_after": self.retry_after,
        }


class IntrusionDetector:
    """Tracks weighted, decaying security signals per client."""

    def __init__(
        self,
        weights: Optional[Dict[str, float]] = None,
        window: float = cfg.INTRUSION_WINDOW_SECONDS,
        half_life: float = cfg.INTRUSION_HALF_LIFE_SECONDS,
        challenge_score: float = cfg.INTRUSION_CHALLENGE_SCORE,
        throttle_score: float = cfg.INTRUSION_THROTTLE_SCORE,
        block_score: float = cfg.INTRUSION_BLOCK_SCORE,
        block_duration: float = cfg.INTRUSION_BLOCK_DURATION_SECONDS,
    ):
        self.weights = dict(cfg.EVENT_WEIGHTS)
        if weights:
            self.weights.update(weights)
        self.window = window
        self.half_life = half_life
        self.challenge_score = challenge_score
        self.throttle_score = throttle_score
        self.block_score = block_score
        self.block_duration = block_duration
        self._clients: Dict[str, ClientState] = {}
        self._lock = threading.RLock()

    # -- recording ---------------------------------------------------------
    def record(self, client_id: str, event_type: str, user_id: Optional[str] = None,
               weight: Optional[float] = None, now: Optional[float] = None) -> ClientVerdict:
        now = now if now is not None else time.time()
        weight = self.weights.get(event_type, 10.0) if weight is None else weight
        with self._lock:
            state = self._clients.setdefault(client_id, ClientState(first_seen=now))
            state.events.append((now, event_type, weight, user_id))
            state.total_events += 1
            state.last_seen = now
            return self._evaluate_locked(client_id, state, now)

    # -- evaluation --------------------------------------------------------
    def evaluate(self, client_id: str, now: Optional[float] = None) -> ClientVerdict:
        now = now if now is not None else time.time()
        with self._lock:
            state = self._clients.get(client_id)
            if state is None:
                return ClientVerdict(client_id=client_id, score=0.0, action=cfg.CLIENT_ACTION_ALLOW)
            return self._evaluate_locked(client_id, state, now)

    def is_blocked(self, client_id: str, now: Optional[float] = None) -> bool:
        return self.evaluate(client_id, now).blocked

    def unblock(self, client_id: str) -> None:
        with self._lock:
            state = self._clients.get(client_id)
            if state:
                state.blocked_until = 0.0
                state.events.clear()

    def _score(self, state: ClientState, now: float) -> Tuple[float, List[str]]:
        # Drop events that fell out of the window.
        while state.events and now - state.events[0][0] > self.window:
            state.events.popleft()
        score = 0.0
        contributions: Dict[str, float] = {}
        failed_users: Set[str] = set()
        for ts, event_type, weight, user_id in state.events:
            age = max(0.0, now - ts)
            decayed = weight * (0.5 ** (age / self.half_life)) if self.half_life > 0 else weight
            score += decayed
            contributions[event_type] = contributions.get(event_type, 0.0) + decayed
            if event_type == "login_failed" and user_id:
                failed_users.add(user_id)
        reasons = [f"{etype} (+{value:.0f})" for etype, value in
                   sorted(contributions.items(), key=lambda kv: -kv[1]) if value > 0.5]
        if len(failed_users) >= cfg.CREDENTIAL_STUFFING_USERS:
            score += cfg.CREDENTIAL_STUFFING_BONUS
            reasons.insert(0, f"credential stuffing across {len(failed_users)} accounts "
                              f"(+{cfg.CREDENTIAL_STUFFING_BONUS:.0f})")
        return max(0.0, score), reasons

    def _evaluate_locked(self, client_id: str, state: ClientState, now: float) -> ClientVerdict:
        score, reasons = self._score(state, now)
        if state.blocked_until > now:
            remaining = int(state.blocked_until - now) + 1
            return ClientVerdict(client_id, score, cfg.CLIENT_ACTION_BLOCK,
                                 reasons + [f"blocked for another {remaining}s"],
                                 blocked_until=state.blocked_until, retry_after=remaining)
        if score >= self.block_score:
            state.blocked_until = now + self.block_duration
            state.block_count += 1
            return ClientVerdict(client_id, score, cfg.CLIENT_ACTION_BLOCK,
                                 reasons + [f"score {score:.0f} >= block threshold {self.block_score:.0f}"],
                                 blocked_until=state.blocked_until, retry_after=int(self.block_duration),
                                 newly_blocked=True)
        if score >= self.throttle_score:
            return ClientVerdict(client_id, score, cfg.CLIENT_ACTION_THROTTLE, reasons)
        if score >= self.challenge_score:
            return ClientVerdict(client_id, score, cfg.CLIENT_ACTION_CHALLENGE, reasons)
        return ClientVerdict(client_id, score, cfg.CLIENT_ACTION_ALLOW, reasons)

    # -- reporting ---------------------------------------------------------
    def snapshot(self, now: Optional[float] = None, limit: int = 20) -> List[dict]:
        now = now if now is not None else time.time()
        with self._lock:
            verdicts = [self._evaluate_locked(cid, state, now) for cid, state in self._clients.items()]
            rows = []
            for verdict in sorted(verdicts, key=lambda v: -v.score):
                state = self._clients[verdict.client_id]
                row = verdict.to_dict()
                row.update({
                    "events_in_window": len(state.events),
                    "total_events": state.total_events,
                    "block_count": state.block_count,
                    "last_seen": state.last_seen,
                })
                rows.append(row)
            return rows[:limit]

    @property
    def info(self) -> dict:
        with self._lock:
            return {
                "model": "Weighted decaying signal score with graduated response",
                "clients_tracked": len(self._clients),
                "currently_blocked": sum(1 for s in self._clients.values() if s.blocked_until > time.time()),
                "thresholds": {
                    "challenge": self.challenge_score,
                    "throttle": self.throttle_score,
                    "block": self.block_score,
                },
                "half_life_seconds": self.half_life,
                "block_duration_seconds": self.block_duration,
            }
