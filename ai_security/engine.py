"""
AISecurityEngine: the facade the server and the web API talk to.

It wires together the three local detectors (threat classifier, behavioural
anomaly detector, intrusion detector) and the optional LLM analyst, persists
security events, keeps counters for the dashboard and turns the detector
output into one decision per request: allow, flag or block.
"""

import json
import threading
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List, Optional

from . import config as cfg
from .anomaly_detector import AnomalyAssessment, ExpenseAnomalyDetector, risk_level_for
from .intrusion_detector import ClientVerdict, IntrusionDetector
from .llm_analyst import LLMSecurityAnalyst
from .threat_classifier import LABEL_BENIGN, ThreatAssessment, ThreatClassifier

ACTION_ALLOW = "allow"
ACTION_FLAG = "flag"
ACTION_BLOCK = "block"

SEVERITY_INFO = "info"
SEVERITY_LOW = "low"
SEVERITY_MEDIUM = "medium"
SEVERITY_HIGH = "high"
SEVERITY_CRITICAL = "critical"

_EVENT_SEVERITY = {
    "login_failed": SEVERITY_LOW,
    "login_success": SEVERITY_INFO,
    "rate_limited": SEVERITY_LOW,
    "hmac_mismatch": SEVERITY_HIGH,
    "replay_detected": SEVERITY_HIGH,
    "signature_invalid": SEVERITY_HIGH,
    "decryption_failed": SEVERITY_HIGH,
    "invalid_session": SEVERITY_LOW,
    "injection_detected": SEVERITY_CRITICAL,
    "anomaly_critical": SEVERITY_CRITICAL,
    "anomaly_high": SEVERITY_HIGH,
    "anomaly_medium": SEVERITY_MEDIUM,
    "client_blocked": SEVERITY_HIGH,
    "request_blocked": SEVERITY_MEDIUM,
    "client_throttled": SEVERITY_MEDIUM,
}

_SEVERITY_RANK = {SEVERITY_INFO: 0, SEVERITY_LOW: 1, SEVERITY_MEDIUM: 2, SEVERITY_HIGH: 3, SEVERITY_CRITICAL: 4}


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).replace(tzinfo=None).isoformat()


@dataclass
class ExpenseAssessment:
    """Combined verdict for one expense submission."""

    user_id: str
    payer: str
    amount: float
    description: str
    threat: ThreatAssessment
    anomaly: AnomalyAssessment
    risk_score: float
    risk_level: str
    action: str
    reasons: List[str] = field(default_factory=list)
    assessed_at: str = field(default_factory=_utcnow_iso)

    @property
    def blocked(self) -> bool:
        return self.action == ACTION_BLOCK

    @property
    def flagged(self) -> bool:
        return self.action == ACTION_FLAG

    @property
    def block_reason(self) -> str:
        if not self.blocked:
            return ""
        if self.threat.malicious:
            return (f"AI Security: rejected {self.threat.description.lower()} "
                    f"(confidence {self.threat.confidence:.0%})")
        return f"AI Security: rejected CRITICAL-risk expense (risk score {self.risk_score:.0f}/100)"

    def to_dict(self) -> dict:
        return {
            "engine": f"{cfg.ENGINE_NAME} v{cfg.ENGINE_VERSION}",
            "action": self.action,
            "risk_score": round(self.risk_score, 1),
            "risk_level": self.risk_level,
            "reasons": list(self.reasons),
            "threat": self.threat.to_dict(),
            "anomaly": self.anomaly.to_dict(),
            "assessed_at": self.assessed_at,
        }


class AISecurityEngine:
    """Facade over all AI security components."""

    def __init__(self, storage=None, llm_analyst: Optional[LLMSecurityAnalyst] = None):
        self.storage = storage
        self.classifier = ThreatClassifier()
        self.anomaly = ExpenseAnomalyDetector()
        self.intrusion = IntrusionDetector()
        self.analyst = llm_analyst if llm_analyst is not None else LLMSecurityAnalyst()
        self.stats: Counter = Counter()
        self.started_at = time.time()
        self._events: Deque[dict] = deque(maxlen=cfg.EVENT_MEMORY_SIZE)
        self._event_seq = 0
        self._lock = threading.RLock()
        if storage is not None:
            self.train_from_storage()

    # -- training ----------------------------------------------------------
    def train_from_storage(self) -> int:
        """Learn baselines from the persisted ledger and user list."""
        if self.storage is None:
            return 0
        try:
            entries = self.storage.get_ledger_entries()
        except Exception:
            entries = []
        try:
            self.anomaly.register_users(self.storage.list_users())
        except Exception:
            pass
        learned = self.anomaly.train(entries)
        self.stats["baseline_entries"] = learned
        return learned

    # -- expense assessment ------------------------------------------------
    def assess_expense(self, user_id: str, payer: str, amount: float, description: str,
                       timestamp: Optional[str] = None) -> ExpenseAssessment:
        """Score a submission without changing any state."""
        description_threat = self.classifier.classify(description)
        payer_threat = self.classifier.classify(payer)
        threat = description_threat
        if payer_threat.label != LABEL_BENIGN and (
                threat.label == LABEL_BENIGN or payer_threat.confidence > threat.confidence):
            threat = payer_threat
        anomaly = self.anomaly.assess(user_id, payer, amount, description, timestamp)

        reasons: List[str] = []
        risk_score = anomaly.score
        if threat.malicious:
            risk_score = 100.0
            reasons.append(f"{threat.description} detected in input "
                           f"(confidence {threat.confidence:.0%}"
                           + (f", rules: {', '.join(threat.signatures)}" if threat.signatures else "")
                           + ")")
        elif threat.suspicious:
            risk_score = min(100.0, risk_score + 20.0)
            reasons.append(f"Input resembles a {threat.description.lower()} "
                           f"(confidence {threat.confidence:.0%})")
        reasons.extend(signal.detail for signal in anomaly.signals)
        risk_level = risk_level_for(risk_score)

        if threat.malicious or (risk_level == cfg.RISK_LEVEL_CRITICAL and cfg.BLOCK_ON_CRITICAL_ANOMALY):
            action = ACTION_BLOCK
        elif risk_level in (cfg.RISK_LEVEL_HIGH, cfg.RISK_LEVEL_MEDIUM, cfg.RISK_LEVEL_CRITICAL):
            action = ACTION_FLAG
        else:
            action = ACTION_ALLOW
        if not reasons:
            reasons.append("No anomalies detected; input classified as benign")

        return ExpenseAssessment(user_id=user_id, payer=payer, amount=float(amount) if amount is not None else 0.0,
                                 description=description or "", threat=threat, anomaly=anomaly,
                                 risk_score=risk_score, risk_level=risk_level, action=action, reasons=reasons)

    def commit_expense(self, assessment: ExpenseAssessment, client_id: Optional[str] = None,
                       timestamp: Optional[str] = None, entry_id: Optional[int] = None,
                       accepted: Optional[bool] = None) -> Optional[dict]:
        """Apply the side effects of an assessment: learn, count and log."""
        accepted = (not assessment.blocked) if accepted is None else accepted
        client_id = client_id or f"user:{assessment.user_id}"
        with self._lock:
            self.stats["expenses_analyzed"] += 1
            if accepted:
                self.anomaly.learn(assessment.user_id, assessment.payer, assessment.amount,
                                   assessment.description, timestamp)
            details = {
                "payer": assessment.payer,
                "amount": assessment.amount,
                "description": assessment.description,
                "risk_level": assessment.risk_level,
                "reasons": assessment.reasons,
                "threat_label": assessment.threat.label,
                "threat_confidence": round(assessment.threat.confidence, 4),
                "signatures": assessment.threat.signatures,
                "anomaly_signals": [s.name for s in assessment.anomaly.signals],
                "entry_id": entry_id,
                "accepted": accepted,
            }
            if assessment.threat.malicious:
                self.stats["threats_blocked"] += 1
                return self.record_event("injection_detected", client_id, assessment.user_id, details,
                                         risk_score=assessment.risk_score)
            if assessment.risk_level == cfg.RISK_LEVEL_CRITICAL:
                self.stats["anomalies_flagged"] += 1
                if not accepted:
                    self.stats["anomalies_blocked"] += 1
                return self.record_event("anomaly_critical", client_id, assessment.user_id, details,
                                         risk_score=assessment.risk_score)
            if assessment.risk_level == cfg.RISK_LEVEL_HIGH:
                self.stats["anomalies_flagged"] += 1
                return self.record_event("anomaly_high", client_id, assessment.user_id, details,
                                         risk_score=assessment.risk_score)
            if assessment.risk_level == cfg.RISK_LEVEL_MEDIUM:
                self.stats["anomalies_flagged"] += 1
                return self.record_event("anomaly_medium", client_id, assessment.user_id, details,
                                         risk_score=assessment.risk_score)
            self.stats["expenses_clean"] += 1
            return None

    # -- generic security signals -----------------------------------------
    def record_event(self, event_type: str, client_id: Optional[str] = None, user_id: Optional[str] = None,
                     details: Optional[dict] = None, risk_score: Optional[float] = None,
                     severity: Optional[str] = None) -> dict:
        """Persist a security event and feed it to the intrusion detector."""
        client_id = client_id or (f"user:{user_id}" if user_id else "unknown")
        severity = severity or _EVENT_SEVERITY.get(event_type, SEVERITY_MEDIUM)
        with self._lock:
            verdict = self.intrusion.record(client_id, event_type, user_id)
            if risk_score is None:
                risk_score = verdict.score
            self._event_seq += 1
            event = {
                "id": None,
                "seq": self._event_seq,
                "timestamp": _utcnow_iso(),
                "event_type": event_type,
                "severity": severity,
                "client_id": client_id,
                "user_id": user_id,
                "risk_score": round(float(risk_score), 1),
                "details": details or {},
                "client_action": verdict.action,
                "client_score": round(min(verdict.score, 100.0), 1),
            }
            if self.storage is not None and hasattr(self.storage, "add_security_event"):
                try:
                    event["id"] = self.storage.add_security_event(
                        timestamp=event["timestamp"], event_type=event_type, severity=severity,
                        client_id=client_id, user_id=user_id, risk_score=event["risk_score"],
                        details=json.dumps({**event["details"], "client_action": verdict.action,
                                            "client_score": event["client_score"]}, default=str))
                except Exception:
                    event["id"] = None
            if event["id"] is None:
                event["id"] = -self._event_seq  # negative ids mark in-memory-only events
            self._events.append(event)
            self.stats["events_recorded"] += 1
            self.stats[f"event:{event_type}"] += 1
            if verdict.newly_blocked and event_type != "client_blocked":
                # Record the transition into the blocked state exactly once per block.
                self.stats["clients_blocked"] += 1
                shown_score = round(min(verdict.score, 100.0), 1)
                block_details = {"reasons": verdict.reasons, "retry_after": verdict.retry_after,
                                 "triggered_by": event_type}
                block_event = {
                    "id": None, "seq": self._event_seq, "timestamp": _utcnow_iso(),
                    "event_type": "client_blocked", "severity": SEVERITY_HIGH, "client_id": client_id,
                    "user_id": user_id, "risk_score": shown_score, "details": block_details,
                    "client_action": verdict.action, "client_score": shown_score,
                }
                if self.storage is not None and hasattr(self.storage, "add_security_event"):
                    try:
                        block_event["id"] = self.storage.add_security_event(
                            timestamp=block_event["timestamp"], event_type="client_blocked",
                            severity=SEVERITY_HIGH, client_id=client_id, user_id=user_id,
                            risk_score=shown_score,
                            details=json.dumps({**block_details, "client_action": verdict.action,
                                                "client_score": shown_score}))
                    except Exception:
                        block_event["id"] = None
                if block_event["id"] is None:
                    block_event["id"] = -self._event_seq - 1_000_000
                self._events.append(block_event)
            return event

    def evaluate_client(self, client_id: str) -> ClientVerdict:
        return self.intrusion.evaluate(client_id)

    def is_blocked(self, client_id: str) -> bool:
        return self.intrusion.is_blocked(client_id)

    def unblock(self, client_id: str) -> None:
        self.intrusion.unblock(client_id)

    # -- dry-run analysis --------------------------------------------------
    def analyze_text(self, text: str) -> dict:
        self.stats["texts_analyzed"] += 1
        return self.classifier.classify(text).to_dict()

    def analyze_expense(self, user_id: str, payer: str, amount: float, description: str) -> dict:
        """Assess without committing: used by the dashboard's test panel."""
        self.stats["dry_runs"] += 1
        assessment = self.assess_expense(user_id, payer, amount, description)
        result = assessment.to_dict()
        result["would_block"] = assessment.blocked
        result["block_reason"] = assessment.block_reason
        return result

    # -- reporting ---------------------------------------------------------
    def get_events(self, limit: int = 50, min_severity: Optional[str] = None) -> List[dict]:
        events: List[dict] = []
        if self.storage is not None and hasattr(self.storage, "get_security_events"):
            try:
                for row in self.storage.get_security_events(limit=limit * 2):
                    details = row.get("details")
                    if isinstance(details, str):
                        try:
                            details = json.loads(details)
                        except ValueError:
                            details = {"raw": details}
                    row = dict(row)
                    row["details"] = details or {}
                    row["client_action"] = row["details"].pop("client_action", None)
                    row["client_score"] = row["details"].pop("client_score", None)
                    events.append(row)
            except Exception:
                events = []
        if not events:
            events = list(reversed(self._events))
        if min_severity:
            threshold = _SEVERITY_RANK.get(min_severity, 0)
            events = [e for e in events if _SEVERITY_RANK.get(e.get("severity"), 0) >= threshold]
        return events[:limit]

    def find_event(self, event_id: int) -> Optional[dict]:
        for event in self.get_events(limit=cfg.EVENT_MEMORY_SIZE):
            if event.get("id") == event_id:
                return event
        for event in self._events:
            if event.get("id") == event_id:
                return event
        return None

    def threat_level(self) -> dict:
        now = time.time()
        recent = [e for e in self.get_events(limit=200)
                  if now - self._event_epoch(e) <= cfg.INTRUSION_WINDOW_SECONDS]
        critical = sum(1 for e in recent if e.get("severity") == SEVERITY_CRITICAL)
        high = sum(1 for e in recent if e.get("severity") == SEVERITY_HIGH)
        blocked_clients = sum(1 for c in self.intrusion.snapshot() if c["action"] == cfg.CLIENT_ACTION_BLOCK)
        if critical or blocked_clients:
            level, label = "HIGH", "Active attack indicators in the last 10 minutes"
        elif high >= 2:
            level, label = "ELEVATED", "Multiple integrity or authentication failures recently"
        elif high or len(recent) >= 5:
            level, label = "GUARDED", "Some suspicious activity recently"
        else:
            level, label = "NORMAL", "No significant security events recently"
        return {"level": level, "label": label, "recent_events": len(recent),
                "recent_critical": critical, "recent_high": high, "blocked_clients": blocked_clients}

    @staticmethod
    def _event_epoch(event: dict) -> float:
        try:
            return datetime.fromisoformat(str(event.get("timestamp"))).replace(tzinfo=timezone.utc).timestamp()
        except (TypeError, ValueError):
            return 0.0

    def get_dashboard(self, event_limit: int = 20) -> dict:
        with self._lock:
            stats = dict(self.stats)
        return {
            "engine": {"name": cfg.ENGINE_NAME, "version": cfg.ENGINE_VERSION,
                       "uptime_seconds": int(time.time() - self.started_at)},
            "threat_level": self.threat_level(),
            "stats": {
                "expenses_analyzed": stats.get("expenses_analyzed", 0),
                "anomalies_flagged": stats.get("anomalies_flagged", 0),
                "threats_blocked": stats.get("threats_blocked", 0) + stats.get("anomalies_blocked", 0),
                "clients_blocked": stats.get("clients_blocked", 0),
                "events_recorded": stats.get("events_recorded", 0),
                "baseline_entries": stats.get("baseline_entries", 0),
                "dry_runs": stats.get("dry_runs", 0),
            },
            "models": {
                "threat_classifier": self.classifier.info,
                "anomaly_detector": self.anomaly.info,
                "intrusion_detector": self.intrusion.info,
                "llm_analyst": self.analyst.info,
            },
            "clients": self.intrusion.snapshot(limit=10),
            "user_profiles": self.anomaly.user_profiles(),
            "recent_events": self.get_events(limit=event_limit),
        }

    # -- explanations ------------------------------------------------------
    def explain_event(self, event_id: int) -> dict:
        event = self.find_event(event_id)
        if event is None:
            return {"found": False, "event_id": event_id}
        context = {
            "engine": f"{cfg.ENGINE_NAME} v{cfg.ENGINE_VERSION}",
            "client_verdict": self.intrusion.evaluate(event.get("client_id") or "unknown").to_dict(),
            "threat_level": self.threat_level(),
        }
        explanation = self.analyst.explain(event, context) if self.analyst.available else None
        if explanation is not None:
            self.stats["llm_explanations"] += 1
            return {"found": True, "event": event, "explanation": explanation, "source": "llm"}
        return {"found": True, "event": event, "explanation": self.rule_based_explanation(event),
                "source": "rules", "llm_error": self.analyst.last_error if self.analyst.enabled else None}

    @staticmethod
    def rule_based_explanation(event: dict) -> dict:
        etype = event.get("event_type", "")
        details = event.get("details") or {}
        severity = event.get("severity", SEVERITY_MEDIUM)
        templates = {
            "injection_detected": ("The input matched the profile of an injection payload. The request was "
                                   "rejected before reaching the ledger.", True,
                                   ["Review the client that sent it", "Consider blocking repeat offenders"]),
            "anomaly_critical": ("The expense deviated far enough from learned spending behaviour to be "
                                 "rejected automatically.", True,
                                 ["Confirm the expense with the submitting user", "Adjust thresholds if legitimate"]),
            "anomaly_high": ("The expense was accepted but is unusual compared with learned behaviour.", False,
                             ["Verify the amount with the group", "Watch for follow-up submissions"]),
            "anomaly_medium": ("The expense is mildly unusual and was accepted.", False, ["No action required"]),
            "login_failed": ("A password check failed for this account.", False,
                             ["Repeated failures escalate to throttling and blocking automatically"]),
            "hmac_mismatch": ("The request body did not match its integrity tag: it was modified in transit "
                              "or forged.", True, ["Investigate the network path", "Rotate the session"]),
            "replay_detected": ("A previously processed request was submitted again.", True,
                                ["Investigate the client", "Confirm no duplicate ledger entries exist"]),
            "signature_invalid": ("A ledger entry or handshake carried a signature that does not verify.", True,
                                  ["Treat as spoofing", "Check the user's key material"]),
            "decryption_failed": ("An encrypted message could not be authenticated or decrypted.", True,
                                  ["Treat as tampering", "Check for a stale or hijacked session"]),
            "client_blocked": ("The client's intrusion score crossed the block threshold; state-changing "
                               "requests are rejected until it cools down.", True,
                               ["No action needed unless a legitimate user is affected"]),
            "rate_limited": ("The client exceeded the request rate limit.", False, ["Monitor for abuse"]),
        }
        summary, likely_attack, actions = templates.get(
            etype, (f"Security event '{etype}' was recorded.", severity in (SEVERITY_HIGH, SEVERITY_CRITICAL),
                    ["Review the event details"]))
        indicators = list(details.get("reasons") or [])
        if details.get("signatures"):
            indicators.append("Matched rules: " + ", ".join(details["signatures"]))
        return {"summary": summary, "likely_attack": likely_attack, "severity": severity,
                "indicators": indicators, "recommended_actions": actions, "model": "rule-based"}
