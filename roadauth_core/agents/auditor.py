"""RoadAuth Auditor Agent - Security Audit & Compliance.

The Auditor agent maintains comprehensive audit logs and ensures:
- Audit trail for all authentication events
- Compliance reporting (SOC 2, GDPR, HIPAA)
- Log integrity verification
- Event correlation and analysis
- Forensic investigation support

Copyright (c) 2024-2026 BlackRoad OS, Inc. All rights reserved.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
import secrets

logger = logging.getLogger(__name__)


class AuditEventType(Enum):
    """Audit event types."""

    # Authentication events
    LOGIN_SUCCESS = auto()
    LOGIN_FAILURE = auto()
    LOGOUT = auto()
    SESSION_CREATED = auto()
    SESSION_EXPIRED = auto()
    SESSION_REVOKED = auto()

    # MFA events
    MFA_SETUP = auto()
    MFA_VERIFIED = auto()
    MFA_FAILED = auto()
    MFA_DISABLED = auto()
    BACKUP_CODE_USED = auto()

    # Token events
    TOKEN_ISSUED = auto()
    TOKEN_REFRESHED = auto()
    TOKEN_REVOKED = auto()
    TOKEN_EXPIRED = auto()

    # User events
    USER_CREATED = auto()
    USER_UPDATED = auto()
    USER_DELETED = auto()
    USER_LOCKED = auto()
    USER_UNLOCKED = auto()
    PASSWORD_CHANGED = auto()
    PASSWORD_RESET = auto()

    # Role/permission events
    ROLE_ASSIGNED = auto()
    ROLE_REMOVED = auto()
    PERMISSION_GRANTED = auto()
    PERMISSION_REVOKED = auto()

    # Access events
    ACCESS_GRANTED = auto()
    ACCESS_DENIED = auto()
    AUTHORIZATION_CHECK = auto()

    # Admin events
    ADMIN_ACTION = auto()
    CONFIG_CHANGED = auto()
    PROVIDER_ADDED = auto()
    PROVIDER_REMOVED = auto()

    # Security events
    THREAT_DETECTED = auto()
    ACCOUNT_COMPROMISED = auto()
    SUSPICIOUS_ACTIVITY = auto()


class AuditSeverity(Enum):
    """Audit event severity."""

    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class AuditEvent:
    """Audit event record."""

    id: str
    event_type: AuditEventType
    severity: AuditSeverity
    timestamp: datetime = field(default_factory=datetime.now)

    # Actor
    user_id: Optional[str] = None
    username: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    session_id: Optional[str] = None

    # Target
    target_type: Optional[str] = None
    target_id: Optional[str] = None

    # Details
    action: str = ""
    outcome: str = ""  # success, failure, error
    details: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    # Integrity
    previous_hash: Optional[str] = None
    hash: Optional[str] = None

    def compute_hash(self, previous_hash: str = "") -> str:
        """Compute event hash for integrity."""
        data = {
            "id": self.id,
            "event_type": self.event_type.name,
            "timestamp": self.timestamp.isoformat(),
            "user_id": self.user_id,
            "action": self.action,
            "outcome": self.outcome,
            "details": self.details,
            "previous_hash": previous_hash,
        }
        serialized = json.dumps(data, sort_keys=True)
        return hashlib.sha256(serialized.encode()).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "event_type": self.event_type.name,
            "severity": self.severity.value,
            "timestamp": self.timestamp.isoformat(),
            "user_id": self.user_id,
            "username": self.username,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "session_id": self.session_id,
            "target_type": self.target_type,
            "target_id": self.target_id,
            "action": self.action,
            "outcome": self.outcome,
            "details": self.details,
            "metadata": self.metadata,
            "hash": self.hash,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AuditEvent:
        """Create from dictionary."""
        return cls(
            id=data["id"],
            event_type=AuditEventType[data["event_type"]],
            severity=AuditSeverity(data.get("severity", "info")),
            timestamp=datetime.fromisoformat(data["timestamp"]),
            user_id=data.get("user_id"),
            username=data.get("username"),
            ip_address=data.get("ip_address"),
            user_agent=data.get("user_agent"),
            session_id=data.get("session_id"),
            target_type=data.get("target_type"),
            target_id=data.get("target_id"),
            action=data.get("action", ""),
            outcome=data.get("outcome", ""),
            details=data.get("details", {}),
            metadata=data.get("metadata", {}),
            hash=data.get("hash"),
        )


class AuditStore:
    """In-memory audit store."""

    def __init__(self, max_events: int = 100000):
        """Initialize store."""
        self._events: List[AuditEvent] = []
        self._by_user: Dict[str, List[str]] = defaultdict(list)
        self._by_type: Dict[AuditEventType, List[str]] = defaultdict(list)
        self._max_events = max_events
        self._last_hash = ""
        self._lock = threading.RLock()

    def append(self, event: AuditEvent) -> None:
        """Append event to audit log."""
        with self._lock:
            # Compute hash chain
            event.previous_hash = self._last_hash
            event.hash = event.compute_hash(self._last_hash)
            self._last_hash = event.hash

            # Store event
            self._events.append(event)

            # Update indexes
            if event.user_id:
                self._by_user[event.user_id].append(event.id)
            self._by_type[event.event_type].append(event.id)

            # Trim if needed
            if len(self._events) > self._max_events:
                removed = self._events.pop(0)
                if removed.user_id and removed.id in self._by_user[removed.user_id]:
                    self._by_user[removed.user_id].remove(removed.id)

    def get(self, event_id: str) -> Optional[AuditEvent]:
        """Get event by ID."""
        for event in self._events:
            if event.id == event_id:
                return event
        return None

    def query(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        event_type: Optional[AuditEventType] = None,
        user_id: Optional[str] = None,
        severity: Optional[AuditSeverity] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[AuditEvent]:
        """Query audit events."""
        with self._lock:
            events = list(self._events)

        # Filter
        if start_time:
            events = [e for e in events if e.timestamp >= start_time]
        if end_time:
            events = [e for e in events if e.timestamp <= end_time]
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        if user_id:
            events = [e for e in events if e.user_id == user_id]
        if severity:
            events = [e for e in events if e.severity == severity]

        # Sort by timestamp (newest first)
        events.sort(key=lambda e: e.timestamp, reverse=True)

        return events[offset:offset + limit]

    def verify_integrity(self) -> Tuple[bool, List[str]]:
        """Verify audit log integrity."""
        with self._lock:
            errors = []
            previous_hash = ""

            for i, event in enumerate(self._events):
                expected_hash = event.compute_hash(previous_hash)

                if event.hash != expected_hash:
                    errors.append(f"Event {i} ({event.id}): hash mismatch")

                if event.previous_hash != previous_hash:
                    errors.append(f"Event {i} ({event.id}): chain broken")

                previous_hash = event.hash or ""

            return len(errors) == 0, errors

    @property
    def count(self) -> int:
        """Get total event count."""
        return len(self._events)


class ComplianceReport:
    """Compliance report generator."""

    def __init__(self, store: AuditStore):
        """Initialize generator."""
        self.store = store

    def generate_access_report(
        self,
        start_time: datetime,
        end_time: datetime,
        user_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Generate access report."""
        events = self.store.query(
            start_time=start_time,
            end_time=end_time,
            user_id=user_id,
            limit=10000,
        )

        # Categorize events
        login_success = [e for e in events if e.event_type == AuditEventType.LOGIN_SUCCESS]
        login_failure = [e for e in events if e.event_type == AuditEventType.LOGIN_FAILURE]
        access_denied = [e for e in events if e.event_type == AuditEventType.ACCESS_DENIED]

        return {
            "report_type": "access",
            "period": {
                "start": start_time.isoformat(),
                "end": end_time.isoformat(),
            },
            "summary": {
                "total_events": len(events),
                "successful_logins": len(login_success),
                "failed_logins": len(login_failure),
                "access_denied": len(access_denied),
                "unique_users": len(set(e.user_id for e in events if e.user_id)),
                "unique_ips": len(set(e.ip_address for e in events if e.ip_address)),
            },
            "generated_at": datetime.now().isoformat(),
        }

    def generate_security_report(
        self,
        start_time: datetime,
        end_time: datetime,
    ) -> Dict[str, Any]:
        """Generate security report."""
        events = self.store.query(
            start_time=start_time,
            end_time=end_time,
            limit=10000,
        )

        # Security events
        security_events = [
            e for e in events
            if e.event_type in {
                AuditEventType.THREAT_DETECTED,
                AuditEventType.ACCOUNT_COMPROMISED,
                AuditEventType.SUSPICIOUS_ACTIVITY,
                AuditEventType.LOGIN_FAILURE,
                AuditEventType.ACCESS_DENIED,
            }
        ]

        # By severity
        by_severity = defaultdict(int)
        for e in security_events:
            by_severity[e.severity.value] += 1

        return {
            "report_type": "security",
            "period": {
                "start": start_time.isoformat(),
                "end": end_time.isoformat(),
            },
            "summary": {
                "total_security_events": len(security_events),
                "by_severity": dict(by_severity),
                "threats_detected": len([e for e in events if e.event_type == AuditEventType.THREAT_DETECTED]),
                "accounts_compromised": len([e for e in events if e.event_type == AuditEventType.ACCOUNT_COMPROMISED]),
            },
            "generated_at": datetime.now().isoformat(),
        }

    def generate_compliance_report(
        self,
        start_time: datetime,
        end_time: datetime,
        framework: str = "SOC2",
    ) -> Dict[str, Any]:
        """Generate compliance report."""
        events = self.store.query(
            start_time=start_time,
            end_time=end_time,
            limit=10000,
        )

        # Verify integrity
        integrity_ok, integrity_errors = self.store.verify_integrity()

        # Check for required controls
        controls = {
            "access_logging": len(events) > 0,
            "authentication_logging": any(
                e.event_type in {AuditEventType.LOGIN_SUCCESS, AuditEventType.LOGIN_FAILURE}
                for e in events
            ),
            "password_change_logging": any(
                e.event_type == AuditEventType.PASSWORD_CHANGED
                for e in events
            ),
            "admin_action_logging": any(
                e.event_type == AuditEventType.ADMIN_ACTION
                for e in events
            ),
            "log_integrity": integrity_ok,
        }

        return {
            "report_type": "compliance",
            "framework": framework,
            "period": {
                "start": start_time.isoformat(),
                "end": end_time.isoformat(),
            },
            "controls": controls,
            "compliance_score": sum(controls.values()) / len(controls) * 100,
            "integrity_status": "passed" if integrity_ok else "failed",
            "integrity_errors": integrity_errors,
            "generated_at": datetime.now().isoformat(),
        }


class Auditor:
    """Auditor Agent - Security Audit & Compliance.

    The Auditor maintains comprehensive audit logs, ensures
    log integrity, and generates compliance reports.
    """

    def __init__(
        self,
        store: Optional[AuditStore] = None,
    ):
        """Initialize Auditor.

        Args:
            store: Audit store implementation
        """
        self.store = store or AuditStore()
        self.compliance = ComplianceReport(self.store)
        self._handlers: List[Callable[[AuditEvent], None]] = []

    def log(
        self,
        event_type: AuditEventType,
        action: str,
        outcome: str = "success",
        severity: AuditSeverity = AuditSeverity.INFO,
        user_id: Optional[str] = None,
        username: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        session_id: Optional[str] = None,
        target_type: Optional[str] = None,
        target_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        """Log an audit event.

        Args:
            event_type: Type of event
            action: Action description
            outcome: Action outcome
            severity: Event severity
            user_id: Acting user ID
            username: Acting username
            ip_address: Client IP
            user_agent: Client user agent
            session_id: Session ID
            target_type: Target entity type
            target_id: Target entity ID
            details: Additional details
            metadata: Additional metadata

        Returns:
            Created audit event
        """
        event = AuditEvent(
            id=secrets.token_urlsafe(16),
            event_type=event_type,
            severity=severity,
            user_id=user_id,
            username=username,
            ip_address=ip_address,
            user_agent=user_agent,
            session_id=session_id,
            target_type=target_type,
            target_id=target_id,
            action=action,
            outcome=outcome,
            details=details or {},
            metadata=metadata or {},
        )

        # Store event
        self.store.append(event)

        # Notify handlers
        for handler in self._handlers:
            try:
                handler(event)
            except Exception as e:
                logger.error(f"Audit handler error: {e}")

        return event

    def log_login(
        self,
        success: bool,
        user_id: Optional[str] = None,
        username: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        failure_reason: Optional[str] = None,
    ) -> AuditEvent:
        """Log login event."""
        event_type = AuditEventType.LOGIN_SUCCESS if success else AuditEventType.LOGIN_FAILURE
        severity = AuditSeverity.INFO if success else AuditSeverity.WARNING

        details = {}
        if failure_reason:
            details["failure_reason"] = failure_reason

        return self.log(
            event_type=event_type,
            action="User login",
            outcome="success" if success else "failure",
            severity=severity,
            user_id=user_id,
            username=username,
            ip_address=ip_address,
            user_agent=user_agent,
            details=details,
        )

    def log_access(
        self,
        granted: bool,
        user_id: str,
        resource: str,
        action: str,
        ip_address: Optional[str] = None,
        denial_reason: Optional[str] = None,
    ) -> AuditEvent:
        """Log access control event."""
        event_type = AuditEventType.ACCESS_GRANTED if granted else AuditEventType.ACCESS_DENIED
        severity = AuditSeverity.INFO if granted else AuditSeverity.WARNING

        details = {
            "resource": resource,
            "requested_action": action,
        }
        if denial_reason:
            details["denial_reason"] = denial_reason

        return self.log(
            event_type=event_type,
            action=f"Access {action} on {resource}",
            outcome="granted" if granted else "denied",
            severity=severity,
            user_id=user_id,
            ip_address=ip_address,
            target_type="resource",
            target_id=resource,
            details=details,
        )

    def log_admin_action(
        self,
        admin_id: str,
        action: str,
        target_type: str,
        target_id: str,
        ip_address: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        """Log administrative action."""
        return self.log(
            event_type=AuditEventType.ADMIN_ACTION,
            action=action,
            outcome="success",
            severity=AuditSeverity.WARNING,
            user_id=admin_id,
            ip_address=ip_address,
            target_type=target_type,
            target_id=target_id,
            details=details or {},
        )

    def on_event(self, handler: Callable[[AuditEvent], None]) -> None:
        """Register event handler."""
        self._handlers.append(handler)

    def query(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        event_type: Optional[AuditEventType] = None,
        user_id: Optional[str] = None,
        severity: Optional[AuditSeverity] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[AuditEvent]:
        """Query audit events."""
        return self.store.query(
            start_time=start_time,
            end_time=end_time,
            event_type=event_type,
            user_id=user_id,
            severity=severity,
            limit=limit,
            offset=offset,
        )

    def get_user_activity(
        self,
        user_id: str,
        days: int = 30,
    ) -> List[AuditEvent]:
        """Get user activity history."""
        start_time = datetime.now() - timedelta(days=days)
        return self.query(user_id=user_id, start_time=start_time, limit=1000)

    def verify_integrity(self) -> Tuple[bool, List[str]]:
        """Verify audit log integrity."""
        return self.store.verify_integrity()

    def generate_report(
        self,
        report_type: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """Generate compliance report."""
        if not start_time:
            start_time = datetime.now() - timedelta(days=30)
        if not end_time:
            end_time = datetime.now()

        if report_type == "access":
            return self.compliance.generate_access_report(start_time, end_time, **kwargs)
        elif report_type == "security":
            return self.compliance.generate_security_report(start_time, end_time)
        elif report_type == "compliance":
            return self.compliance.generate_compliance_report(start_time, end_time, **kwargs)
        else:
            raise ValueError(f"Unknown report type: {report_type}")

    def get_statistics(self) -> Dict[str, Any]:
        """Get auditor statistics."""
        events = self.store.query(limit=10000)

        by_type = defaultdict(int)
        by_severity = defaultdict(int)

        for event in events:
            by_type[event.event_type.name] += 1
            by_severity[event.severity.value] += 1

        return {
            "total_events": self.store.count,
            "events_by_type": dict(by_type),
            "events_by_severity": dict(by_severity),
        }


__all__ = [
    "Auditor",
    "AuditEvent",
    "AuditEventType",
    "AuditSeverity",
    "AuditStore",
    "ComplianceReport",
]
