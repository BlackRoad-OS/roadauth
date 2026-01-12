"""RoadAuth Sentinel Agent - Threat Detection & Anomaly Monitoring.

The Sentinel agent monitors authentication events and detects:
- Brute force attacks
- Credential stuffing
- Account takeover attempts
- Suspicious login patterns
- Geographic anomalies
- Device fingerprint anomalies

Copyright (c) 2024-2026 BlackRoad OS, Inc. All rights reserved.
"""

from __future__ import annotations

import logging
import math
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class ThreatLevel(Enum):
    """Threat severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatType(Enum):
    """Types of detected threats."""

    BRUTE_FORCE = auto()
    CREDENTIAL_STUFFING = auto()
    ACCOUNT_TAKEOVER = auto()
    SUSPICIOUS_LOCATION = auto()
    IMPOSSIBLE_TRAVEL = auto()
    DEVICE_CHANGE = auto()
    BOT_ACTIVITY = auto()
    DISTRIBUTED_ATTACK = auto()
    PASSWORD_SPRAY = auto()
    TOR_EXIT_NODE = auto()
    KNOWN_BAD_IP = auto()
    ANOMALOUS_BEHAVIOR = auto()


@dataclass
class ThreatEvent:
    """Detected threat event."""

    id: str
    threat_type: ThreatType
    level: ThreatLevel
    timestamp: datetime = field(default_factory=datetime.now)

    # Context
    user_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    session_id: Optional[str] = None

    # Details
    description: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    recommended_action: Optional[str] = None

    # Status
    acknowledged: bool = False
    resolved: bool = False
    resolved_at: Optional[datetime] = None
    resolved_by: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "threat_type": self.threat_type.name,
            "level": self.level.value,
            "timestamp": self.timestamp.isoformat(),
            "user_id": self.user_id,
            "ip_address": self.ip_address,
            "description": self.description,
            "evidence": self.evidence,
            "recommended_action": self.recommended_action,
            "acknowledged": self.acknowledged,
            "resolved": self.resolved,
        }


@dataclass
class LoginAttempt:
    """Login attempt record."""

    timestamp: datetime
    ip_address: str
    user_agent: str
    success: bool
    user_id: Optional[str] = None
    location: Optional[Dict[str, Any]] = None
    device_fingerprint: Optional[str] = None


class TimeWindow:
    """Sliding time window for tracking events."""

    def __init__(self, window_seconds: int = 300):
        """Initialize time window.

        Args:
            window_seconds: Window duration in seconds
        """
        self.window_seconds = window_seconds
        self._events: List[Tuple[float, Any]] = []
        self._lock = threading.Lock()

    def add(self, event: Any) -> None:
        """Add event to window."""
        with self._lock:
            now = time.time()
            self._events.append((now, event))
            self._cleanup(now)

    def count(self) -> int:
        """Get count of events in window."""
        with self._lock:
            self._cleanup(time.time())
            return len(self._events)

    def get_events(self) -> List[Any]:
        """Get all events in window."""
        with self._lock:
            self._cleanup(time.time())
            return [e[1] for e in self._events]

    def _cleanup(self, now: float) -> None:
        """Remove expired events."""
        cutoff = now - self.window_seconds
        self._events = [(t, e) for t, e in self._events if t > cutoff]


class BruteForceDetector:
    """Detects brute force attacks."""

    def __init__(
        self,
        threshold: int = 10,
        window_seconds: int = 300,
    ):
        """Initialize detector.

        Args:
            threshold: Number of failures to trigger
            window_seconds: Time window
        """
        self.threshold = threshold
        self.window_seconds = window_seconds
        self._by_ip: Dict[str, TimeWindow] = defaultdict(lambda: TimeWindow(window_seconds))
        self._by_user: Dict[str, TimeWindow] = defaultdict(lambda: TimeWindow(window_seconds))

    def record(self, attempt: LoginAttempt) -> Optional[ThreatEvent]:
        """Record login attempt and check for brute force.

        Args:
            attempt: Login attempt

        Returns:
            ThreatEvent if detected
        """
        if attempt.success:
            return None

        # Track by IP
        self._by_ip[attempt.ip_address].add(attempt)
        ip_count = self._by_ip[attempt.ip_address].count()

        # Track by user
        if attempt.user_id:
            self._by_user[attempt.user_id].add(attempt)
            user_count = self._by_user[attempt.user_id].count()
        else:
            user_count = 0

        # Check thresholds
        if ip_count >= self.threshold:
            return ThreatEvent(
                id=f"bf_{attempt.ip_address}_{int(time.time())}",
                threat_type=ThreatType.BRUTE_FORCE,
                level=ThreatLevel.HIGH if ip_count >= self.threshold * 2 else ThreatLevel.MEDIUM,
                ip_address=attempt.ip_address,
                description=f"Brute force attack detected: {ip_count} failed attempts from IP",
                evidence={
                    "failed_attempts": ip_count,
                    "window_seconds": self.window_seconds,
                    "threshold": self.threshold,
                },
                recommended_action="Block IP temporarily",
            )

        if user_count >= self.threshold:
            return ThreatEvent(
                id=f"bf_{attempt.user_id}_{int(time.time())}",
                threat_type=ThreatType.BRUTE_FORCE,
                level=ThreatLevel.HIGH,
                user_id=attempt.user_id,
                ip_address=attempt.ip_address,
                description=f"Brute force attack on user: {user_count} failed attempts",
                evidence={
                    "failed_attempts": user_count,
                    "window_seconds": self.window_seconds,
                },
                recommended_action="Lock account temporarily",
            )

        return None


class CredentialStuffingDetector:
    """Detects credential stuffing attacks."""

    def __init__(
        self,
        unique_user_threshold: int = 20,
        window_seconds: int = 300,
    ):
        """Initialize detector.

        Args:
            unique_user_threshold: Unique users per IP to trigger
            window_seconds: Time window
        """
        self.unique_user_threshold = unique_user_threshold
        self.window_seconds = window_seconds
        self._by_ip: Dict[str, TimeWindow] = defaultdict(lambda: TimeWindow(window_seconds))

    def record(self, attempt: LoginAttempt) -> Optional[ThreatEvent]:
        """Record attempt and check for credential stuffing.

        Args:
            attempt: Login attempt

        Returns:
            ThreatEvent if detected
        """
        if not attempt.user_id:
            return None

        self._by_ip[attempt.ip_address].add(attempt.user_id)

        # Count unique users
        users = set(self._by_ip[attempt.ip_address].get_events())

        if len(users) >= self.unique_user_threshold:
            return ThreatEvent(
                id=f"cs_{attempt.ip_address}_{int(time.time())}",
                threat_type=ThreatType.CREDENTIAL_STUFFING,
                level=ThreatLevel.CRITICAL,
                ip_address=attempt.ip_address,
                description=f"Credential stuffing detected: {len(users)} unique users from IP",
                evidence={
                    "unique_users": len(users),
                    "window_seconds": self.window_seconds,
                },
                recommended_action="Block IP and investigate",
            )

        return None


class ImpossibleTravelDetector:
    """Detects impossible travel scenarios."""

    # Earth radius in km
    EARTH_RADIUS = 6371

    def __init__(
        self,
        max_speed_kmh: float = 900,  # Typical airplane speed
    ):
        """Initialize detector.

        Args:
            max_speed_kmh: Maximum travel speed in km/h
        """
        self.max_speed_kmh = max_speed_kmh
        self._last_login: Dict[str, Tuple[datetime, Dict[str, Any]]] = {}

    def record(
        self,
        user_id: str,
        timestamp: datetime,
        location: Dict[str, Any],
    ) -> Optional[ThreatEvent]:
        """Record login and check for impossible travel.

        Args:
            user_id: User ID
            timestamp: Login timestamp
            location: Location with lat/lon

        Returns:
            ThreatEvent if detected
        """
        if not location or "lat" not in location or "lon" not in location:
            return None

        last = self._last_login.get(user_id)
        self._last_login[user_id] = (timestamp, location)

        if not last:
            return None

        last_time, last_location = last

        # Calculate distance
        distance = self._haversine(
            last_location["lat"], last_location["lon"],
            location["lat"], location["lon"]
        )

        # Calculate time difference
        time_diff = (timestamp - last_time).total_seconds() / 3600  # hours

        if time_diff <= 0:
            return None

        # Calculate required speed
        required_speed = distance / time_diff

        if required_speed > self.max_speed_kmh:
            return ThreatEvent(
                id=f"it_{user_id}_{int(time.time())}",
                threat_type=ThreatType.IMPOSSIBLE_TRAVEL,
                level=ThreatLevel.HIGH,
                user_id=user_id,
                description=f"Impossible travel detected: {distance:.0f}km in {time_diff:.1f}h",
                evidence={
                    "distance_km": round(distance, 1),
                    "time_hours": round(time_diff, 2),
                    "required_speed_kmh": round(required_speed, 0),
                    "max_speed_kmh": self.max_speed_kmh,
                    "from_location": last_location,
                    "to_location": location,
                },
                recommended_action="Require re-authentication",
            )

        return None

    def _haversine(self, lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """Calculate distance between two points using Haversine formula.

        Returns:
            Distance in kilometers
        """
        lat1_rad = math.radians(lat1)
        lat2_rad = math.radians(lat2)
        delta_lat = math.radians(lat2 - lat1)
        delta_lon = math.radians(lon2 - lon1)

        a = math.sin(delta_lat / 2) ** 2 + \
            math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(delta_lon / 2) ** 2
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

        return self.EARTH_RADIUS * c


class AnomalyScorer:
    """Scores login attempts for anomalies."""

    def __init__(self):
        """Initialize scorer."""
        self._user_patterns: Dict[str, Dict[str, Any]] = {}

    def score(self, attempt: LoginAttempt) -> float:
        """Score login attempt for anomaly.

        Args:
            attempt: Login attempt

        Returns:
            Anomaly score (0.0 = normal, 1.0 = highly anomalous)
        """
        if not attempt.user_id:
            return 0.0

        patterns = self._user_patterns.get(attempt.user_id)
        if not patterns:
            # First login, establish baseline
            self._update_patterns(attempt)
            return 0.0

        score = 0.0
        factors = 0

        # Time of day anomaly
        hour = attempt.timestamp.hour
        usual_hours = patterns.get("usual_hours", set())
        if usual_hours and hour not in usual_hours:
            score += 0.3
        factors += 1

        # Day of week anomaly
        day = attempt.timestamp.weekday()
        usual_days = patterns.get("usual_days", set())
        if usual_days and day not in usual_days:
            score += 0.2
        factors += 1

        # IP anomaly
        usual_ips = patterns.get("usual_ips", set())
        if usual_ips and attempt.ip_address not in usual_ips:
            score += 0.3
        factors += 1

        # User agent anomaly
        usual_agents = patterns.get("usual_agents", set())
        if usual_agents and attempt.user_agent not in usual_agents:
            score += 0.2
        factors += 1

        # Update patterns
        self._update_patterns(attempt)

        return min(1.0, score / factors * 2) if factors > 0 else 0.0

    def _update_patterns(self, attempt: LoginAttempt) -> None:
        """Update user patterns."""
        if not attempt.user_id:
            return

        if attempt.user_id not in self._user_patterns:
            self._user_patterns[attempt.user_id] = {
                "usual_hours": set(),
                "usual_days": set(),
                "usual_ips": set(),
                "usual_agents": set(),
            }

        patterns = self._user_patterns[attempt.user_id]

        # Keep last N items
        max_items = 10

        patterns["usual_hours"].add(attempt.timestamp.hour)
        patterns["usual_days"].add(attempt.timestamp.weekday())
        patterns["usual_ips"].add(attempt.ip_address)
        patterns["usual_agents"].add(attempt.user_agent)

        # Trim to max items
        for key in ["usual_ips", "usual_agents"]:
            if len(patterns[key]) > max_items:
                patterns[key] = set(list(patterns[key])[-max_items:])


class Sentinel:
    """Sentinel Agent - Threat Detection & Anomaly Monitoring.

    The Sentinel continuously monitors authentication events,
    analyzing patterns and detecting potential security threats
    using multiple detection algorithms.
    """

    def __init__(
        self,
        brute_force_threshold: int = 10,
        credential_stuffing_threshold: int = 20,
        anomaly_threshold: float = 0.7,
        window_seconds: int = 300,
    ):
        """Initialize Sentinel.

        Args:
            brute_force_threshold: Failures to trigger brute force detection
            credential_stuffing_threshold: Unique users per IP threshold
            anomaly_threshold: Anomaly score threshold
            window_seconds: Detection window in seconds
        """
        self.brute_force_detector = BruteForceDetector(
            threshold=brute_force_threshold,
            window_seconds=window_seconds,
        )
        self.credential_stuffing_detector = CredentialStuffingDetector(
            unique_user_threshold=credential_stuffing_threshold,
            window_seconds=window_seconds,
        )
        self.impossible_travel_detector = ImpossibleTravelDetector()
        self.anomaly_scorer = AnomalyScorer()

        self.anomaly_threshold = anomaly_threshold

        # Threat storage
        self._threats: Dict[str, ThreatEvent] = {}
        self._threat_handlers: List[Callable[[ThreatEvent], None]] = []
        self._lock = threading.RLock()

        # Statistics
        self._stats = {
            "total_attempts": 0,
            "failed_attempts": 0,
            "threats_detected": 0,
            "threats_by_type": defaultdict(int),
        }

    def analyze(self, attempt: LoginAttempt) -> List[ThreatEvent]:
        """Analyze login attempt for threats.

        Args:
            attempt: Login attempt to analyze

        Returns:
            List of detected threats
        """
        threats = []

        # Update stats
        self._stats["total_attempts"] += 1
        if not attempt.success:
            self._stats["failed_attempts"] += 1

        # Run detectors
        bf_threat = self.brute_force_detector.record(attempt)
        if bf_threat:
            threats.append(bf_threat)

        cs_threat = self.credential_stuffing_detector.record(attempt)
        if cs_threat:
            threats.append(cs_threat)

        # Impossible travel (only for successful logins)
        if attempt.success and attempt.user_id and attempt.location:
            it_threat = self.impossible_travel_detector.record(
                attempt.user_id,
                attempt.timestamp,
                attempt.location,
            )
            if it_threat:
                threats.append(it_threat)

        # Anomaly scoring
        anomaly_score = self.anomaly_scorer.score(attempt)
        if anomaly_score >= self.anomaly_threshold:
            threats.append(ThreatEvent(
                id=f"an_{attempt.user_id}_{int(time.time())}",
                threat_type=ThreatType.ANOMALOUS_BEHAVIOR,
                level=ThreatLevel.MEDIUM if anomaly_score < 0.9 else ThreatLevel.HIGH,
                user_id=attempt.user_id,
                ip_address=attempt.ip_address,
                description=f"Anomalous login behavior detected (score: {anomaly_score:.2f})",
                evidence={
                    "anomaly_score": round(anomaly_score, 2),
                    "threshold": self.anomaly_threshold,
                },
                recommended_action="Monitor user activity",
            ))

        # Store and notify
        for threat in threats:
            self._store_threat(threat)
            self._notify_handlers(threat)
            self._stats["threats_detected"] += 1
            self._stats["threats_by_type"][threat.threat_type.name] += 1

        return threats

    def on_threat(self, handler: Callable[[ThreatEvent], None]) -> None:
        """Register threat handler.

        Args:
            handler: Callback function
        """
        self._threat_handlers.append(handler)

    def get_threats(
        self,
        threat_type: Optional[ThreatType] = None,
        level: Optional[ThreatLevel] = None,
        unresolved_only: bool = False,
        limit: int = 100,
    ) -> List[ThreatEvent]:
        """Get detected threats.

        Args:
            threat_type: Filter by type
            level: Filter by level
            unresolved_only: Only unresolved threats
            limit: Maximum results

        Returns:
            List of threats
        """
        with self._lock:
            threats = list(self._threats.values())

        # Filter
        if threat_type:
            threats = [t for t in threats if t.threat_type == threat_type]
        if level:
            threats = [t for t in threats if t.level == level]
        if unresolved_only:
            threats = [t for t in threats if not t.resolved]

        # Sort by timestamp (newest first)
        threats.sort(key=lambda t: t.timestamp, reverse=True)

        return threats[:limit]

    def acknowledge_threat(self, threat_id: str) -> bool:
        """Acknowledge a threat.

        Args:
            threat_id: Threat ID

        Returns:
            True if acknowledged
        """
        with self._lock:
            if threat_id in self._threats:
                self._threats[threat_id].acknowledged = True
                return True
            return False

    def resolve_threat(self, threat_id: str, resolved_by: str) -> bool:
        """Resolve a threat.

        Args:
            threat_id: Threat ID
            resolved_by: User who resolved

        Returns:
            True if resolved
        """
        with self._lock:
            if threat_id in self._threats:
                threat = self._threats[threat_id]
                threat.resolved = True
                threat.resolved_at = datetime.now()
                threat.resolved_by = resolved_by
                return True
            return False

    def get_statistics(self) -> Dict[str, Any]:
        """Get sentinel statistics.

        Returns:
            Statistics dictionary
        """
        return {
            **self._stats,
            "threats_by_type": dict(self._stats["threats_by_type"]),
            "active_threats": len([t for t in self._threats.values() if not t.resolved]),
        }

    def _store_threat(self, threat: ThreatEvent) -> None:
        """Store threat event."""
        with self._lock:
            self._threats[threat.id] = threat

    def _notify_handlers(self, threat: ThreatEvent) -> None:
        """Notify threat handlers."""
        for handler in self._threat_handlers:
            try:
                handler(threat)
            except Exception as e:
                logger.error(f"Threat handler error: {e}")


__all__ = [
    "Sentinel",
    "ThreatEvent",
    "ThreatType",
    "ThreatLevel",
    "LoginAttempt",
    "BruteForceDetector",
    "CredentialStuffingDetector",
    "ImpossibleTravelDetector",
    "AnomalyScorer",
]
