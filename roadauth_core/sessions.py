"""RoadAuth Sessions - Distributed Session Management.

Provides comprehensive session handling including:
- Session creation and validation
- Distributed session stores (Redis, Database, Memory)
- Session security and fingerprinting
- Concurrent session management
- Session events and hooks

Copyright (c) 2024-2026 BlackRoad OS, Inc. All rights reserved.
"""

from __future__ import annotations

import hashlib
import json
import logging
import secrets
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union
from collections import OrderedDict

# Configure logging
logger = logging.getLogger(__name__)


class SessionStatus(Enum):
    """Session status."""

    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    LOCKED = "locked"


class SessionEvent(Enum):
    """Session lifecycle events."""

    CREATED = auto()
    ACCESSED = auto()
    UPDATED = auto()
    EXPIRED = auto()
    REVOKED = auto()
    LOCKED = auto()
    UNLOCKED = auto()


@dataclass
class SessionFingerprint:
    """Session fingerprint for device/browser identification."""

    user_agent: str = ""
    ip_address: str = ""
    accept_language: str = ""
    screen_resolution: str = ""
    timezone: str = ""
    platform: str = ""

    # Hardware fingerprint
    device_memory: Optional[int] = None
    hardware_concurrency: Optional[int] = None

    # Browser fingerprint
    plugins: List[str] = field(default_factory=list)
    canvas_hash: str = ""
    webgl_hash: str = ""
    audio_hash: str = ""

    def compute_hash(self) -> str:
        """Compute fingerprint hash."""
        data = {
            "user_agent": self.user_agent,
            "ip_address": self.ip_address,
            "accept_language": self.accept_language,
            "screen_resolution": self.screen_resolution,
            "timezone": self.timezone,
            "platform": self.platform,
            "device_memory": self.device_memory,
            "hardware_concurrency": self.hardware_concurrency,
            "plugins": sorted(self.plugins),
            "canvas_hash": self.canvas_hash,
            "webgl_hash": self.webgl_hash,
            "audio_hash": self.audio_hash,
        }

        serialized = json.dumps(data, sort_keys=True)
        return hashlib.sha256(serialized.encode()).hexdigest()[:16]

    def similarity(self, other: SessionFingerprint) -> float:
        """Calculate similarity score with another fingerprint.

        Args:
            other: Another fingerprint

        Returns:
            Similarity score (0.0 to 1.0)
        """
        matches = 0
        total = 0

        # Compare string fields
        string_fields = [
            "user_agent", "ip_address", "accept_language",
            "screen_resolution", "timezone", "platform",
            "canvas_hash", "webgl_hash", "audio_hash"
        ]

        for field_name in string_fields:
            total += 1
            if getattr(self, field_name) == getattr(other, field_name):
                matches += 1

        # Compare numeric fields
        if self.device_memory is not None and other.device_memory is not None:
            total += 1
            if self.device_memory == other.device_memory:
                matches += 1

        if self.hardware_concurrency is not None and other.hardware_concurrency is not None:
            total += 1
            if self.hardware_concurrency == other.hardware_concurrency:
                matches += 1

        # Compare plugins
        if self.plugins and other.plugins:
            total += 1
            common = len(set(self.plugins) & set(other.plugins))
            union = len(set(self.plugins) | set(other.plugins))
            if union > 0:
                matches += common / union

        return matches / total if total > 0 else 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "user_agent": self.user_agent,
            "ip_address": self.ip_address,
            "accept_language": self.accept_language,
            "screen_resolution": self.screen_resolution,
            "timezone": self.timezone,
            "platform": self.platform,
            "device_memory": self.device_memory,
            "hardware_concurrency": self.hardware_concurrency,
            "plugins": self.plugins,
            "canvas_hash": self.canvas_hash,
            "webgl_hash": self.webgl_hash,
            "audio_hash": self.audio_hash,
            "hash": self.compute_hash(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> SessionFingerprint:
        """Create from dictionary."""
        return cls(
            user_agent=data.get("user_agent", ""),
            ip_address=data.get("ip_address", ""),
            accept_language=data.get("accept_language", ""),
            screen_resolution=data.get("screen_resolution", ""),
            timezone=data.get("timezone", ""),
            platform=data.get("platform", ""),
            device_memory=data.get("device_memory"),
            hardware_concurrency=data.get("hardware_concurrency"),
            plugins=data.get("plugins", []),
            canvas_hash=data.get("canvas_hash", ""),
            webgl_hash=data.get("webgl_hash", ""),
            audio_hash=data.get("audio_hash", ""),
        )


@dataclass
class Session:
    """User session.

    Represents an authenticated user session with associated metadata,
    security information, and lifecycle management.
    """

    id: str
    user_id: str
    status: SessionStatus = SessionStatus.ACTIVE

    # Timestamps
    created_at: datetime = field(default_factory=datetime.now)
    accessed_at: datetime = field(default_factory=datetime.now)
    expires_at: Optional[datetime] = None

    # Security
    fingerprint: Optional[SessionFingerprint] = None
    ip_address: str = ""
    user_agent: str = ""

    # Token association
    access_token_id: Optional[str] = None
    refresh_token_id: Optional[str] = None

    # Session data
    data: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    # Activity tracking
    access_count: int = 0
    last_activity: Optional[str] = None

    # Security flags
    is_remembered: bool = False
    requires_mfa: bool = False
    mfa_verified: bool = False

    # Device info
    device_id: Optional[str] = None
    device_name: Optional[str] = None
    device_type: Optional[str] = None  # desktop, mobile, tablet

    @classmethod
    def create(
        cls,
        user_id: str,
        ttl: int = 3600,
        fingerprint: Optional[SessionFingerprint] = None,
        **kwargs
    ) -> Session:
        """Create a new session.

        Args:
            user_id: User ID
            ttl: Time to live in seconds
            fingerprint: Optional session fingerprint
            **kwargs: Additional session attributes

        Returns:
            New session instance
        """
        session_id = secrets.token_urlsafe(32)
        now = datetime.now()

        return cls(
            id=session_id,
            user_id=user_id,
            created_at=now,
            accessed_at=now,
            expires_at=now + timedelta(seconds=ttl),
            fingerprint=fingerprint,
            **kwargs
        )

    @property
    def is_expired(self) -> bool:
        """Check if session is expired."""
        if self.expires_at is None:
            return False
        return datetime.now() > self.expires_at

    @property
    def is_active(self) -> bool:
        """Check if session is active."""
        return self.status == SessionStatus.ACTIVE and not self.is_expired

    @property
    def age(self) -> timedelta:
        """Get session age."""
        return datetime.now() - self.created_at

    @property
    def idle_time(self) -> timedelta:
        """Get idle time since last access."""
        return datetime.now() - self.accessed_at

    def touch(self, activity: Optional[str] = None) -> None:
        """Update last access time.

        Args:
            activity: Optional activity description
        """
        self.accessed_at = datetime.now()
        self.access_count += 1
        if activity:
            self.last_activity = activity

    def extend(self, seconds: int) -> None:
        """Extend session expiration.

        Args:
            seconds: Seconds to extend
        """
        if self.expires_at:
            self.expires_at = self.expires_at + timedelta(seconds=seconds)
        else:
            self.expires_at = datetime.now() + timedelta(seconds=seconds)

    def revoke(self) -> None:
        """Revoke session."""
        self.status = SessionStatus.REVOKED

    def lock(self) -> None:
        """Lock session."""
        self.status = SessionStatus.LOCKED

    def unlock(self) -> None:
        """Unlock session."""
        if self.status == SessionStatus.LOCKED:
            self.status = SessionStatus.ACTIVE

    def set_data(self, key: str, value: Any) -> None:
        """Set session data.

        Args:
            key: Data key
            value: Data value
        """
        self.data[key] = value

    def get_data(self, key: str, default: Any = None) -> Any:
        """Get session data.

        Args:
            key: Data key
            default: Default value

        Returns:
            Data value or default
        """
        return self.data.get(key, default)

    def delete_data(self, key: str) -> bool:
        """Delete session data.

        Args:
            key: Data key

        Returns:
            True if deleted
        """
        if key in self.data:
            del self.data[key]
            return True
        return False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "accessed_at": self.accessed_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "fingerprint": self.fingerprint.to_dict() if self.fingerprint else None,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "access_token_id": self.access_token_id,
            "refresh_token_id": self.refresh_token_id,
            "data": self.data,
            "metadata": self.metadata,
            "access_count": self.access_count,
            "last_activity": self.last_activity,
            "is_remembered": self.is_remembered,
            "requires_mfa": self.requires_mfa,
            "mfa_verified": self.mfa_verified,
            "device_id": self.device_id,
            "device_name": self.device_name,
            "device_type": self.device_type,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Session:
        """Create from dictionary."""
        fingerprint = None
        if data.get("fingerprint"):
            fingerprint = SessionFingerprint.from_dict(data["fingerprint"])

        return cls(
            id=data["id"],
            user_id=data["user_id"],
            status=SessionStatus(data.get("status", "active")),
            created_at=datetime.fromisoformat(data["created_at"]),
            accessed_at=datetime.fromisoformat(data["accessed_at"]),
            expires_at=datetime.fromisoformat(data["expires_at"]) if data.get("expires_at") else None,
            fingerprint=fingerprint,
            ip_address=data.get("ip_address", ""),
            user_agent=data.get("user_agent", ""),
            access_token_id=data.get("access_token_id"),
            refresh_token_id=data.get("refresh_token_id"),
            data=data.get("data", {}),
            metadata=data.get("metadata", {}),
            access_count=data.get("access_count", 0),
            last_activity=data.get("last_activity"),
            is_remembered=data.get("is_remembered", False),
            requires_mfa=data.get("requires_mfa", False),
            mfa_verified=data.get("mfa_verified", False),
            device_id=data.get("device_id"),
            device_name=data.get("device_name"),
            device_type=data.get("device_type"),
        )


class SessionStore(ABC):
    """Abstract session store interface."""

    @abstractmethod
    def save(self, session: Session) -> bool:
        """Save session."""
        pass

    @abstractmethod
    def get(self, session_id: str) -> Optional[Session]:
        """Get session by ID."""
        pass

    @abstractmethod
    def delete(self, session_id: str) -> bool:
        """Delete session."""
        pass

    @abstractmethod
    def get_by_user(self, user_id: str) -> List[Session]:
        """Get all sessions for user."""
        pass

    @abstractmethod
    def delete_by_user(self, user_id: str) -> int:
        """Delete all sessions for user."""
        pass

    @abstractmethod
    def cleanup_expired(self) -> int:
        """Clean up expired sessions."""
        pass


class InMemorySessionStore(SessionStore):
    """In-memory session store with LRU eviction."""

    def __init__(self, max_sessions: int = 10000):
        """Initialize store.

        Args:
            max_sessions: Maximum sessions to store
        """
        self._sessions: OrderedDict[str, Session] = OrderedDict()
        self._user_sessions: Dict[str, Set[str]] = {}
        self._max_sessions = max_sessions
        self._lock = threading.RLock()

    def save(self, session: Session) -> bool:
        """Save session."""
        with self._lock:
            # Evict oldest if at capacity
            while len(self._sessions) >= self._max_sessions:
                oldest_id, _ = self._sessions.popitem(last=False)
                self._remove_user_mapping(oldest_id)

            # Save session
            self._sessions[session.id] = session
            self._sessions.move_to_end(session.id)

            # Update user mapping
            if session.user_id not in self._user_sessions:
                self._user_sessions[session.user_id] = set()
            self._user_sessions[session.user_id].add(session.id)

            return True

    def get(self, session_id: str) -> Optional[Session]:
        """Get session by ID."""
        with self._lock:
            session = self._sessions.get(session_id)
            if session:
                # Move to end (LRU)
                self._sessions.move_to_end(session_id)
            return session

    def delete(self, session_id: str) -> bool:
        """Delete session."""
        with self._lock:
            if session_id in self._sessions:
                session = self._sessions.pop(session_id)
                self._remove_user_mapping(session_id, session.user_id)
                return True
            return False

    def get_by_user(self, user_id: str) -> List[Session]:
        """Get all sessions for user."""
        with self._lock:
            session_ids = self._user_sessions.get(user_id, set())
            return [
                self._sessions[sid]
                for sid in session_ids
                if sid in self._sessions
            ]

    def delete_by_user(self, user_id: str) -> int:
        """Delete all sessions for user."""
        with self._lock:
            session_ids = self._user_sessions.pop(user_id, set())
            count = 0
            for sid in session_ids:
                if sid in self._sessions:
                    del self._sessions[sid]
                    count += 1
            return count

    def cleanup_expired(self) -> int:
        """Clean up expired sessions."""
        with self._lock:
            expired = [
                sid for sid, session in self._sessions.items()
                if session.is_expired
            ]
            for sid in expired:
                session = self._sessions.pop(sid)
                self._remove_user_mapping(sid, session.user_id)
            return len(expired)

    def _remove_user_mapping(self, session_id: str, user_id: Optional[str] = None) -> None:
        """Remove session from user mapping."""
        if user_id is None:
            # Find user ID
            for uid, sids in self._user_sessions.items():
                if session_id in sids:
                    user_id = uid
                    break

        if user_id and user_id in self._user_sessions:
            self._user_sessions[user_id].discard(session_id)
            if not self._user_sessions[user_id]:
                del self._user_sessions[user_id]

    @property
    def count(self) -> int:
        """Get total session count."""
        return len(self._sessions)


class RedisSessionStore(SessionStore):
    """Redis-backed session store for distributed deployments."""

    def __init__(
        self,
        redis_client: Any,
        prefix: str = "session:",
        ttl: int = 86400
    ):
        """Initialize Redis store.

        Args:
            redis_client: Redis client instance
            prefix: Key prefix
            ttl: Default TTL in seconds
        """
        self._redis = redis_client
        self._prefix = prefix
        self._ttl = ttl

    def _key(self, session_id: str) -> str:
        """Generate Redis key."""
        return f"{self._prefix}{session_id}"

    def _user_key(self, user_id: str) -> str:
        """Generate user sessions key."""
        return f"{self._prefix}user:{user_id}"

    def save(self, session: Session) -> bool:
        """Save session."""
        try:
            key = self._key(session.id)
            data = json.dumps(session.to_dict())

            # Calculate TTL
            ttl = self._ttl
            if session.expires_at:
                remaining = (session.expires_at - datetime.now()).total_seconds()
                ttl = max(int(remaining), 1)

            # Save session data
            self._redis.setex(key, ttl, data)

            # Add to user's session set
            user_key = self._user_key(session.user_id)
            self._redis.sadd(user_key, session.id)
            self._redis.expire(user_key, self._ttl)

            return True
        except Exception as e:
            logger.error(f"Failed to save session: {e}")
            return False

    def get(self, session_id: str) -> Optional[Session]:
        """Get session by ID."""
        try:
            key = self._key(session_id)
            data = self._redis.get(key)
            if data:
                return Session.from_dict(json.loads(data))
            return None
        except Exception as e:
            logger.error(f"Failed to get session: {e}")
            return None

    def delete(self, session_id: str) -> bool:
        """Delete session."""
        try:
            # Get session to find user ID
            session = self.get(session_id)
            if session:
                # Remove from user set
                user_key = self._user_key(session.user_id)
                self._redis.srem(user_key, session_id)

            # Delete session
            key = self._key(session_id)
            return self._redis.delete(key) > 0
        except Exception as e:
            logger.error(f"Failed to delete session: {e}")
            return False

    def get_by_user(self, user_id: str) -> List[Session]:
        """Get all sessions for user."""
        try:
            user_key = self._user_key(user_id)
            session_ids = self._redis.smembers(user_key)

            sessions = []
            for sid in session_ids:
                session = self.get(sid.decode() if isinstance(sid, bytes) else sid)
                if session:
                    sessions.append(session)

            return sessions
        except Exception as e:
            logger.error(f"Failed to get user sessions: {e}")
            return []

    def delete_by_user(self, user_id: str) -> int:
        """Delete all sessions for user."""
        try:
            user_key = self._user_key(user_id)
            session_ids = self._redis.smembers(user_key)

            count = 0
            for sid in session_ids:
                key = self._key(sid.decode() if isinstance(sid, bytes) else sid)
                if self._redis.delete(key):
                    count += 1

            self._redis.delete(user_key)
            return count
        except Exception as e:
            logger.error(f"Failed to delete user sessions: {e}")
            return 0

    def cleanup_expired(self) -> int:
        """Clean up expired sessions (handled by Redis TTL)."""
        # Redis handles expiration automatically
        return 0


class SessionManager:
    """Manages user sessions with security and lifecycle handling."""

    def __init__(
        self,
        store: Optional[SessionStore] = None,
        default_ttl: int = 3600,
        remember_me_ttl: int = 2592000,  # 30 days
        max_sessions_per_user: int = 10,
        idle_timeout: int = 1800,  # 30 minutes
        fingerprint_validation: bool = True,
        fingerprint_threshold: float = 0.7,
    ):
        """Initialize session manager.

        Args:
            store: Session store implementation
            default_ttl: Default session TTL in seconds
            remember_me_ttl: TTL for remembered sessions
            max_sessions_per_user: Maximum concurrent sessions per user
            idle_timeout: Idle timeout in seconds
            fingerprint_validation: Enable fingerprint validation
            fingerprint_threshold: Minimum fingerprint similarity
        """
        self.store = store or InMemorySessionStore()
        self.default_ttl = default_ttl
        self.remember_me_ttl = remember_me_ttl
        self.max_sessions_per_user = max_sessions_per_user
        self.idle_timeout = idle_timeout
        self.fingerprint_validation = fingerprint_validation
        self.fingerprint_threshold = fingerprint_threshold

        # Event handlers
        self._event_handlers: Dict[SessionEvent, List[Callable]] = {
            event: [] for event in SessionEvent
        }

        # Background cleanup
        self._cleanup_interval = 300  # 5 minutes
        self._cleanup_thread: Optional[threading.Thread] = None
        self._running = False
        self._lock = threading.RLock()

    def create(
        self,
        user_id: str,
        fingerprint: Optional[SessionFingerprint] = None,
        remember_me: bool = False,
        requires_mfa: bool = False,
        **kwargs
    ) -> Session:
        """Create a new session.

        Args:
            user_id: User ID
            fingerprint: Optional session fingerprint
            remember_me: Extended session duration
            requires_mfa: Whether MFA is required
            **kwargs: Additional session attributes

        Returns:
            Created session
        """
        # Enforce session limit
        self._enforce_session_limit(user_id)

        # Determine TTL
        ttl = self.remember_me_ttl if remember_me else self.default_ttl

        # Create session
        session = Session.create(
            user_id=user_id,
            ttl=ttl,
            fingerprint=fingerprint,
            is_remembered=remember_me,
            requires_mfa=requires_mfa,
            **kwargs
        )

        # Save session
        self.store.save(session)

        # Fire event
        self._fire_event(SessionEvent.CREATED, session)

        logger.info(f"Session created: {session.id} for user {user_id}")
        return session

    def get(self, session_id: str, touch: bool = True) -> Optional[Session]:
        """Get session by ID.

        Args:
            session_id: Session ID
            touch: Update access time

        Returns:
            Session or None
        """
        session = self.store.get(session_id)

        if not session:
            return None

        # Check if expired
        if session.is_expired:
            session.status = SessionStatus.EXPIRED
            self.store.save(session)
            self._fire_event(SessionEvent.EXPIRED, session)
            return None

        # Check if active
        if session.status != SessionStatus.ACTIVE:
            return None

        # Check idle timeout
        if session.idle_time.total_seconds() > self.idle_timeout:
            session.status = SessionStatus.EXPIRED
            self.store.save(session)
            self._fire_event(SessionEvent.EXPIRED, session)
            return None

        # Update access time
        if touch:
            session.touch()
            self.store.save(session)
            self._fire_event(SessionEvent.ACCESSED, session)

        return session

    def validate(
        self,
        session_id: str,
        fingerprint: Optional[SessionFingerprint] = None
    ) -> Tuple[bool, Optional[Session], str]:
        """Validate session.

        Args:
            session_id: Session ID
            fingerprint: Current fingerprint for validation

        Returns:
            (is_valid, session, reason)
        """
        session = self.get(session_id, touch=False)

        if not session:
            return False, None, "Session not found or expired"

        # Check MFA requirement
        if session.requires_mfa and not session.mfa_verified:
            return False, session, "MFA verification required"

        # Validate fingerprint
        if self.fingerprint_validation and fingerprint and session.fingerprint:
            similarity = session.fingerprint.similarity(fingerprint)
            if similarity < self.fingerprint_threshold:
                logger.warning(
                    f"Fingerprint mismatch for session {session_id}: "
                    f"similarity={similarity:.2f}"
                )
                return False, session, "Fingerprint mismatch"

        # Update access time
        session.touch()
        self.store.save(session)

        return True, session, "Valid"

    def refresh(self, session_id: str, extend_seconds: Optional[int] = None) -> Optional[Session]:
        """Refresh session expiration.

        Args:
            session_id: Session ID
            extend_seconds: Seconds to extend (uses default if None)

        Returns:
            Updated session or None
        """
        session = self.get(session_id, touch=True)
        if not session:
            return None

        # Extend expiration
        extend = extend_seconds or (self.remember_me_ttl if session.is_remembered else self.default_ttl)
        session.extend(extend)
        self.store.save(session)

        self._fire_event(SessionEvent.UPDATED, session)
        return session

    def revoke(self, session_id: str) -> bool:
        """Revoke session.

        Args:
            session_id: Session ID

        Returns:
            True if revoked
        """
        session = self.store.get(session_id)
        if not session:
            return False

        session.revoke()
        self.store.save(session)

        self._fire_event(SessionEvent.REVOKED, session)
        logger.info(f"Session revoked: {session_id}")
        return True

    def revoke_all(self, user_id: str, except_session: Optional[str] = None) -> int:
        """Revoke all sessions for user.

        Args:
            user_id: User ID
            except_session: Session ID to exclude

        Returns:
            Number of sessions revoked
        """
        sessions = self.store.get_by_user(user_id)
        count = 0

        for session in sessions:
            if session.id != except_session:
                session.revoke()
                self.store.save(session)
                self._fire_event(SessionEvent.REVOKED, session)
                count += 1

        logger.info(f"Revoked {count} sessions for user {user_id}")
        return count

    def lock(self, session_id: str) -> bool:
        """Lock session.

        Args:
            session_id: Session ID

        Returns:
            True if locked
        """
        session = self.store.get(session_id)
        if not session:
            return False

        session.lock()
        self.store.save(session)

        self._fire_event(SessionEvent.LOCKED, session)
        return True

    def unlock(self, session_id: str) -> bool:
        """Unlock session.

        Args:
            session_id: Session ID

        Returns:
            True if unlocked
        """
        session = self.store.get(session_id)
        if not session or session.status != SessionStatus.LOCKED:
            return False

        session.unlock()
        self.store.save(session)

        self._fire_event(SessionEvent.UNLOCKED, session)
        return True

    def verify_mfa(self, session_id: str) -> bool:
        """Mark session as MFA verified.

        Args:
            session_id: Session ID

        Returns:
            True if updated
        """
        session = self.store.get(session_id)
        if not session:
            return False

        session.mfa_verified = True
        self.store.save(session)

        self._fire_event(SessionEvent.UPDATED, session)
        return True

    def get_user_sessions(self, user_id: str) -> List[Session]:
        """Get all sessions for user.

        Args:
            user_id: User ID

        Returns:
            List of sessions
        """
        return [
            s for s in self.store.get_by_user(user_id)
            if s.status == SessionStatus.ACTIVE and not s.is_expired
        ]

    def set_session_data(self, session_id: str, key: str, value: Any) -> bool:
        """Set session data.

        Args:
            session_id: Session ID
            key: Data key
            value: Data value

        Returns:
            True if set
        """
        session = self.store.get(session_id)
        if not session:
            return False

        session.set_data(key, value)
        self.store.save(session)
        return True

    def get_session_data(self, session_id: str, key: str, default: Any = None) -> Any:
        """Get session data.

        Args:
            session_id: Session ID
            key: Data key
            default: Default value

        Returns:
            Data value or default
        """
        session = self.store.get(session_id)
        if not session:
            return default
        return session.get_data(key, default)

    def on(self, event: SessionEvent, handler: Callable[[Session], None]) -> None:
        """Register event handler.

        Args:
            event: Event type
            handler: Handler function
        """
        self._event_handlers[event].append(handler)

    def _fire_event(self, event: SessionEvent, session: Session) -> None:
        """Fire event to handlers."""
        for handler in self._event_handlers[event]:
            try:
                handler(session)
            except Exception as e:
                logger.error(f"Event handler error: {e}")

    def _enforce_session_limit(self, user_id: str) -> None:
        """Enforce maximum sessions per user."""
        sessions = self.get_user_sessions(user_id)

        # Sort by access time (oldest first)
        sessions.sort(key=lambda s: s.accessed_at)

        # Revoke oldest sessions if over limit
        while len(sessions) >= self.max_sessions_per_user:
            oldest = sessions.pop(0)
            self.revoke(oldest.id)
            logger.info(f"Revoked oldest session {oldest.id} for user {user_id}")

    def start_cleanup(self) -> None:
        """Start background cleanup thread."""
        if self._running:
            return

        self._running = True
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self._cleanup_thread.start()
        logger.info("Session cleanup thread started")

    def stop_cleanup(self) -> None:
        """Stop background cleanup thread."""
        self._running = False
        if self._cleanup_thread:
            self._cleanup_thread.join(timeout=5)
            self._cleanup_thread = None
        logger.info("Session cleanup thread stopped")

    def _cleanup_loop(self) -> None:
        """Background cleanup loop."""
        while self._running:
            try:
                count = self.store.cleanup_expired()
                if count > 0:
                    logger.info(f"Cleaned up {count} expired sessions")
            except Exception as e:
                logger.error(f"Session cleanup error: {e}")

            time.sleep(self._cleanup_interval)


class ConcurrentSessionPolicy:
    """Policy for handling concurrent sessions."""

    def __init__(
        self,
        max_concurrent: int = 5,
        action: str = "revoke_oldest",  # revoke_oldest, revoke_all, deny
        notify_user: bool = True,
    ):
        """Initialize policy.

        Args:
            max_concurrent: Maximum concurrent sessions
            action: Action when limit exceeded
            notify_user: Notify user of session changes
        """
        self.max_concurrent = max_concurrent
        self.action = action
        self.notify_user = notify_user

    def apply(
        self,
        manager: SessionManager,
        user_id: str,
        new_session: Session
    ) -> Tuple[bool, List[str]]:
        """Apply policy for new session.

        Args:
            manager: Session manager
            user_id: User ID
            new_session: New session being created

        Returns:
            (is_allowed, revoked_session_ids)
        """
        sessions = manager.get_user_sessions(user_id)
        revoked = []

        if len(sessions) < self.max_concurrent:
            return True, revoked

        if self.action == "deny":
            return False, revoked

        elif self.action == "revoke_all":
            for session in sessions:
                if session.id != new_session.id:
                    manager.revoke(session.id)
                    revoked.append(session.id)

        elif self.action == "revoke_oldest":
            # Sort by access time
            sessions.sort(key=lambda s: s.accessed_at)

            # Revoke oldest until under limit
            while len(sessions) >= self.max_concurrent:
                oldest = sessions.pop(0)
                manager.revoke(oldest.id)
                revoked.append(oldest.id)

        return True, revoked


__all__ = [
    "Session",
    "SessionStatus",
    "SessionEvent",
    "SessionFingerprint",
    "SessionStore",
    "InMemorySessionStore",
    "RedisSessionStore",
    "SessionManager",
    "ConcurrentSessionPolicy",
]
