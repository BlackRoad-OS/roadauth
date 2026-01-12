"""RoadAuth Refresh Tokens - Refresh Token Management.

Provides secure refresh token handling:
- Token generation and validation
- Token rotation and revocation
- Family-based token tracking
- Reuse detection and prevention

Copyright (c) 2024-2026 BlackRoad OS, Inc. All rights reserved.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from collections import OrderedDict

# Configure logging
logger = logging.getLogger(__name__)


class RefreshTokenStatus(Enum):
    """Refresh token status."""

    ACTIVE = "active"
    USED = "used"
    REVOKED = "revoked"
    EXPIRED = "expired"


class RefreshTokenEvent(Enum):
    """Refresh token events."""

    CREATED = auto()
    USED = auto()
    ROTATED = auto()
    REVOKED = auto()
    EXPIRED = auto()
    REUSE_DETECTED = auto()


@dataclass
class RefreshToken:
    """Refresh token entity."""

    id: str
    user_id: str
    token_hash: str  # Store hash, not plaintext
    status: RefreshTokenStatus = RefreshTokenStatus.ACTIVE

    # Timestamps
    created_at: datetime = field(default_factory=datetime.now)
    expires_at: Optional[datetime] = None
    used_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None

    # Token family for rotation tracking
    family_id: str = ""

    # Device/session binding
    session_id: Optional[str] = None
    device_id: Optional[str] = None
    ip_address: str = ""
    user_agent: str = ""

    # Security
    rotation_count: int = 0
    max_rotations: int = 100

    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        user_id: str,
        ttl: int = 2592000,  # 30 days
        session_id: Optional[str] = None,
        device_id: Optional[str] = None,
        **kwargs
    ) -> Tuple[RefreshToken, str]:
        """Create a new refresh token.

        Args:
            user_id: User ID
            ttl: Time to live in seconds
            session_id: Associated session ID
            device_id: Associated device ID
            **kwargs: Additional attributes

        Returns:
            (RefreshToken, plaintext_token)
        """
        # Generate secure token
        plaintext_token = secrets.token_urlsafe(64)
        token_hash = cls._hash_token(plaintext_token)

        token = cls(
            id=secrets.token_urlsafe(16),
            user_id=user_id,
            token_hash=token_hash,
            expires_at=datetime.now() + timedelta(seconds=ttl),
            family_id=secrets.token_urlsafe(8),
            session_id=session_id,
            device_id=device_id,
            **kwargs
        )

        return token, plaintext_token

    @staticmethod
    def _hash_token(token: str) -> str:
        """Hash token for storage."""
        return hashlib.sha256(token.encode()).hexdigest()

    def verify(self, plaintext_token: str) -> bool:
        """Verify plaintext token matches hash.

        Args:
            plaintext_token: Plaintext token to verify

        Returns:
            True if matches
        """
        return self.token_hash == self._hash_token(plaintext_token)

    @property
    def is_expired(self) -> bool:
        """Check if token is expired."""
        if self.expires_at is None:
            return False
        return datetime.now() > self.expires_at

    @property
    def is_active(self) -> bool:
        """Check if token is active."""
        return (
            self.status == RefreshTokenStatus.ACTIVE
            and not self.is_expired
        )

    @property
    def can_rotate(self) -> bool:
        """Check if token can be rotated."""
        return (
            self.is_active
            and self.rotation_count < self.max_rotations
        )

    @property
    def remaining_time(self) -> int:
        """Get remaining validity time in seconds."""
        if self.expires_at is None:
            return -1
        delta = self.expires_at - datetime.now()
        return max(0, int(delta.total_seconds()))

    def mark_used(self) -> None:
        """Mark token as used."""
        self.status = RefreshTokenStatus.USED
        self.used_at = datetime.now()

    def revoke(self) -> None:
        """Revoke token."""
        self.status = RefreshTokenStatus.REVOKED
        self.revoked_at = datetime.now()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "used_at": self.used_at.isoformat() if self.used_at else None,
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
            "family_id": self.family_id,
            "session_id": self.session_id,
            "device_id": self.device_id,
            "rotation_count": self.rotation_count,
            "metadata": self.metadata,
        }


class RefreshTokenStore:
    """In-memory refresh token store."""

    def __init__(self, max_tokens: int = 100000):
        """Initialize store.

        Args:
            max_tokens: Maximum tokens to store
        """
        self._tokens: OrderedDict[str, RefreshToken] = OrderedDict()
        self._by_user: Dict[str, Set[str]] = {}
        self._by_family: Dict[str, Set[str]] = {}
        self._max_tokens = max_tokens
        self._lock = threading.RLock()

    def save(self, token: RefreshToken) -> bool:
        """Save refresh token."""
        with self._lock:
            # Evict oldest if at capacity
            while len(self._tokens) >= self._max_tokens:
                oldest_id, _ = self._tokens.popitem(last=False)
                self._remove_mappings(oldest_id)

            # Save token
            self._tokens[token.id] = token
            self._tokens.move_to_end(token.id)

            # Update user mapping
            if token.user_id not in self._by_user:
                self._by_user[token.user_id] = set()
            self._by_user[token.user_id].add(token.id)

            # Update family mapping
            if token.family_id:
                if token.family_id not in self._by_family:
                    self._by_family[token.family_id] = set()
                self._by_family[token.family_id].add(token.id)

            return True

    def get(self, token_id: str) -> Optional[RefreshToken]:
        """Get token by ID."""
        return self._tokens.get(token_id)

    def get_by_hash(self, token_hash: str) -> Optional[RefreshToken]:
        """Get token by hash."""
        for token in self._tokens.values():
            if token.token_hash == token_hash:
                return token
        return None

    def delete(self, token_id: str) -> bool:
        """Delete token."""
        with self._lock:
            if token_id in self._tokens:
                self._remove_mappings(token_id)
                del self._tokens[token_id]
                return True
            return False

    def get_by_user(self, user_id: str) -> List[RefreshToken]:
        """Get all tokens for user."""
        token_ids = self._by_user.get(user_id, set())
        return [self._tokens[tid] for tid in token_ids if tid in self._tokens]

    def get_by_family(self, family_id: str) -> List[RefreshToken]:
        """Get all tokens in family."""
        token_ids = self._by_family.get(family_id, set())
        return [self._tokens[tid] for tid in token_ids if tid in self._tokens]

    def delete_by_user(self, user_id: str) -> int:
        """Delete all tokens for user."""
        with self._lock:
            token_ids = list(self._by_user.get(user_id, set()))
            count = 0
            for tid in token_ids:
                if self.delete(tid):
                    count += 1
            return count

    def delete_by_family(self, family_id: str) -> int:
        """Delete all tokens in family."""
        with self._lock:
            token_ids = list(self._by_family.get(family_id, set()))
            count = 0
            for tid in token_ids:
                if self.delete(tid):
                    count += 1
            return count

    def cleanup_expired(self) -> int:
        """Remove expired tokens."""
        with self._lock:
            expired = [
                tid for tid, token in self._tokens.items()
                if token.is_expired
            ]
            for tid in expired:
                self.delete(tid)
            return len(expired)

    def _remove_mappings(self, token_id: str) -> None:
        """Remove token from mappings."""
        token = self._tokens.get(token_id)
        if not token:
            return

        if token.user_id in self._by_user:
            self._by_user[token.user_id].discard(token_id)
            if not self._by_user[token.user_id]:
                del self._by_user[token.user_id]

        if token.family_id and token.family_id in self._by_family:
            self._by_family[token.family_id].discard(token_id)
            if not self._by_family[token.family_id]:
                del self._by_family[token.family_id]

    @property
    def count(self) -> int:
        """Get total token count."""
        return len(self._tokens)


class RefreshTokenManager:
    """Manages refresh tokens with rotation and security features."""

    def __init__(
        self,
        store: Optional[RefreshTokenStore] = None,
        default_ttl: int = 2592000,  # 30 days
        rotation_ttl: int = 604800,  # 7 days after rotation
        max_tokens_per_user: int = 10,
        absolute_timeout: int = 7776000,  # 90 days
        reuse_detection: bool = True,
        automatic_revocation: bool = True,
    ):
        """Initialize refresh token manager.

        Args:
            store: Token store implementation
            default_ttl: Default token TTL in seconds
            rotation_ttl: TTL after rotation
            max_tokens_per_user: Maximum tokens per user
            absolute_timeout: Maximum token lifetime
            reuse_detection: Enable token reuse detection
            automatic_revocation: Revoke family on reuse
        """
        self.store = store or RefreshTokenStore()
        self.default_ttl = default_ttl
        self.rotation_ttl = rotation_ttl
        self.max_tokens_per_user = max_tokens_per_user
        self.absolute_timeout = absolute_timeout
        self.reuse_detection = reuse_detection
        self.automatic_revocation = automatic_revocation

        # Event handlers
        self._event_handlers: Dict[RefreshTokenEvent, List[Callable]] = {
            event: [] for event in RefreshTokenEvent
        }

        # Background cleanup
        self._cleanup_interval = 3600  # 1 hour
        self._cleanup_thread: Optional[threading.Thread] = None
        self._running = False
        self._lock = threading.RLock()

    def create(
        self,
        user_id: str,
        session_id: Optional[str] = None,
        device_id: Optional[str] = None,
        ip_address: str = "",
        user_agent: str = "",
        **metadata
    ) -> Tuple[RefreshToken, str]:
        """Create a new refresh token.

        Args:
            user_id: User ID
            session_id: Associated session ID
            device_id: Associated device ID
            ip_address: Client IP address
            user_agent: Client user agent
            **metadata: Additional metadata

        Returns:
            (RefreshToken, plaintext_token)
        """
        # Enforce token limit
        self._enforce_token_limit(user_id)

        # Create token
        token, plaintext = RefreshToken.create(
            user_id=user_id,
            ttl=self.default_ttl,
            session_id=session_id,
            device_id=device_id,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata=metadata,
        )

        # Save token
        self.store.save(token)

        # Fire event
        self._fire_event(RefreshTokenEvent.CREATED, token)

        logger.info(f"Refresh token created: {token.id} for user {user_id}")
        return token, plaintext

    def validate(self, plaintext_token: str) -> Optional[RefreshToken]:
        """Validate a refresh token.

        Args:
            plaintext_token: Plaintext token to validate

        Returns:
            RefreshToken if valid, None otherwise
        """
        token_hash = RefreshToken._hash_token(plaintext_token)
        token = self.store.get_by_hash(token_hash)

        if not token:
            return None

        # Check if token is active
        if not token.is_active:
            # Check for reuse
            if self.reuse_detection and token.status == RefreshTokenStatus.USED:
                self._handle_reuse(token)
            return None

        return token

    def rotate(self, plaintext_token: str) -> Optional[Tuple[RefreshToken, str]]:
        """Rotate a refresh token.

        Invalidates the old token and creates a new one in the same family.

        Args:
            plaintext_token: Current token

        Returns:
            (new_token, new_plaintext) or None if invalid
        """
        # Validate current token
        current_token = self.validate(plaintext_token)
        if not current_token:
            return None

        if not current_token.can_rotate:
            logger.warning(f"Token cannot be rotated: {current_token.id}")
            return None

        # Mark current token as used
        current_token.mark_used()
        self.store.save(current_token)

        # Create new token in same family
        new_token, new_plaintext = RefreshToken.create(
            user_id=current_token.user_id,
            ttl=self.rotation_ttl,
            session_id=current_token.session_id,
            device_id=current_token.device_id,
            ip_address=current_token.ip_address,
            user_agent=current_token.user_agent,
            metadata=current_token.metadata,
        )

        # Preserve family
        new_token.family_id = current_token.family_id
        new_token.rotation_count = current_token.rotation_count + 1

        # Check absolute timeout
        family_start = self._get_family_start(current_token.family_id)
        if family_start:
            age = (datetime.now() - family_start).total_seconds()
            if age > self.absolute_timeout:
                logger.warning(f"Token family exceeded absolute timeout")
                self._revoke_family(current_token.family_id)
                return None

        # Save new token
        self.store.save(new_token)

        # Fire events
        self._fire_event(RefreshTokenEvent.USED, current_token)
        self._fire_event(RefreshTokenEvent.ROTATED, new_token)

        logger.info(f"Token rotated: {current_token.id} -> {new_token.id}")
        return new_token, new_plaintext

    def revoke(self, token_id: str) -> bool:
        """Revoke a specific token.

        Args:
            token_id: Token ID

        Returns:
            True if revoked
        """
        token = self.store.get(token_id)
        if not token:
            return False

        token.revoke()
        self.store.save(token)

        self._fire_event(RefreshTokenEvent.REVOKED, token)
        logger.info(f"Refresh token revoked: {token_id}")
        return True

    def revoke_all(self, user_id: str, except_token: Optional[str] = None) -> int:
        """Revoke all tokens for user.

        Args:
            user_id: User ID
            except_token: Token ID to exclude

        Returns:
            Number of tokens revoked
        """
        tokens = self.store.get_by_user(user_id)
        count = 0

        for token in tokens:
            if token.id != except_token and token.is_active:
                token.revoke()
                self.store.save(token)
                self._fire_event(RefreshTokenEvent.REVOKED, token)
                count += 1

        logger.info(f"Revoked {count} refresh tokens for user {user_id}")
        return count

    def revoke_by_device(self, user_id: str, device_id: str) -> int:
        """Revoke all tokens for a device.

        Args:
            user_id: User ID
            device_id: Device ID

        Returns:
            Number of tokens revoked
        """
        tokens = self.store.get_by_user(user_id)
        count = 0

        for token in tokens:
            if token.device_id == device_id and token.is_active:
                token.revoke()
                self.store.save(token)
                self._fire_event(RefreshTokenEvent.REVOKED, token)
                count += 1

        return count

    def revoke_by_session(self, session_id: str) -> int:
        """Revoke all tokens for a session.

        Args:
            session_id: Session ID

        Returns:
            Number of tokens revoked
        """
        count = 0
        for token in list(self.store._tokens.values()):
            if token.session_id == session_id and token.is_active:
                token.revoke()
                self.store.save(token)
                self._fire_event(RefreshTokenEvent.REVOKED, token)
                count += 1

        return count

    def get_user_tokens(self, user_id: str) -> List[RefreshToken]:
        """Get all tokens for user.

        Args:
            user_id: User ID

        Returns:
            List of tokens
        """
        return [t for t in self.store.get_by_user(user_id) if t.is_active]

    def get_token_info(self, token_id: str) -> Optional[Dict[str, Any]]:
        """Get token information.

        Args:
            token_id: Token ID

        Returns:
            Token info or None
        """
        token = self.store.get(token_id)
        if not token:
            return None

        return {
            "id": token.id,
            "user_id": token.user_id,
            "status": token.status.value,
            "created_at": token.created_at.isoformat(),
            "expires_at": token.expires_at.isoformat() if token.expires_at else None,
            "remaining_seconds": token.remaining_time,
            "rotation_count": token.rotation_count,
            "device_id": token.device_id,
            "session_id": token.session_id,
            "family_id": token.family_id,
        }

    def on(self, event: RefreshTokenEvent, handler: Callable[[RefreshToken], None]) -> None:
        """Register event handler.

        Args:
            event: Event type
            handler: Handler function
        """
        self._event_handlers[event].append(handler)

    def _fire_event(self, event: RefreshTokenEvent, token: RefreshToken) -> None:
        """Fire event to handlers."""
        for handler in self._event_handlers[event]:
            try:
                handler(token)
            except Exception as e:
                logger.error(f"Event handler error: {e}")

    def _handle_reuse(self, token: RefreshToken) -> None:
        """Handle token reuse detection."""
        logger.warning(f"Token reuse detected: {token.id} in family {token.family_id}")

        self._fire_event(RefreshTokenEvent.REUSE_DETECTED, token)

        if self.automatic_revocation:
            self._revoke_family(token.family_id)

    def _revoke_family(self, family_id: str) -> int:
        """Revoke all tokens in family.

        Args:
            family_id: Family ID

        Returns:
            Number of tokens revoked
        """
        tokens = self.store.get_by_family(family_id)
        count = 0

        for token in tokens:
            if token.status != RefreshTokenStatus.REVOKED:
                token.revoke()
                self.store.save(token)
                self._fire_event(RefreshTokenEvent.REVOKED, token)
                count += 1

        logger.warning(f"Revoked {count} tokens in family {family_id}")
        return count

    def _get_family_start(self, family_id: str) -> Optional[datetime]:
        """Get family start time (oldest token creation)."""
        tokens = self.store.get_by_family(family_id)
        if not tokens:
            return None

        return min(t.created_at for t in tokens)

    def _enforce_token_limit(self, user_id: str) -> None:
        """Enforce maximum tokens per user."""
        tokens = self.get_user_tokens(user_id)

        # Sort by creation time (oldest first)
        tokens.sort(key=lambda t: t.created_at)

        # Revoke oldest tokens if over limit
        while len(tokens) >= self.max_tokens_per_user:
            oldest = tokens.pop(0)
            self.revoke(oldest.id)
            logger.info(f"Revoked oldest token {oldest.id} for user {user_id}")

    def start_cleanup(self) -> None:
        """Start background cleanup thread."""
        if self._running:
            return

        self._running = True
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self._cleanup_thread.start()
        logger.info("Refresh token cleanup thread started")

    def stop_cleanup(self) -> None:
        """Stop background cleanup thread."""
        self._running = False
        if self._cleanup_thread:
            self._cleanup_thread.join(timeout=5)
            self._cleanup_thread = None
        logger.info("Refresh token cleanup thread stopped")

    def _cleanup_loop(self) -> None:
        """Background cleanup loop."""
        while self._running:
            try:
                count = self.store.cleanup_expired()
                if count > 0:
                    logger.info(f"Cleaned up {count} expired refresh tokens")
            except Exception as e:
                logger.error(f"Refresh token cleanup error: {e}")

            time.sleep(self._cleanup_interval)


class RefreshTokenRotationPolicy:
    """Policy for refresh token rotation."""

    def __init__(
        self,
        rotation_interval: int = 86400,  # 1 day
        grace_period: int = 60,  # 60 seconds
        force_rotation_on_ip_change: bool = True,
        force_rotation_on_device_change: bool = True,
    ):
        """Initialize rotation policy.

        Args:
            rotation_interval: Suggested rotation interval in seconds
            grace_period: Grace period after rotation
            force_rotation_on_ip_change: Force rotation on IP change
            force_rotation_on_device_change: Force rotation on device change
        """
        self.rotation_interval = rotation_interval
        self.grace_period = grace_period
        self.force_rotation_on_ip_change = force_rotation_on_ip_change
        self.force_rotation_on_device_change = force_rotation_on_device_change

    def should_rotate(
        self,
        token: RefreshToken,
        current_ip: Optional[str] = None,
        current_device: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """Check if token should be rotated.

        Args:
            token: Current token
            current_ip: Current IP address
            current_device: Current device ID

        Returns:
            (should_rotate, reason)
        """
        # Check age
        age = (datetime.now() - token.created_at).total_seconds()
        if age > self.rotation_interval:
            return True, "Token age exceeded rotation interval"

        # Check IP change
        if self.force_rotation_on_ip_change and current_ip:
            if token.ip_address and token.ip_address != current_ip:
                return True, "IP address changed"

        # Check device change
        if self.force_rotation_on_device_change and current_device:
            if token.device_id and token.device_id != current_device:
                return True, "Device changed"

        return False, ""


__all__ = [
    "RefreshToken",
    "RefreshTokenStatus",
    "RefreshTokenEvent",
    "RefreshTokenStore",
    "RefreshTokenManager",
    "RefreshTokenRotationPolicy",
]
