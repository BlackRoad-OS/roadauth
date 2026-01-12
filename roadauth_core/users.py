"""RoadAuth Users - User management and storage.

Provides comprehensive user management including:
- User CRUD operations
- Profile management
- Status management (active, disabled, locked)
- User search and filtering
- Bulk operations

Copyright (c) 2024-2026 BlackRoad OS, Inc. All rights reserved.
"""

from __future__ import annotations

import logging
import secrets
import threading
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Any, Callable, Dict, Iterator, List, Optional, Set, Tuple

# Configure logging
logger = logging.getLogger(__name__)


class UserStatus(Enum):
    """User account status."""

    ACTIVE = "active"
    DISABLED = "disabled"
    LOCKED = "locked"
    PENDING_VERIFICATION = "pending_verification"
    PENDING_APPROVAL = "pending_approval"
    SUSPENDED = "suspended"
    DELETED = "deleted"


class UserEvent(Enum):
    """User lifecycle events."""

    CREATED = auto()
    UPDATED = auto()
    DELETED = auto()
    ACTIVATED = auto()
    DISABLED = auto()
    LOCKED = auto()
    UNLOCKED = auto()
    PASSWORD_CHANGED = auto()
    EMAIL_CHANGED = auto()
    MFA_ENABLED = auto()
    MFA_DISABLED = auto()
    LOGIN = auto()
    LOGOUT = auto()
    FAILED_LOGIN = auto()


@dataclass
class User:
    """User entity.

    Represents a user in the authentication system with all
    associated metadata and security settings.
    """

    id: str
    email: str
    password_hash: str
    status: UserStatus = UserStatus.ACTIVE
    roles: List[str] = field(default_factory=lambda: ["user"])
    permissions: Set[str] = field(default_factory=set)

    # Profile
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    display_name: Optional[str] = None
    avatar_url: Optional[str] = None
    phone: Optional[str] = None
    timezone: str = "UTC"
    locale: str = "en-US"

    # Security
    mfa_enabled: bool = False
    mfa_secret: Optional[str] = None
    mfa_backup_codes: List[str] = field(default_factory=list)
    webauthn_credentials: List[Dict[str, Any]] = field(default_factory=list)

    # Verification
    email_verified: bool = False
    email_verification_token: Optional[str] = None
    phone_verified: bool = False

    # Timestamps
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    last_login: Optional[datetime] = None
    password_changed_at: Optional[datetime] = None

    # Security tracking
    failed_login_attempts: int = 0
    last_failed_login: Optional[datetime] = None
    locked_until: Optional[datetime] = None
    last_ip_address: Optional[str] = None

    # External identities
    external_ids: Dict[str, str] = field(default_factory=dict)  # provider -> external_id

    # Custom metadata
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def full_name(self) -> str:
        """Get user's full name."""
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        return self.display_name or self.email.split("@")[0]

    @property
    def is_active(self) -> bool:
        """Check if user is active."""
        return self.status == UserStatus.ACTIVE

    @property
    def is_locked(self) -> bool:
        """Check if user is locked."""
        if self.locked_until:
            return datetime.now() < self.locked_until
        return self.status == UserStatus.LOCKED

    def has_role(self, role: str) -> bool:
        """Check if user has a specific role."""
        return role in self.roles

    def has_permission(self, permission: str) -> bool:
        """Check if user has a specific permission."""
        return permission in self.permissions or "*" in self.permissions

    def to_dict(self, include_sensitive: bool = False) -> Dict[str, Any]:
        """Convert to dictionary.

        Args:
            include_sensitive: Include sensitive fields

        Returns:
            User data as dictionary
        """
        data = {
            "id": self.id,
            "email": self.email,
            "status": self.status.value,
            "roles": self.roles,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "display_name": self.display_name,
            "avatar_url": self.avatar_url,
            "phone": self.phone,
            "timezone": self.timezone,
            "locale": self.locale,
            "mfa_enabled": self.mfa_enabled,
            "email_verified": self.email_verified,
            "phone_verified": self.phone_verified,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "last_login": self.last_login.isoformat() if self.last_login else None,
            "metadata": self.metadata,
        }

        if include_sensitive:
            data.update({
                "password_hash": self.password_hash,
                "mfa_secret": self.mfa_secret,
                "mfa_backup_codes": self.mfa_backup_codes,
                "failed_login_attempts": self.failed_login_attempts,
                "locked_until": self.locked_until.isoformat() if self.locked_until else None,
            })

        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> User:
        """Create from dictionary.

        Args:
            data: User data dictionary

        Returns:
            User instance
        """
        # Handle datetime fields
        for field_name in ["created_at", "updated_at", "last_login", "password_changed_at", "locked_until"]:
            if field_name in data and isinstance(data[field_name], str):
                data[field_name] = datetime.fromisoformat(data[field_name])

        # Handle status enum
        if "status" in data and isinstance(data["status"], str):
            data["status"] = UserStatus(data["status"])

        return cls(**data)


@dataclass
class UserFilter:
    """Filter criteria for user queries."""

    email: Optional[str] = None
    email_contains: Optional[str] = None
    status: Optional[UserStatus] = None
    statuses: Optional[List[UserStatus]] = None
    roles: Optional[List[str]] = None
    has_role: Optional[str] = None
    mfa_enabled: Optional[bool] = None
    email_verified: Optional[bool] = None
    created_after: Optional[datetime] = None
    created_before: Optional[datetime] = None
    last_login_after: Optional[datetime] = None
    last_login_before: Optional[datetime] = None
    metadata_key: Optional[str] = None
    metadata_value: Optional[Any] = None


@dataclass
class UserPage:
    """Paginated user results."""

    users: List[User]
    total: int
    page: int
    page_size: int
    has_next: bool
    has_prev: bool


class UserStore:
    """Abstract base class for user storage."""

    def get(self, user_id: str) -> Optional[User]:
        """Get user by ID."""
        raise NotImplementedError

    def get_by_email(self, email: str) -> Optional[User]:
        """Get user by email."""
        raise NotImplementedError

    def save(self, user: User) -> None:
        """Save user."""
        raise NotImplementedError

    def delete(self, user_id: str) -> bool:
        """Delete user."""
        raise NotImplementedError

    def query(self, filter: UserFilter, page: int = 1, page_size: int = 50) -> UserPage:
        """Query users with filter."""
        raise NotImplementedError


class InMemoryUserStore(UserStore):
    """In-memory user storage implementation."""

    def __init__(self):
        """Initialize in-memory store."""
        self._users: Dict[str, User] = {}
        self._email_index: Dict[str, str] = {}  # email -> user_id
        self._lock = threading.RLock()

    def get(self, user_id: str) -> Optional[User]:
        """Get user by ID."""
        with self._lock:
            return self._users.get(user_id)

    def get_by_email(self, email: str) -> Optional[User]:
        """Get user by email."""
        with self._lock:
            user_id = self._email_index.get(email.lower())
            if user_id:
                return self._users.get(user_id)
            return None

    def save(self, user: User) -> None:
        """Save user."""
        with self._lock:
            user.updated_at = datetime.now()
            self._users[user.id] = user
            self._email_index[user.email.lower()] = user.id

    def delete(self, user_id: str) -> bool:
        """Delete user."""
        with self._lock:
            user = self._users.get(user_id)
            if user:
                del self._users[user_id]
                if user.email.lower() in self._email_index:
                    del self._email_index[user.email.lower()]
                return True
            return False

    def query(self, filter: UserFilter, page: int = 1, page_size: int = 50) -> UserPage:
        """Query users with filter."""
        with self._lock:
            # Apply filters
            matching = list(self._users.values())

            if filter.email:
                matching = [u for u in matching if u.email.lower() == filter.email.lower()]

            if filter.email_contains:
                matching = [u for u in matching if filter.email_contains.lower() in u.email.lower()]

            if filter.status:
                matching = [u for u in matching if u.status == filter.status]

            if filter.statuses:
                matching = [u for u in matching if u.status in filter.statuses]

            if filter.has_role:
                matching = [u for u in matching if filter.has_role in u.roles]

            if filter.roles:
                matching = [u for u in matching if any(r in u.roles for r in filter.roles)]

            if filter.mfa_enabled is not None:
                matching = [u for u in matching if u.mfa_enabled == filter.mfa_enabled]

            if filter.email_verified is not None:
                matching = [u for u in matching if u.email_verified == filter.email_verified]

            if filter.created_after:
                matching = [u for u in matching if u.created_at >= filter.created_after]

            if filter.created_before:
                matching = [u for u in matching if u.created_at <= filter.created_before]

            # Pagination
            total = len(matching)
            start = (page - 1) * page_size
            end = start + page_size
            page_users = matching[start:end]

            return UserPage(
                users=page_users,
                total=total,
                page=page,
                page_size=page_size,
                has_next=end < total,
                has_prev=page > 1,
            )

    def count(self) -> int:
        """Get total user count."""
        with self._lock:
            return len(self._users)


class UserManager:
    """Manages user lifecycle operations.

    Provides high-level user management including:
    - User creation with validation
    - Profile updates
    - Status management
    - Event publishing
    """

    def __init__(self, store: Optional[UserStore] = None):
        """Initialize user manager.

        Args:
            store: User storage backend
        """
        self.store = store or InMemoryUserStore()
        self._event_handlers: Dict[UserEvent, List[Callable]] = {}
        self._lock = threading.RLock()

    def create(
        self,
        email: str,
        password_hash: str,
        roles: Optional[List[str]] = None,
        **kwargs,
    ) -> User:
        """Create a new user.

        Args:
            email: User email
            password_hash: Hashed password
            roles: Initial roles
            **kwargs: Additional user fields

        Returns:
            Created user

        Raises:
            ValueError: If email already exists
        """
        with self._lock:
            # Check for existing email
            if self.store.get_by_email(email):
                raise ValueError(f"Email already exists: {email}")

            # Generate ID
            user_id = secrets.token_urlsafe(16)

            # Create user
            user = User(
                id=user_id,
                email=email.lower(),
                password_hash=password_hash,
                roles=roles or ["user"],
                **kwargs,
            )

            self.store.save(user)
            self._emit_event(UserEvent.CREATED, user)

            logger.info(f"User created: {email}")
            return user

    def get(self, user_id: str) -> Optional[User]:
        """Get user by ID."""
        return self.store.get(user_id)

    def get_by_email(self, email: str) -> Optional[User]:
        """Get user by email."""
        return self.store.get_by_email(email)

    def update(self, user_id: str, **updates) -> Optional[User]:
        """Update user fields.

        Args:
            user_id: User ID
            **updates: Fields to update

        Returns:
            Updated user or None
        """
        with self._lock:
            user = self.store.get(user_id)
            if not user:
                return None

            # Apply updates
            for key, value in updates.items():
                if hasattr(user, key) and key not in ("id", "created_at"):
                    setattr(user, key, value)

            self.store.save(user)
            self._emit_event(UserEvent.UPDATED, user)

            return user

    def delete(self, user_id: str) -> bool:
        """Delete user.

        Args:
            user_id: User ID

        Returns:
            True if deleted
        """
        with self._lock:
            user = self.store.get(user_id)
            if user:
                result = self.store.delete(user_id)
                if result:
                    self._emit_event(UserEvent.DELETED, user)
                return result
            return False

    def disable(self, user_id: str, reason: Optional[str] = None) -> bool:
        """Disable user account.

        Args:
            user_id: User ID
            reason: Optional reason for disabling

        Returns:
            True if disabled
        """
        user = self.update(
            user_id,
            status=UserStatus.DISABLED,
            metadata={**(self.get(user_id).metadata or {}), "disabled_reason": reason},
        )
        if user:
            self._emit_event(UserEvent.DISABLED, user)
            return True
        return False

    def enable(self, user_id: str) -> bool:
        """Enable user account.

        Args:
            user_id: User ID

        Returns:
            True if enabled
        """
        user = self.update(user_id, status=UserStatus.ACTIVE)
        if user:
            self._emit_event(UserEvent.ACTIVATED, user)
            return True
        return False

    def lock(self, user_id: str, duration_seconds: int = 1800) -> bool:
        """Lock user account.

        Args:
            user_id: User ID
            duration_seconds: Lock duration

        Returns:
            True if locked
        """
        from datetime import timedelta
        locked_until = datetime.now() + timedelta(seconds=duration_seconds)

        user = self.update(
            user_id,
            status=UserStatus.LOCKED,
            locked_until=locked_until,
        )
        if user:
            self._emit_event(UserEvent.LOCKED, user)
            return True
        return False

    def unlock(self, user_id: str) -> bool:
        """Unlock user account.

        Args:
            user_id: User ID

        Returns:
            True if unlocked
        """
        user = self.update(
            user_id,
            status=UserStatus.ACTIVE,
            locked_until=None,
            failed_login_attempts=0,
        )
        if user:
            self._emit_event(UserEvent.UNLOCKED, user)
            return True
        return False

    def change_password(self, user_id: str, new_password_hash: str) -> bool:
        """Change user password.

        Args:
            user_id: User ID
            new_password_hash: New hashed password

        Returns:
            True if changed
        """
        user = self.update(
            user_id,
            password_hash=new_password_hash,
            password_changed_at=datetime.now(),
        )
        if user:
            self._emit_event(UserEvent.PASSWORD_CHANGED, user)
            return True
        return False

    def record_login(self, user_id: str, ip_address: Optional[str] = None) -> bool:
        """Record successful login.

        Args:
            user_id: User ID
            ip_address: Client IP

        Returns:
            True if recorded
        """
        user = self.update(
            user_id,
            last_login=datetime.now(),
            last_ip_address=ip_address,
            failed_login_attempts=0,
        )
        if user:
            self._emit_event(UserEvent.LOGIN, user)
            return True
        return False

    def record_failed_login(self, user_id: str) -> int:
        """Record failed login attempt.

        Args:
            user_id: User ID

        Returns:
            Number of failed attempts
        """
        user = self.store.get(user_id)
        if user:
            attempts = user.failed_login_attempts + 1
            self.update(
                user_id,
                failed_login_attempts=attempts,
                last_failed_login=datetime.now(),
            )
            self._emit_event(UserEvent.FAILED_LOGIN, user)
            return attempts
        return 0

    def add_role(self, user_id: str, role: str) -> bool:
        """Add role to user.

        Args:
            user_id: User ID
            role: Role to add

        Returns:
            True if added
        """
        user = self.store.get(user_id)
        if user and role not in user.roles:
            user.roles.append(role)
            self.store.save(user)
            self._emit_event(UserEvent.UPDATED, user)
            return True
        return False

    def remove_role(self, user_id: str, role: str) -> bool:
        """Remove role from user.

        Args:
            user_id: User ID
            role: Role to remove

        Returns:
            True if removed
        """
        user = self.store.get(user_id)
        if user and role in user.roles:
            user.roles.remove(role)
            self.store.save(user)
            self._emit_event(UserEvent.UPDATED, user)
            return True
        return False

    def enable_mfa(self, user_id: str, secret: str, backup_codes: List[str]) -> bool:
        """Enable MFA for user.

        Args:
            user_id: User ID
            secret: TOTP secret
            backup_codes: Backup recovery codes

        Returns:
            True if enabled
        """
        user = self.update(
            user_id,
            mfa_enabled=True,
            mfa_secret=secret,
            mfa_backup_codes=backup_codes,
        )
        if user:
            self._emit_event(UserEvent.MFA_ENABLED, user)
            return True
        return False

    def disable_mfa(self, user_id: str) -> bool:
        """Disable MFA for user.

        Args:
            user_id: User ID

        Returns:
            True if disabled
        """
        user = self.update(
            user_id,
            mfa_enabled=False,
            mfa_secret=None,
            mfa_backup_codes=[],
        )
        if user:
            self._emit_event(UserEvent.MFA_DISABLED, user)
            return True
        return False

    def search(self, filter: UserFilter, page: int = 1, page_size: int = 50) -> UserPage:
        """Search users with filters.

        Args:
            filter: Search filter
            page: Page number
            page_size: Results per page

        Returns:
            Paginated results
        """
        return self.store.query(filter, page, page_size)

    def on(self, event: UserEvent, handler: Callable[[User], None]) -> None:
        """Register event handler.

        Args:
            event: Event type
            handler: Handler function
        """
        if event not in self._event_handlers:
            self._event_handlers[event] = []
        self._event_handlers[event].append(handler)

    def _emit_event(self, event: UserEvent, user: User) -> None:
        """Emit user event to handlers."""
        handlers = self._event_handlers.get(event, [])
        for handler in handlers:
            try:
                handler(user)
            except Exception as e:
                logger.error(f"Event handler error: {e}")


__all__ = [
    "User",
    "UserStatus",
    "UserEvent",
    "UserFilter",
    "UserPage",
    "UserStore",
    "InMemoryUserStore",
    "UserManager",
]
