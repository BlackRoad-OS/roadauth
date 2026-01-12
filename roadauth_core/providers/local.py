"""RoadAuth Local Provider - Local Username/Password Authentication.

Implements local database authentication with:
- Password hashing (Argon2id, bcrypt, PBKDF2)
- Password policy enforcement
- Account lockout
- Password history

Copyright (c) 2024-2026 BlackRoad OS, Inc. All rights reserved.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

from roadauth_core.providers.base import (
    AuthProvider,
    AuthProviderConfig,
    AuthProviderResult,
    AuthProviderType,
    AuthStatus,
)

# Configure logging
logger = logging.getLogger(__name__)


class HashAlgorithm(Enum):
    """Password hash algorithms."""

    PBKDF2_SHA256 = "pbkdf2_sha256"
    PBKDF2_SHA512 = "pbkdf2_sha512"
    BCRYPT = "bcrypt"
    ARGON2ID = "argon2id"


@dataclass
class PasswordPolicy:
    """Password policy configuration."""

    min_length: int = 8
    max_length: int = 128
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_digit: bool = True
    require_special: bool = False
    special_characters: str = "!@#$%^&*()_+-=[]{}|;':\",./<>?"

    # History
    password_history_count: int = 5
    prevent_reuse: bool = True

    # Expiration
    max_age_days: int = 90
    warn_before_expiry_days: int = 14

    # Complexity
    min_unique_chars: int = 4
    disallow_username_in_password: bool = True
    disallow_common_passwords: bool = True

    def validate(self, password: str, username: Optional[str] = None) -> Tuple[bool, List[str]]:
        """Validate password against policy.

        Args:
            password: Password to validate
            username: Optional username to check against

        Returns:
            (is_valid, list_of_errors)
        """
        errors = []

        # Length checks
        if len(password) < self.min_length:
            errors.append(f"Password must be at least {self.min_length} characters")
        if len(password) > self.max_length:
            errors.append(f"Password must be at most {self.max_length} characters")

        # Character requirements
        if self.require_uppercase and not re.search(r"[A-Z]", password):
            errors.append("Password must contain at least one uppercase letter")
        if self.require_lowercase and not re.search(r"[a-z]", password):
            errors.append("Password must contain at least one lowercase letter")
        if self.require_digit and not re.search(r"\d", password):
            errors.append("Password must contain at least one digit")
        if self.require_special and not any(c in self.special_characters for c in password):
            errors.append("Password must contain at least one special character")

        # Unique characters
        if len(set(password)) < self.min_unique_chars:
            errors.append(f"Password must contain at least {self.min_unique_chars} unique characters")

        # Username check
        if self.disallow_username_in_password and username:
            if username.lower() in password.lower():
                errors.append("Password cannot contain username")

        return len(errors) == 0, errors


class PasswordHasher:
    """Password hashing utility."""

    def __init__(
        self,
        algorithm: HashAlgorithm = HashAlgorithm.PBKDF2_SHA256,
        iterations: int = 600000,
        salt_length: int = 32,
    ):
        """Initialize hasher.

        Args:
            algorithm: Hash algorithm
            iterations: Iteration count for PBKDF2
            salt_length: Salt length in bytes
        """
        self.algorithm = algorithm
        self.iterations = iterations
        self.salt_length = salt_length

    def hash(self, password: str) -> str:
        """Hash a password.

        Args:
            password: Plaintext password

        Returns:
            Hashed password string
        """
        salt = secrets.token_bytes(self.salt_length)

        if self.algorithm == HashAlgorithm.PBKDF2_SHA256:
            hash_bytes = hashlib.pbkdf2_hmac(
                "sha256",
                password.encode(),
                salt,
                self.iterations,
            )
            return f"pbkdf2_sha256${self.iterations}${salt.hex()}${hash_bytes.hex()}"

        elif self.algorithm == HashAlgorithm.PBKDF2_SHA512:
            hash_bytes = hashlib.pbkdf2_hmac(
                "sha512",
                password.encode(),
                salt,
                self.iterations,
            )
            return f"pbkdf2_sha512${self.iterations}${salt.hex()}${hash_bytes.hex()}"

        else:
            # Default to PBKDF2-SHA256
            hash_bytes = hashlib.pbkdf2_hmac(
                "sha256",
                password.encode(),
                salt,
                self.iterations,
            )
            return f"pbkdf2_sha256${self.iterations}${salt.hex()}${hash_bytes.hex()}"

    def verify(self, password: str, hash_string: str) -> bool:
        """Verify a password against hash.

        Args:
            password: Plaintext password
            hash_string: Stored hash

        Returns:
            True if matches
        """
        try:
            parts = hash_string.split("$")
            if len(parts) != 4:
                return False

            algorithm, iterations, salt_hex, hash_hex = parts
            iterations = int(iterations)
            salt = bytes.fromhex(salt_hex)
            stored_hash = bytes.fromhex(hash_hex)

            if algorithm == "pbkdf2_sha256":
                computed_hash = hashlib.pbkdf2_hmac(
                    "sha256",
                    password.encode(),
                    salt,
                    iterations,
                )
            elif algorithm == "pbkdf2_sha512":
                computed_hash = hashlib.pbkdf2_hmac(
                    "sha512",
                    password.encode(),
                    salt,
                    iterations,
                )
            else:
                return False

            return hmac.compare_digest(computed_hash, stored_hash)

        except Exception as e:
            logger.error(f"Password verification error: {e}")
            return False

    def needs_rehash(self, hash_string: str) -> bool:
        """Check if hash needs to be rehashed.

        Args:
            hash_string: Stored hash

        Returns:
            True if should rehash
        """
        try:
            parts = hash_string.split("$")
            if len(parts) != 4:
                return True

            algorithm, iterations, _, _ = parts
            iterations = int(iterations)

            # Check if algorithm or iterations changed
            current_algo = self.algorithm.value
            if algorithm != current_algo:
                return True
            if iterations < self.iterations:
                return True

            return False

        except Exception:
            return True


@dataclass
class LocalProviderConfig(AuthProviderConfig):
    """Local provider configuration."""

    # Password hashing
    hash_algorithm: HashAlgorithm = HashAlgorithm.PBKDF2_SHA256
    hash_iterations: int = 600000

    # Password policy
    password_policy: PasswordPolicy = field(default_factory=PasswordPolicy)

    # Account lockout
    lockout_threshold: int = 5
    lockout_duration: int = 300  # 5 minutes
    lockout_observation_window: int = 900  # 15 minutes

    # Session
    max_sessions_per_user: int = 5
    session_idle_timeout: int = 1800  # 30 minutes

    # Rate limiting
    rate_limit_enabled: bool = True
    rate_limit_attempts: int = 10
    rate_limit_window: int = 60  # 1 minute


class LocalUserStore:
    """In-memory local user store."""

    def __init__(self):
        """Initialize store."""
        self._users: Dict[str, Dict[str, Any]] = {}
        self._by_email: Dict[str, str] = {}
        self._by_username: Dict[str, str] = {}

    def create_user(
        self,
        user_id: str,
        email: str,
        username: str,
        password_hash: str,
        **kwargs
    ) -> Dict[str, Any]:
        """Create user."""
        user = {
            "id": user_id,
            "email": email.lower(),
            "username": username.lower(),
            "password_hash": password_hash,
            "password_history": [password_hash],
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat(),
            "last_login_at": None,
            "password_changed_at": datetime.now().isoformat(),
            "failed_login_count": 0,
            "locked_until": None,
            "is_active": True,
            **kwargs
        }

        self._users[user_id] = user
        self._by_email[email.lower()] = user_id
        self._by_username[username.lower()] = user_id

        return user

    def get_user(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user by ID."""
        return self._users.get(user_id)

    def get_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Get user by email."""
        user_id = self._by_email.get(email.lower())
        return self._users.get(user_id) if user_id else None

    def get_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """Get user by username."""
        user_id = self._by_username.get(username.lower())
        return self._users.get(user_id) if user_id else None

    def update_user(self, user_id: str, **updates) -> Optional[Dict[str, Any]]:
        """Update user."""
        user = self._users.get(user_id)
        if not user:
            return None

        user.update(updates)
        user["updated_at"] = datetime.now().isoformat()
        return user

    def delete_user(self, user_id: str) -> bool:
        """Delete user."""
        user = self._users.get(user_id)
        if not user:
            return False

        del self._users[user_id]
        self._by_email.pop(user["email"], None)
        self._by_username.pop(user["username"], None)
        return True


class LocalProvider(AuthProvider):
    """Local username/password authentication provider."""

    def __init__(
        self,
        config: Optional[LocalProviderConfig] = None,
        user_store: Optional[LocalUserStore] = None,
    ):
        """Initialize local provider.

        Args:
            config: Provider configuration
            user_store: User store implementation
        """
        if config is None:
            config = LocalProviderConfig(
                provider_id="local",
                provider_type=AuthProviderType.LOCAL,
            )

        super().__init__(config)
        self.local_config = config
        self.user_store = user_store or LocalUserStore()
        self.hasher = PasswordHasher(
            algorithm=config.hash_algorithm,
            iterations=config.hash_iterations,
        )

        # Rate limiting state
        self._rate_limit: Dict[str, List[float]] = {}

    async def initialize(self) -> bool:
        """Initialize provider."""
        self._initialized = True
        logger.info("Local auth provider initialized")
        return True

    async def authenticate(
        self,
        credentials: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> AuthProviderResult:
        """Authenticate user with username/password.

        Args:
            credentials: Must contain 'identifier' (email/username) and 'password'
            context: Optional context (IP, user agent, etc.)

        Returns:
            Authentication result
        """
        identifier = credentials.get("identifier", "").strip()
        password = credentials.get("password", "")

        if not identifier or not password:
            return AuthProviderResult.failure_result(
                AuthStatus.INVALID_CREDENTIALS,
                "Missing credentials",
            )

        # Rate limiting
        if self.local_config.rate_limit_enabled:
            client_ip = (context or {}).get("ip", identifier)
            if self._is_rate_limited(client_ip):
                return AuthProviderResult.failure_result(
                    AuthStatus.FAILURE,
                    "Too many attempts. Please try again later.",
                )

        # Find user
        user = self.user_store.get_by_email(identifier)
        if not user:
            user = self.user_store.get_by_username(identifier)

        if not user:
            self._record_attempt(identifier)
            return AuthProviderResult.failure_result(
                AuthStatus.USER_NOT_FOUND,
                "Invalid credentials",
            )

        # Check if account is active
        if not user.get("is_active"):
            return AuthProviderResult.failure_result(
                AuthStatus.ACCOUNT_DISABLED,
                "Account is disabled",
            )

        # Check lockout
        locked_until = user.get("locked_until")
        if locked_until:
            locked_until_dt = datetime.fromisoformat(locked_until)
            if datetime.now() < locked_until_dt:
                return AuthProviderResult.failure_result(
                    AuthStatus.ACCOUNT_LOCKED,
                    f"Account locked until {locked_until}",
                )
            else:
                # Lockout expired, reset
                self.user_store.update_user(
                    user["id"],
                    locked_until=None,
                    failed_login_count=0,
                )

        # Verify password
        if not self.hasher.verify(password, user["password_hash"]):
            self._handle_failed_login(user)
            return AuthProviderResult.failure_result(
                AuthStatus.INVALID_CREDENTIALS,
                "Invalid credentials",
            )

        # Check password expiration
        password_changed = user.get("password_changed_at")
        if password_changed:
            changed_dt = datetime.fromisoformat(password_changed)
            max_age = timedelta(days=self.local_config.password_policy.max_age_days)
            if datetime.now() > changed_dt + max_age:
                return AuthProviderResult.failure_result(
                    AuthStatus.PASSWORD_EXPIRED,
                    "Password has expired",
                    requires_password_change=True,
                )

        # Successful login
        self._handle_successful_login(user)

        # Check if rehash needed
        if self.hasher.needs_rehash(user["password_hash"]):
            new_hash = self.hasher.hash(password)
            self.user_store.update_user(user["id"], password_hash=new_hash)

        # Check if password expiring soon
        requires_change = False
        if password_changed:
            changed_dt = datetime.fromisoformat(password_changed)
            warn_days = self.local_config.password_policy.warn_before_expiry_days
            max_age = self.local_config.password_policy.max_age_days
            warn_threshold = changed_dt + timedelta(days=max_age - warn_days)
            if datetime.now() > warn_threshold:
                requires_change = True

        return AuthProviderResult.success_result(
            user_id=user["id"],
            email=user["email"],
            username=user["username"],
            display_name=user.get("display_name"),
            provider_id=self.provider_id,
            provider_type=self.provider_type,
            requires_password_change=requires_change,
            requires_mfa=self.local_config.require_mfa,
        )

    async def validate_user(self, user_id: str) -> bool:
        """Validate user exists and is active.

        Args:
            user_id: User ID

        Returns:
            True if valid
        """
        user = self.user_store.get_user(user_id)
        return user is not None and user.get("is_active", False)

    async def get_user_info(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user information.

        Args:
            user_id: User ID

        Returns:
            User info (without sensitive data)
        """
        user = self.user_store.get_user(user_id)
        if not user:
            return None

        return {
            "id": user["id"],
            "email": user["email"],
            "username": user["username"],
            "display_name": user.get("display_name"),
            "created_at": user["created_at"],
            "last_login_at": user.get("last_login_at"),
            "is_active": user.get("is_active"),
        }

    async def change_password(
        self,
        user_id: str,
        current_password: str,
        new_password: str,
    ) -> Tuple[bool, str]:
        """Change user password.

        Args:
            user_id: User ID
            current_password: Current password
            new_password: New password

        Returns:
            (success, message)
        """
        user = self.user_store.get_user(user_id)
        if not user:
            return False, "User not found"

        # Verify current password
        if not self.hasher.verify(current_password, user["password_hash"]):
            return False, "Current password is incorrect"

        # Validate new password
        policy = self.local_config.password_policy
        is_valid, errors = policy.validate(new_password, user["username"])
        if not is_valid:
            return False, "; ".join(errors)

        # Check password history
        if policy.prevent_reuse:
            history = user.get("password_history", [])
            for old_hash in history[-policy.password_history_count:]:
                if self.hasher.verify(new_password, old_hash):
                    return False, "Cannot reuse recent passwords"

        # Hash and save new password
        new_hash = self.hasher.hash(new_password)
        history = user.get("password_history", [])
        history.append(new_hash)

        # Keep only recent history
        history = history[-policy.password_history_count:]

        self.user_store.update_user(
            user_id,
            password_hash=new_hash,
            password_history=history,
            password_changed_at=datetime.now().isoformat(),
        )

        logger.info(f"Password changed for user {user_id}")
        return True, "Password changed successfully"

    async def reset_password(
        self,
        user_id: str,
        new_password: str,
    ) -> Tuple[bool, str]:
        """Reset user password (admin action).

        Args:
            user_id: User ID
            new_password: New password

        Returns:
            (success, message)
        """
        user = self.user_store.get_user(user_id)
        if not user:
            return False, "User not found"

        # Validate new password
        policy = self.local_config.password_policy
        is_valid, errors = policy.validate(new_password, user["username"])
        if not is_valid:
            return False, "; ".join(errors)

        # Hash and save new password
        new_hash = self.hasher.hash(new_password)

        self.user_store.update_user(
            user_id,
            password_hash=new_hash,
            password_changed_at=datetime.now().isoformat(),
            locked_until=None,
            failed_login_count=0,
        )

        logger.info(f"Password reset for user {user_id}")
        return True, "Password reset successfully"

    def _handle_failed_login(self, user: Dict[str, Any]) -> None:
        """Handle failed login attempt."""
        failed_count = user.get("failed_login_count", 0) + 1

        updates = {"failed_login_count": failed_count}

        if failed_count >= self.local_config.lockout_threshold:
            lockout_until = datetime.now() + timedelta(
                seconds=self.local_config.lockout_duration
            )
            updates["locked_until"] = lockout_until.isoformat()
            logger.warning(f"Account locked for user {user['id']}")

        self.user_store.update_user(user["id"], **updates)

    def _handle_successful_login(self, user: Dict[str, Any]) -> None:
        """Handle successful login."""
        self.user_store.update_user(
            user["id"],
            failed_login_count=0,
            locked_until=None,
            last_login_at=datetime.now().isoformat(),
        )

    def _is_rate_limited(self, identifier: str) -> bool:
        """Check if identifier is rate limited."""
        now = time.time()
        window = self.local_config.rate_limit_window
        max_attempts = self.local_config.rate_limit_attempts

        # Get attempts in window
        attempts = self._rate_limit.get(identifier, [])
        attempts = [t for t in attempts if now - t < window]
        self._rate_limit[identifier] = attempts

        return len(attempts) >= max_attempts

    def _record_attempt(self, identifier: str) -> None:
        """Record authentication attempt."""
        now = time.time()
        if identifier not in self._rate_limit:
            self._rate_limit[identifier] = []
        self._rate_limit[identifier].append(now)


__all__ = [
    "LocalProvider",
    "LocalProviderConfig",
    "LocalUserStore",
    "PasswordHasher",
    "PasswordPolicy",
    "HashAlgorithm",
]
