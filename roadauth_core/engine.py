"""RoadAuth Engine - Core authentication and authorization engine.

Provides the main RoadAuth class that orchestrates all authentication
and authorization operations including:
- User authentication with multiple providers
- Token generation and validation
- Session management
- Permission checking
- MFA verification

Copyright (c) 2024-2026 BlackRoad OS, Inc. All rights reserved.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, auto
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

import yaml

# Configure logging
logger = logging.getLogger(__name__)

# Default paths
DEFAULT_CONFIG_PATH = Path.home() / ".roadauth" / "config.yaml"
DEFAULT_DATA_PATH = Path.home() / ".roadauth" / "data"


class AuthStatus(Enum):
    """Authentication result status."""

    SUCCESS = auto()
    INVALID_CREDENTIALS = auto()
    USER_NOT_FOUND = auto()
    USER_DISABLED = auto()
    USER_LOCKED = auto()
    MFA_REQUIRED = auto()
    MFA_FAILED = auto()
    TOKEN_EXPIRED = auto()
    TOKEN_INVALID = auto()
    SESSION_EXPIRED = auto()
    PROVIDER_ERROR = auto()
    RATE_LIMITED = auto()


class TokenType(Enum):
    """Types of tokens."""

    ACCESS = "access"
    REFRESH = "refresh"
    ID = "id"
    API_KEY = "api_key"
    SERVICE = "service"


@dataclass
class AuthConfig:
    """Authentication configuration."""

    # Secret keys
    secret_key: str = ""
    jwt_secret: str = ""

    # Token settings
    access_token_expires: int = 3600  # 1 hour
    refresh_token_expires: int = 604800  # 7 days
    token_algorithm: str = "HS256"

    # Session settings
    session_expires: int = 86400  # 24 hours
    session_sliding: bool = True
    max_sessions_per_user: int = 5

    # Security settings
    password_min_length: int = 12
    password_require_uppercase: bool = True
    password_require_lowercase: bool = True
    password_require_digit: bool = True
    password_require_special: bool = True
    password_hash_algorithm: str = "pbkdf2_sha256"
    password_hash_iterations: int = 310000

    # Lockout settings
    max_failed_attempts: int = 5
    lockout_duration: int = 1800  # 30 minutes

    # MFA settings
    mfa_enabled: bool = True
    mfa_required_for_admin: bool = True
    mfa_issuer: str = "RoadAuth"

    # Rate limiting
    rate_limit_enabled: bool = True
    rate_limit_requests: int = 100
    rate_limit_window: int = 60

    # Providers
    providers: List[str] = field(default_factory=lambda: ["local"])

    @classmethod
    def from_file(cls, path: Path) -> AuthConfig:
        """Load config from YAML file."""
        if not path.exists():
            return cls()

        with open(path) as f:
            data = yaml.safe_load(f) or {}

        return cls(**{k: v for k, v in data.items() if hasattr(cls, k)})

    def to_file(self, path: Path) -> None:
        """Save config to YAML file."""
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "w") as f:
            yaml.dump(self.__dict__, f, default_flow_style=False)


@dataclass
class AuthResult:
    """Result of an authentication attempt."""

    success: bool
    status: AuthStatus
    user_id: Optional[str] = None
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    id_token: Optional[str] = None
    expires_at: Optional[datetime] = None
    session_id: Optional[str] = None
    mfa_token: Optional[str] = None  # Temporary token for MFA flow
    message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TokenData:
    """Decoded token data."""

    token_type: TokenType
    user_id: str
    issued_at: datetime
    expires_at: datetime
    claims: Dict[str, Any] = field(default_factory=dict)
    jti: Optional[str] = None  # JWT ID for revocation


# =============================================================================
# Password Hashing
# =============================================================================


class PasswordHasher:
    """Secure password hashing with configurable algorithms."""

    def __init__(self, algorithm: str = "pbkdf2_sha256", iterations: int = 310000):
        """Initialize password hasher.

        Args:
            algorithm: Hash algorithm (pbkdf2_sha256, argon2, bcrypt)
            iterations: Number of iterations for PBKDF2
        """
        self.algorithm = algorithm
        self.iterations = iterations

    def hash(self, password: str) -> str:
        """Hash a password.

        Args:
            password: Plain text password

        Returns:
            Encoded hash string
        """
        salt = secrets.token_bytes(32)

        if self.algorithm == "pbkdf2_sha256":
            hash_bytes = hashlib.pbkdf2_hmac(
                "sha256",
                password.encode("utf-8"),
                salt,
                self.iterations
            )

            import base64
            salt_b64 = base64.b64encode(salt).decode("ascii")
            hash_b64 = base64.b64encode(hash_bytes).decode("ascii")

            return f"pbkdf2_sha256${self.iterations}${salt_b64}${hash_b64}"

        raise ValueError(f"Unsupported algorithm: {self.algorithm}")

    def verify(self, password: str, hash_string: str) -> bool:
        """Verify a password against a hash.

        Args:
            password: Plain text password
            hash_string: Stored hash string

        Returns:
            True if password matches
        """
        try:
            parts = hash_string.split("$")
            if len(parts) != 4:
                return False

            algorithm, iterations, salt_b64, stored_hash_b64 = parts

            import base64
            salt = base64.b64decode(salt_b64)
            stored_hash = base64.b64decode(stored_hash_b64)

            if algorithm == "pbkdf2_sha256":
                computed_hash = hashlib.pbkdf2_hmac(
                    "sha256",
                    password.encode("utf-8"),
                    salt,
                    int(iterations)
                )

                return hmac.compare_digest(computed_hash, stored_hash)

            return False

        except Exception:
            return False

    def needs_rehash(self, hash_string: str) -> bool:
        """Check if hash needs to be updated (algorithm/iteration change)."""
        try:
            parts = hash_string.split("$")
            if len(parts) != 4:
                return True

            algorithm, iterations = parts[0], int(parts[1])

            return algorithm != self.algorithm or iterations != self.iterations

        except Exception:
            return True


class PasswordValidator:
    """Validates password strength."""

    def __init__(self, config: AuthConfig):
        """Initialize validator with config."""
        self.config = config

    def validate(self, password: str) -> Tuple[bool, List[str]]:
        """Validate password strength.

        Args:
            password: Password to validate

        Returns:
            (is_valid, list_of_errors)
        """
        errors = []

        if len(password) < self.config.password_min_length:
            errors.append(f"Password must be at least {self.config.password_min_length} characters")

        if self.config.password_require_uppercase and not any(c.isupper() for c in password):
            errors.append("Password must contain at least one uppercase letter")

        if self.config.password_require_lowercase and not any(c.islower() for c in password):
            errors.append("Password must contain at least one lowercase letter")

        if self.config.password_require_digit and not any(c.isdigit() for c in password):
            errors.append("Password must contain at least one digit")

        if self.config.password_require_special:
            special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
            if not any(c in special_chars for c in password):
                errors.append("Password must contain at least one special character")

        # Check for common passwords
        common_passwords = {"password", "123456", "qwerty", "admin", "letmein"}
        if password.lower() in common_passwords:
            errors.append("Password is too common")

        return len(errors) == 0, errors


# =============================================================================
# Rate Limiter
# =============================================================================


class RateLimiter:
    """Token bucket rate limiter."""

    def __init__(self, requests: int = 100, window: int = 60):
        """Initialize rate limiter.

        Args:
            requests: Maximum requests per window
            window: Time window in seconds
        """
        self.max_requests = requests
        self.window = window
        self._buckets: Dict[str, List[float]] = {}
        self._lock = threading.RLock()

    def is_allowed(self, key: str) -> Tuple[bool, int]:
        """Check if request is allowed.

        Args:
            key: Rate limit key (usually IP or user ID)

        Returns:
            (is_allowed, remaining_requests)
        """
        with self._lock:
            now = time.time()
            cutoff = now - self.window

            # Get or create bucket
            if key not in self._buckets:
                self._buckets[key] = []

            # Remove old entries
            self._buckets[key] = [t for t in self._buckets[key] if t > cutoff]

            # Check limit
            remaining = self.max_requests - len(self._buckets[key])

            if remaining > 0:
                self._buckets[key].append(now)
                return True, remaining - 1

            return False, 0

    def reset(self, key: str) -> None:
        """Reset rate limit for a key."""
        with self._lock:
            if key in self._buckets:
                del self._buckets[key]


# =============================================================================
# Token Blacklist
# =============================================================================


class TokenBlacklist:
    """Manages revoked tokens."""

    def __init__(self):
        """Initialize token blacklist."""
        self._blacklist: Dict[str, datetime] = {}
        self._lock = threading.RLock()

    def revoke(self, jti: str, expires_at: datetime) -> None:
        """Add token to blacklist.

        Args:
            jti: JWT ID
            expires_at: When the token expires (for cleanup)
        """
        with self._lock:
            self._blacklist[jti] = expires_at

    def is_revoked(self, jti: str) -> bool:
        """Check if token is revoked."""
        with self._lock:
            return jti in self._blacklist

    def cleanup(self) -> int:
        """Remove expired entries from blacklist.

        Returns:
            Number of entries removed
        """
        with self._lock:
            now = datetime.now()
            expired = [jti for jti, exp in self._blacklist.items() if exp < now]

            for jti in expired:
                del self._blacklist[jti]

            return len(expired)


# =============================================================================
# Main RoadAuth Engine
# =============================================================================


class RoadAuth:
    """Main authentication and authorization engine.

    Core Principle: "Identity is the foundation of trust."
    Moral Constant: Protect user credentials and privacy above all.
    """

    CORE_PRINCIPLE = "Identity is the foundation of trust."
    MORAL_CONSTANT = "Protect user credentials and privacy above all."

    def __init__(
        self,
        config: Optional[AuthConfig] = None,
        secret_key: Optional[str] = None,
        config_path: Optional[Path] = None,
    ):
        """Initialize RoadAuth engine.

        Args:
            config: Auth configuration
            secret_key: Secret key for tokens (overrides config)
            config_path: Path to config file
        """
        # Load configuration
        if config:
            self.config = config
        elif config_path:
            self.config = AuthConfig.from_file(config_path)
        else:
            self.config = AuthConfig.from_file(DEFAULT_CONFIG_PATH)

        # Override secret key if provided
        if secret_key:
            self.config.secret_key = secret_key
            self.config.jwt_secret = secret_key

        # Generate secret if not set
        if not self.config.secret_key:
            self.config.secret_key = secrets.token_urlsafe(32)
            self.config.jwt_secret = self.config.secret_key

        # Initialize components
        self.password_hasher = PasswordHasher(
            algorithm=self.config.password_hash_algorithm,
            iterations=self.config.password_hash_iterations,
        )
        self.password_validator = PasswordValidator(self.config)
        self.rate_limiter = RateLimiter(
            requests=self.config.rate_limit_requests,
            window=self.config.rate_limit_window,
        )
        self.token_blacklist = TokenBlacklist()

        # User and session storage (in-memory for now)
        self._users: Dict[str, Dict[str, Any]] = {}
        self._sessions: Dict[str, Dict[str, Any]] = {}
        self._failed_attempts: Dict[str, int] = {}
        self._lockouts: Dict[str, datetime] = {}

        # Providers
        self._providers: Dict[str, Any] = {}

        # Thread safety
        self._lock = threading.RLock()

        logger.info("RoadAuth engine initialized")
        logger.info(f"Core principle: {self.CORE_PRINCIPLE}")

    def register(
        self,
        email: str,
        password: str,
        **metadata,
    ) -> Tuple[bool, Union[str, List[str]]]:
        """Register a new user.

        Args:
            email: User email
            password: User password
            **metadata: Additional user metadata

        Returns:
            (success, user_id or error_list)
        """
        with self._lock:
            # Validate email
            if not self._validate_email(email):
                return False, ["Invalid email format"]

            # Check if user exists
            if email.lower() in self._users:
                return False, ["User already exists"]

            # Validate password
            is_valid, errors = self.password_validator.validate(password)
            if not is_valid:
                return False, errors

            # Create user
            user_id = secrets.token_urlsafe(16)
            password_hash = self.password_hasher.hash(password)

            self._users[email.lower()] = {
                "id": user_id,
                "email": email.lower(),
                "password_hash": password_hash,
                "created_at": datetime.now().isoformat(),
                "status": "active",
                "roles": ["user"],
                "mfa_enabled": False,
                "metadata": metadata,
            }

            logger.info(f"User registered: {email}")
            return True, user_id

    def authenticate(
        self,
        email: str,
        password: str,
        mfa_code: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> AuthResult:
        """Authenticate a user.

        Args:
            email: User email
            password: User password
            mfa_code: MFA code if required
            ip_address: Client IP for rate limiting

        Returns:
            AuthResult with tokens if successful
        """
        # Rate limiting
        if self.config.rate_limit_enabled and ip_address:
            allowed, remaining = self.rate_limiter.is_allowed(ip_address)
            if not allowed:
                return AuthResult(
                    success=False,
                    status=AuthStatus.RATE_LIMITED,
                    message="Too many requests. Please try again later.",
                )

        with self._lock:
            email_lower = email.lower()

            # Check if user exists
            if email_lower not in self._users:
                return AuthResult(
                    success=False,
                    status=AuthStatus.USER_NOT_FOUND,
                    message="Invalid credentials",
                )

            user = self._users[email_lower]

            # Check lockout
            if email_lower in self._lockouts:
                lockout_until = self._lockouts[email_lower]
                if datetime.now() < lockout_until:
                    return AuthResult(
                        success=False,
                        status=AuthStatus.USER_LOCKED,
                        message=f"Account locked until {lockout_until.isoformat()}",
                    )
                else:
                    del self._lockouts[email_lower]
                    self._failed_attempts[email_lower] = 0

            # Check user status
            if user.get("status") == "disabled":
                return AuthResult(
                    success=False,
                    status=AuthStatus.USER_DISABLED,
                    message="Account is disabled",
                )

            # Verify password
            if not self.password_hasher.verify(password, user["password_hash"]):
                # Track failed attempts
                self._failed_attempts[email_lower] = self._failed_attempts.get(email_lower, 0) + 1

                if self._failed_attempts[email_lower] >= self.config.max_failed_attempts:
                    lockout_until = datetime.now() + timedelta(seconds=self.config.lockout_duration)
                    self._lockouts[email_lower] = lockout_until

                    return AuthResult(
                        success=False,
                        status=AuthStatus.USER_LOCKED,
                        message=f"Account locked until {lockout_until.isoformat()}",
                    )

                return AuthResult(
                    success=False,
                    status=AuthStatus.INVALID_CREDENTIALS,
                    message="Invalid credentials",
                )

            # Reset failed attempts on successful password
            self._failed_attempts[email_lower] = 0

            # Check MFA
            if user.get("mfa_enabled") and self.config.mfa_enabled:
                if not mfa_code:
                    # Generate temporary MFA token
                    mfa_token = secrets.token_urlsafe(32)
                    return AuthResult(
                        success=False,
                        status=AuthStatus.MFA_REQUIRED,
                        mfa_token=mfa_token,
                        message="MFA code required",
                    )

                # Verify MFA (simplified - would use TOTP manager)
                if not self._verify_mfa(user, mfa_code):
                    return AuthResult(
                        success=False,
                        status=AuthStatus.MFA_FAILED,
                        message="Invalid MFA code",
                    )

            # Generate tokens
            access_token = self._generate_token(user, TokenType.ACCESS)
            refresh_token = self._generate_token(user, TokenType.REFRESH)

            # Create session
            session_id = secrets.token_urlsafe(32)
            expires_at = datetime.now() + timedelta(seconds=self.config.access_token_expires)

            self._sessions[session_id] = {
                "user_id": user["id"],
                "created_at": datetime.now().isoformat(),
                "expires_at": expires_at.isoformat(),
                "ip_address": ip_address,
            }

            # Check password rehash
            if self.password_hasher.needs_rehash(user["password_hash"]):
                user["password_hash"] = self.password_hasher.hash(password)

            logger.info(f"User authenticated: {email}")

            return AuthResult(
                success=True,
                status=AuthStatus.SUCCESS,
                user_id=user["id"],
                access_token=access_token,
                refresh_token=refresh_token,
                expires_at=expires_at,
                session_id=session_id,
            )

    def validate_token(self, token: str) -> Tuple[bool, Optional[TokenData]]:
        """Validate a token.

        Args:
            token: JWT or Paseto token

        Returns:
            (is_valid, token_data)
        """
        try:
            # Decode token (simplified - would use JWT library)
            import base64
            import json

            parts = token.split(".")
            if len(parts) != 3:
                return False, None

            # Decode payload
            payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))

            # Check expiration
            exp = datetime.fromtimestamp(payload.get("exp", 0))
            if datetime.now() > exp:
                return False, None

            # Check blacklist
            jti = payload.get("jti")
            if jti and self.token_blacklist.is_revoked(jti):
                return False, None

            token_data = TokenData(
                token_type=TokenType(payload.get("type", "access")),
                user_id=payload.get("sub"),
                issued_at=datetime.fromtimestamp(payload.get("iat", 0)),
                expires_at=exp,
                claims=payload,
                jti=jti,
            )

            return True, token_data

        except Exception as e:
            logger.debug(f"Token validation failed: {e}")
            return False, None

    def refresh_token(self, refresh_token: str) -> AuthResult:
        """Refresh access token using refresh token.

        Args:
            refresh_token: Valid refresh token

        Returns:
            AuthResult with new tokens
        """
        is_valid, token_data = self.validate_token(refresh_token)

        if not is_valid or token_data.token_type != TokenType.REFRESH:
            return AuthResult(
                success=False,
                status=AuthStatus.TOKEN_INVALID,
                message="Invalid refresh token",
            )

        # Get user
        user = self._get_user_by_id(token_data.user_id)
        if not user:
            return AuthResult(
                success=False,
                status=AuthStatus.USER_NOT_FOUND,
                message="User not found",
            )

        # Generate new tokens
        new_access_token = self._generate_token(user, TokenType.ACCESS)
        new_refresh_token = self._generate_token(user, TokenType.REFRESH)
        expires_at = datetime.now() + timedelta(seconds=self.config.access_token_expires)

        # Revoke old refresh token
        if token_data.jti:
            self.token_blacklist.revoke(token_data.jti, token_data.expires_at)

        return AuthResult(
            success=True,
            status=AuthStatus.SUCCESS,
            user_id=user["id"],
            access_token=new_access_token,
            refresh_token=new_refresh_token,
            expires_at=expires_at,
        )

    def logout(self, token: str, session_id: Optional[str] = None) -> bool:
        """Logout user by revoking token and session.

        Args:
            token: Access token to revoke
            session_id: Session to invalidate

        Returns:
            True if successful
        """
        is_valid, token_data = self.validate_token(token)

        if is_valid and token_data.jti:
            self.token_blacklist.revoke(token_data.jti, token_data.expires_at)

        if session_id and session_id in self._sessions:
            with self._lock:
                del self._sessions[session_id]

        return True

    def authorize(self, user_id: str, permission: str, resource: Optional[str] = None) -> bool:
        """Check if user has permission.

        Args:
            user_id: User ID
            permission: Required permission
            resource: Optional resource identifier

        Returns:
            True if authorized
        """
        user = self._get_user_by_id(user_id)
        if not user:
            return False

        # Check user roles for permission
        # Simplified - would use RBAC manager
        if "admin" in user.get("roles", []):
            return True

        # Check specific permission
        # Format: "resource:action" or just "action"
        user_permissions = self._get_user_permissions(user)

        if "*" in user_permissions:
            return True

        if permission in user_permissions:
            return True

        if resource:
            full_permission = f"{resource}:{permission}"
            if full_permission in user_permissions:
                return True

        return False

    def _generate_token(self, user: Dict[str, Any], token_type: TokenType) -> str:
        """Generate a JWT token."""
        import base64
        import json

        now = datetime.now()

        if token_type == TokenType.ACCESS:
            expires = now + timedelta(seconds=self.config.access_token_expires)
        else:
            expires = now + timedelta(seconds=self.config.refresh_token_expires)

        payload = {
            "sub": user["id"],
            "email": user["email"],
            "roles": user.get("roles", []),
            "type": token_type.value,
            "iat": int(now.timestamp()),
            "exp": int(expires.timestamp()),
            "jti": secrets.token_urlsafe(16),
        }

        # Create JWT (simplified - would use proper JWT library)
        header = {"alg": self.config.token_algorithm, "typ": "JWT"}
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()

        message = f"{header_b64}.{payload_b64}"
        signature = hmac.new(
            self.config.jwt_secret.encode(),
            message.encode(),
            hashlib.sha256
        ).digest()
        signature_b64 = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()

        return f"{message}.{signature_b64}"

    def _validate_email(self, email: str) -> bool:
        """Validate email format."""
        import re
        pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        return bool(re.match(pattern, email))

    def _verify_mfa(self, user: Dict[str, Any], code: str) -> bool:
        """Verify MFA code (simplified)."""
        # Would use TOTP manager
        return len(code) == 6 and code.isdigit()

    def _get_user_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user by ID."""
        for user in self._users.values():
            if user["id"] == user_id:
                return user
        return None

    def _get_user_permissions(self, user: Dict[str, Any]) -> Set[str]:
        """Get all permissions for a user."""
        permissions = set()

        # Role-based permissions (simplified)
        role_permissions = {
            "admin": {"*"},
            "user": {"read", "profile:read", "profile:update"},
            "moderator": {"read", "write", "users:read"},
        }

        for role in user.get("roles", []):
            permissions.update(role_permissions.get(role, set()))

        return permissions

    def get_stats(self) -> Dict[str, Any]:
        """Get authentication statistics."""
        return {
            "total_users": len(self._users),
            "active_sessions": len(self._sessions),
            "locked_accounts": len(self._lockouts),
            "blacklisted_tokens": len(self.token_blacklist._blacklist),
        }


# =============================================================================
# Factory Functions
# =============================================================================


def create_auth(
    secret_key: Optional[str] = None,
    config_path: Optional[Path] = None,
    **kwargs,
) -> RoadAuth:
    """Create a RoadAuth instance.

    Args:
        secret_key: Secret key for tokens
        config_path: Path to config file
        **kwargs: Additional config options

    Returns:
        Configured RoadAuth instance
    """
    config = AuthConfig(**kwargs) if kwargs else None
    return RoadAuth(config=config, secret_key=secret_key, config_path=config_path)


__all__ = [
    "RoadAuth",
    "AuthConfig",
    "AuthResult",
    "AuthStatus",
    "TokenType",
    "TokenData",
    "PasswordHasher",
    "PasswordValidator",
    "RateLimiter",
    "TokenBlacklist",
    "create_auth",
]
