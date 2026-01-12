"""RoadAuth TOTP - Time-based One-Time Password.

Implements RFC 6238 TOTP for two-factor authentication:
- Secret generation and storage
- Code generation and validation
- QR code provisioning URI generation
- Clock drift tolerance
- Rate limiting

Compatible with:
- Google Authenticator
- Authy
- Microsoft Authenticator
- 1Password
- Any RFC 6238 compliant app

Copyright (c) 2024-2026 BlackRoad OS, Inc. All rights reserved.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import secrets
import struct
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote, urlencode

# Configure logging
logger = logging.getLogger(__name__)


class TOTPAlgorithm(Enum):
    """TOTP hash algorithms."""

    SHA1 = "SHA1"
    SHA256 = "SHA256"
    SHA512 = "SHA512"


class TOTPStatus(Enum):
    """TOTP secret status."""

    PENDING = "pending"  # Awaiting verification
    ACTIVE = "active"  # Verified and active
    DISABLED = "disabled"  # Disabled by user
    REVOKED = "revoked"  # Revoked by admin


@dataclass
class TOTPSecret:
    """TOTP secret for a user."""

    id: str
    user_id: str
    secret: str  # Base32 encoded
    algorithm: TOTPAlgorithm = TOTPAlgorithm.SHA1
    digits: int = 6
    period: int = 30  # Time step in seconds
    status: TOTPStatus = TOTPStatus.PENDING

    # Metadata
    name: Optional[str] = None  # Display name
    issuer: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)
    verified_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None

    # Rate limiting
    failed_attempts: int = 0
    locked_until: Optional[datetime] = None

    # Backup
    recovery_codes: List[str] = field(default_factory=list)

    @classmethod
    def generate(
        cls,
        user_id: str,
        issuer: Optional[str] = None,
        name: Optional[str] = None,
        algorithm: TOTPAlgorithm = TOTPAlgorithm.SHA1,
        digits: int = 6,
        period: int = 30,
    ) -> TOTPSecret:
        """Generate a new TOTP secret.

        Args:
            user_id: User ID
            issuer: Application issuer name
            name: Display name (usually email)
            algorithm: Hash algorithm
            digits: Number of digits
            period: Time step in seconds

        Returns:
            TOTPSecret instance
        """
        # Generate 160-bit secret (20 bytes)
        raw_secret = secrets.token_bytes(20)
        encoded_secret = base64.b32encode(raw_secret).decode().rstrip("=")

        return cls(
            id=secrets.token_urlsafe(8),
            user_id=user_id,
            secret=encoded_secret,
            algorithm=algorithm,
            digits=digits,
            period=period,
            issuer=issuer,
            name=name,
        )

    @property
    def secret_bytes(self) -> bytes:
        """Get secret as bytes."""
        # Add padding if needed
        secret = self.secret + "=" * ((8 - len(self.secret) % 8) % 8)
        return base64.b32decode(secret.upper())

    @property
    def is_active(self) -> bool:
        """Check if secret is active."""
        return self.status == TOTPStatus.ACTIVE

    @property
    def is_locked(self) -> bool:
        """Check if secret is locked due to failed attempts."""
        if self.locked_until is None:
            return False
        return datetime.now() < self.locked_until

    def get_provisioning_uri(self, account_name: Optional[str] = None) -> str:
        """Get otpauth:// provisioning URI for QR code.

        Args:
            account_name: Account name to display

        Returns:
            Provisioning URI
        """
        account = account_name or self.name or self.user_id

        # Build label
        if self.issuer:
            label = f"{self.issuer}:{account}"
        else:
            label = account

        # Build parameters
        params = {
            "secret": self.secret,
            "algorithm": self.algorithm.value,
            "digits": str(self.digits),
            "period": str(self.period),
        }

        if self.issuer:
            params["issuer"] = self.issuer

        return f"otpauth://totp/{quote(label)}?{urlencode(params)}"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary (without secret)."""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "algorithm": self.algorithm.value,
            "digits": self.digits,
            "period": self.period,
            "status": self.status.value,
            "name": self.name,
            "issuer": self.issuer,
            "created_at": self.created_at.isoformat(),
            "verified_at": self.verified_at.isoformat() if self.verified_at else None,
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
        }


class TOTPGenerator:
    """TOTP code generator implementing RFC 6238."""

    @staticmethod
    def generate(
        secret: bytes,
        timestamp: Optional[int] = None,
        period: int = 30,
        digits: int = 6,
        algorithm: TOTPAlgorithm = TOTPAlgorithm.SHA1,
    ) -> str:
        """Generate TOTP code.

        Args:
            secret: Secret key bytes
            timestamp: Unix timestamp (defaults to now)
            period: Time step in seconds
            digits: Number of digits
            algorithm: Hash algorithm

        Returns:
            TOTP code string
        """
        if timestamp is None:
            timestamp = int(time.time())

        # Calculate time counter
        counter = timestamp // period

        # Generate HOTP
        code = TOTPGenerator._hotp(secret, counter, digits, algorithm)

        return code.zfill(digits)

    @staticmethod
    def _hotp(
        secret: bytes,
        counter: int,
        digits: int,
        algorithm: TOTPAlgorithm,
    ) -> str:
        """Generate HOTP code (RFC 4226).

        Args:
            secret: Secret key bytes
            counter: Counter value
            digits: Number of digits
            algorithm: Hash algorithm

        Returns:
            HOTP code string
        """
        # Pack counter as big-endian 8-byte integer
        counter_bytes = struct.pack(">Q", counter)

        # Choose hash function
        if algorithm == TOTPAlgorithm.SHA1:
            hash_func = hashlib.sha1
        elif algorithm == TOTPAlgorithm.SHA256:
            hash_func = hashlib.sha256
        elif algorithm == TOTPAlgorithm.SHA512:
            hash_func = hashlib.sha512
        else:
            hash_func = hashlib.sha1

        # Generate HMAC
        hmac_digest = hmac.new(secret, counter_bytes, hash_func).digest()

        # Dynamic truncation
        offset = hmac_digest[-1] & 0x0F
        binary = struct.unpack(">I", hmac_digest[offset:offset + 4])[0] & 0x7FFFFFFF

        # Generate OTP
        otp = binary % (10 ** digits)

        return str(otp)


class TOTPStore:
    """In-memory TOTP secret store."""

    def __init__(self):
        """Initialize store."""
        self._secrets: Dict[str, TOTPSecret] = {}
        self._by_user: Dict[str, str] = {}  # user_id -> secret_id
        self._lock = threading.RLock()

    def save(self, secret: TOTPSecret) -> bool:
        """Save TOTP secret."""
        with self._lock:
            self._secrets[secret.id] = secret
            self._by_user[secret.user_id] = secret.id
            return True

    def get(self, secret_id: str) -> Optional[TOTPSecret]:
        """Get secret by ID."""
        return self._secrets.get(secret_id)

    def get_by_user(self, user_id: str) -> Optional[TOTPSecret]:
        """Get secret by user ID."""
        secret_id = self._by_user.get(user_id)
        if secret_id:
            return self._secrets.get(secret_id)
        return None

    def delete(self, secret_id: str) -> bool:
        """Delete secret."""
        with self._lock:
            secret = self._secrets.get(secret_id)
            if secret:
                del self._secrets[secret_id]
                if self._by_user.get(secret.user_id) == secret_id:
                    del self._by_user[secret.user_id]
                return True
            return False

    def delete_by_user(self, user_id: str) -> bool:
        """Delete secret by user ID."""
        secret_id = self._by_user.get(user_id)
        if secret_id:
            return self.delete(secret_id)
        return False


class TOTPManager:
    """Manages TOTP secrets and verification."""

    def __init__(
        self,
        issuer: str = "RoadAuth",
        store: Optional[TOTPStore] = None,
        digits: int = 6,
        period: int = 30,
        algorithm: TOTPAlgorithm = TOTPAlgorithm.SHA1,
        window: int = 1,  # Allow codes from adjacent time windows
        max_attempts: int = 5,
        lockout_duration: int = 300,  # 5 minutes
    ):
        """Initialize TOTP manager.

        Args:
            issuer: Application issuer name
            store: TOTP secret store
            digits: Number of digits
            period: Time step in seconds
            algorithm: Hash algorithm
            window: Time window tolerance
            max_attempts: Max failed attempts before lockout
            lockout_duration: Lockout duration in seconds
        """
        self.issuer = issuer
        self.store = store or TOTPStore()
        self.digits = digits
        self.period = period
        self.algorithm = algorithm
        self.window = window
        self.max_attempts = max_attempts
        self.lockout_duration = lockout_duration

    def setup(
        self,
        user_id: str,
        name: Optional[str] = None,
    ) -> Tuple[TOTPSecret, str]:
        """Set up TOTP for a user.

        Args:
            user_id: User ID
            name: Display name (usually email)

        Returns:
            (TOTPSecret, provisioning_uri)
        """
        # Check for existing secret
        existing = self.store.get_by_user(user_id)
        if existing and existing.status == TOTPStatus.ACTIVE:
            raise ValueError("TOTP already enabled for user")

        # Generate new secret
        secret = TOTPSecret.generate(
            user_id=user_id,
            issuer=self.issuer,
            name=name,
            algorithm=self.algorithm,
            digits=self.digits,
            period=self.period,
        )

        # Save secret
        self.store.save(secret)

        # Get provisioning URI
        uri = secret.get_provisioning_uri(name)

        logger.info(f"TOTP setup initiated for user {user_id}")
        return secret, uri

    def verify_setup(self, user_id: str, code: str) -> bool:
        """Verify TOTP setup with initial code.

        Args:
            user_id: User ID
            code: TOTP code from authenticator app

        Returns:
            True if verified
        """
        secret = self.store.get_by_user(user_id)
        if not secret:
            return False

        if secret.status != TOTPStatus.PENDING:
            return False

        # Verify code
        if self._verify_code(secret, code):
            secret.status = TOTPStatus.ACTIVE
            secret.verified_at = datetime.now()
            self.store.save(secret)
            logger.info(f"TOTP verified for user {user_id}")
            return True

        return False

    def verify(self, user_id: str, code: str) -> bool:
        """Verify TOTP code.

        Args:
            user_id: User ID
            code: TOTP code

        Returns:
            True if valid
        """
        secret = self.store.get_by_user(user_id)
        if not secret:
            return False

        if secret.status != TOTPStatus.ACTIVE:
            return False

        # Check lockout
        if secret.is_locked:
            logger.warning(f"TOTP locked for user {user_id}")
            return False

        # Verify code
        if self._verify_code(secret, code):
            # Reset failed attempts
            secret.failed_attempts = 0
            secret.last_used_at = datetime.now()
            self.store.save(secret)
            return True

        # Increment failed attempts
        secret.failed_attempts += 1
        if secret.failed_attempts >= self.max_attempts:
            secret.locked_until = datetime.now() + timedelta(seconds=self.lockout_duration)
            logger.warning(f"TOTP locked for user {user_id} after {self.max_attempts} failed attempts")

        self.store.save(secret)
        return False

    def _verify_code(self, secret: TOTPSecret, code: str) -> bool:
        """Verify code against secret.

        Args:
            secret: TOTP secret
            code: Code to verify

        Returns:
            True if valid
        """
        now = int(time.time())

        # Check code in time window
        for offset in range(-self.window, self.window + 1):
            timestamp = now + (offset * secret.period)
            expected = TOTPGenerator.generate(
                secret=secret.secret_bytes,
                timestamp=timestamp,
                period=secret.period,
                digits=secret.digits,
                algorithm=secret.algorithm,
            )

            if hmac.compare_digest(code, expected):
                return True

        return False

    def disable(self, user_id: str) -> bool:
        """Disable TOTP for user.

        Args:
            user_id: User ID

        Returns:
            True if disabled
        """
        secret = self.store.get_by_user(user_id)
        if not secret:
            return False

        secret.status = TOTPStatus.DISABLED
        self.store.save(secret)
        logger.info(f"TOTP disabled for user {user_id}")
        return True

    def revoke(self, user_id: str) -> bool:
        """Revoke TOTP for user (admin action).

        Args:
            user_id: User ID

        Returns:
            True if revoked
        """
        secret = self.store.get_by_user(user_id)
        if not secret:
            return False

        secret.status = TOTPStatus.REVOKED
        self.store.save(secret)
        logger.info(f"TOTP revoked for user {user_id}")
        return True

    def reset(self, user_id: str) -> bool:
        """Reset TOTP for user (delete and allow new setup).

        Args:
            user_id: User ID

        Returns:
            True if reset
        """
        result = self.store.delete_by_user(user_id)
        if result:
            logger.info(f"TOTP reset for user {user_id}")
        return result

    def is_enabled(self, user_id: str) -> bool:
        """Check if TOTP is enabled for user.

        Args:
            user_id: User ID

        Returns:
            True if enabled
        """
        secret = self.store.get_by_user(user_id)
        return secret is not None and secret.status == TOTPStatus.ACTIVE

    def get_secret_info(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get TOTP secret info (without secret itself).

        Args:
            user_id: User ID

        Returns:
            Secret info or None
        """
        secret = self.store.get_by_user(user_id)
        if not secret:
            return None
        return secret.to_dict()

    def generate_current_code(self, user_id: str) -> Optional[str]:
        """Generate current code (for testing/debug only).

        Args:
            user_id: User ID

        Returns:
            Current code or None
        """
        secret = self.store.get_by_user(user_id)
        if not secret or not secret.is_active:
            return None

        return TOTPGenerator.generate(
            secret=secret.secret_bytes,
            period=secret.period,
            digits=secret.digits,
            algorithm=secret.algorithm,
        )

    def unlock(self, user_id: str) -> bool:
        """Unlock TOTP for user (admin action).

        Args:
            user_id: User ID

        Returns:
            True if unlocked
        """
        secret = self.store.get_by_user(user_id)
        if not secret:
            return False

        secret.locked_until = None
        secret.failed_attempts = 0
        self.store.save(secret)
        logger.info(f"TOTP unlocked for user {user_id}")
        return True


__all__ = [
    "TOTPManager",
    "TOTPSecret",
    "TOTPGenerator",
    "TOTPAlgorithm",
    "TOTPStatus",
    "TOTPStore",
]
