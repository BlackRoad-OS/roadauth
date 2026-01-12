"""RoadAuth Backup Codes - Recovery Code Management.

Provides backup/recovery codes for MFA:
- One-time use codes
- Secure generation
- Hashed storage
- Rate limiting
- Regeneration support

Backup codes provide a fallback when the primary MFA method
is unavailable (lost phone, broken authenticator, etc.)

Copyright (c) 2024-2026 BlackRoad OS, Inc. All rights reserved.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

# Configure logging
logger = logging.getLogger(__name__)


class BackupCodeStatus(Enum):
    """Backup code status."""

    ACTIVE = "active"
    USED = "used"
    EXPIRED = "expired"
    REVOKED = "revoked"


@dataclass
class BackupCode:
    """Single backup code."""

    id: str
    user_id: str
    code_hash: str
    status: BackupCodeStatus = BackupCodeStatus.ACTIVE

    # Timestamps
    created_at: datetime = field(default_factory=datetime.now)
    used_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None

    # Usage info
    used_ip: Optional[str] = None
    used_user_agent: Optional[str] = None

    @classmethod
    def create(
        cls,
        user_id: str,
        expires_in: Optional[int] = None,
    ) -> Tuple[BackupCode, str]:
        """Create a new backup code.

        Args:
            user_id: User ID
            expires_in: Optional expiration in seconds

        Returns:
            (BackupCode, plaintext_code)
        """
        # Generate code (format: XXXX-XXXX-XXXX)
        parts = [
            secrets.token_hex(2).upper()
            for _ in range(3)
        ]
        plaintext_code = "-".join(parts)

        # Hash code for storage
        code_hash = cls._hash_code(plaintext_code)

        # Calculate expiration
        expires_at = None
        if expires_in:
            expires_at = datetime.now() + timedelta(seconds=expires_in)

        code = cls(
            id=secrets.token_urlsafe(8),
            user_id=user_id,
            code_hash=code_hash,
            expires_at=expires_at,
        )

        return code, plaintext_code

    @staticmethod
    def _hash_code(code: str) -> str:
        """Hash code for secure storage."""
        # Normalize code (remove dashes, uppercase)
        normalized = code.replace("-", "").upper()
        return hashlib.sha256(normalized.encode()).hexdigest()

    def verify(self, plaintext_code: str) -> bool:
        """Verify plaintext code matches hash.

        Args:
            plaintext_code: Plaintext code to verify

        Returns:
            True if matches
        """
        expected_hash = self._hash_code(plaintext_code)
        return hmac.compare_digest(self.code_hash, expected_hash)

    @property
    def is_expired(self) -> bool:
        """Check if code is expired."""
        if self.expires_at is None:
            return False
        return datetime.now() > self.expires_at

    @property
    def is_valid(self) -> bool:
        """Check if code is valid for use."""
        return (
            self.status == BackupCodeStatus.ACTIVE
            and not self.is_expired
        )

    def mark_used(self, ip: Optional[str] = None, user_agent: Optional[str] = None) -> None:
        """Mark code as used."""
        self.status = BackupCodeStatus.USED
        self.used_at = datetime.now()
        self.used_ip = ip
        self.used_user_agent = user_agent


@dataclass
class BackupCodeSet:
    """Set of backup codes for a user."""

    user_id: str
    codes: List[BackupCode] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)

    # Metadata
    total_generated: int = 0
    total_used: int = 0
    generation_count: int = 0  # How many times regenerated

    @property
    def remaining_codes(self) -> int:
        """Get count of remaining valid codes."""
        return sum(1 for c in self.codes if c.is_valid)

    @property
    def used_codes(self) -> int:
        """Get count of used codes."""
        return sum(1 for c in self.codes if c.status == BackupCodeStatus.USED)

    def get_valid_codes(self) -> List[BackupCode]:
        """Get all valid codes."""
        return [c for c in self.codes if c.is_valid]


class BackupCodeStore:
    """In-memory backup code store."""

    def __init__(self):
        """Initialize store."""
        self._code_sets: Dict[str, BackupCodeSet] = {}
        self._codes: Dict[str, BackupCode] = {}
        self._lock = threading.RLock()

    def save_code_set(self, code_set: BackupCodeSet) -> bool:
        """Save code set."""
        with self._lock:
            self._code_sets[code_set.user_id] = code_set
            for code in code_set.codes:
                self._codes[code.id] = code
            return True

    def get_code_set(self, user_id: str) -> Optional[BackupCodeSet]:
        """Get code set for user."""
        return self._code_sets.get(user_id)

    def get_code(self, code_id: str) -> Optional[BackupCode]:
        """Get code by ID."""
        return self._codes.get(code_id)

    def find_code_by_hash(self, user_id: str, code_hash: str) -> Optional[BackupCode]:
        """Find code by hash."""
        code_set = self._code_sets.get(user_id)
        if not code_set:
            return None

        for code in code_set.codes:
            if code.code_hash == code_hash:
                return code
        return None

    def update_code(self, code: BackupCode) -> bool:
        """Update code."""
        with self._lock:
            if code.id in self._codes:
                self._codes[code.id] = code
                return True
            return False

    def delete_code_set(self, user_id: str) -> bool:
        """Delete code set for user."""
        with self._lock:
            code_set = self._code_sets.get(user_id)
            if code_set:
                for code in code_set.codes:
                    if code.id in self._codes:
                        del self._codes[code.id]
                del self._code_sets[user_id]
                return True
            return False


class BackupCodesManager:
    """Manages backup codes for MFA recovery."""

    def __init__(
        self,
        store: Optional[BackupCodeStore] = None,
        num_codes: int = 10,
        code_expiry: Optional[int] = None,  # Codes don't expire by default
        max_attempts: int = 5,
        lockout_duration: int = 300,  # 5 minutes
        regeneration_limit: int = 10,  # Max regenerations
    ):
        """Initialize backup codes manager.

        Args:
            store: Backup code store
            num_codes: Number of codes to generate
            code_expiry: Optional code expiry in seconds
            max_attempts: Max failed attempts before lockout
            lockout_duration: Lockout duration in seconds
            regeneration_limit: Maximum code regenerations
        """
        self.store = store or BackupCodeStore()
        self.num_codes = num_codes
        self.code_expiry = code_expiry
        self.max_attempts = max_attempts
        self.lockout_duration = lockout_duration
        self.regeneration_limit = regeneration_limit

        # Rate limiting
        self._failed_attempts: Dict[str, int] = {}
        self._lockouts: Dict[str, datetime] = {}
        self._lock = threading.RLock()

    def generate(self, user_id: str) -> Tuple[BackupCodeSet, List[str]]:
        """Generate backup codes for user.

        Args:
            user_id: User ID

        Returns:
            (BackupCodeSet, list_of_plaintext_codes)
        """
        # Check regeneration limit
        existing = self.store.get_code_set(user_id)
        if existing and existing.generation_count >= self.regeneration_limit:
            raise ValueError("Regeneration limit exceeded")

        # Generate codes
        codes = []
        plaintext_codes = []

        for _ in range(self.num_codes):
            code, plaintext = BackupCode.create(
                user_id=user_id,
                expires_in=self.code_expiry,
            )
            codes.append(code)
            plaintext_codes.append(plaintext)

        # Create code set
        code_set = BackupCodeSet(
            user_id=user_id,
            codes=codes,
            total_generated=len(codes),
            generation_count=(existing.generation_count + 1) if existing else 1,
        )

        # Save code set
        self.store.save_code_set(code_set)

        logger.info(f"Generated {len(codes)} backup codes for user {user_id}")
        return code_set, plaintext_codes

    def regenerate(self, user_id: str) -> Tuple[BackupCodeSet, List[str]]:
        """Regenerate backup codes (invalidates old codes).

        Args:
            user_id: User ID

        Returns:
            (BackupCodeSet, list_of_plaintext_codes)
        """
        # Delete existing codes
        self.store.delete_code_set(user_id)

        # Generate new codes
        return self.generate(user_id)

    def verify(
        self,
        user_id: str,
        code: str,
        ip: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> bool:
        """Verify a backup code.

        Args:
            user_id: User ID
            code: Backup code to verify
            ip: Client IP address
            user_agent: Client user agent

        Returns:
            True if valid
        """
        # Check lockout
        if self._is_locked_out(user_id):
            logger.warning(f"Backup codes locked for user {user_id}")
            return False

        # Get code set
        code_set = self.store.get_code_set(user_id)
        if not code_set:
            self._record_failed_attempt(user_id)
            return False

        # Find matching code
        code_hash = BackupCode._hash_code(code)

        for backup_code in code_set.codes:
            if backup_code.is_valid and backup_code.verify(code):
                # Mark code as used
                backup_code.mark_used(ip=ip, user_agent=user_agent)
                self.store.update_code(backup_code)

                # Update code set stats
                code_set.total_used += 1
                self.store.save_code_set(code_set)

                # Reset failed attempts
                self._reset_failed_attempts(user_id)

                logger.info(f"Backup code used for user {user_id}")
                return True

        # Code not found or already used
        self._record_failed_attempt(user_id)
        return False

    def get_remaining_count(self, user_id: str) -> int:
        """Get count of remaining valid codes.

        Args:
            user_id: User ID

        Returns:
            Number of remaining codes
        """
        code_set = self.store.get_code_set(user_id)
        if not code_set:
            return 0
        return code_set.remaining_codes

    def get_status(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get backup codes status.

        Args:
            user_id: User ID

        Returns:
            Status info or None
        """
        code_set = self.store.get_code_set(user_id)
        if not code_set:
            return None

        return {
            "user_id": user_id,
            "total_codes": len(code_set.codes),
            "remaining_codes": code_set.remaining_codes,
            "used_codes": code_set.used_codes,
            "created_at": code_set.created_at.isoformat(),
            "generation_count": code_set.generation_count,
            "codes": [
                {
                    "id": c.id,
                    "status": c.status.value,
                    "created_at": c.created_at.isoformat(),
                    "used_at": c.used_at.isoformat() if c.used_at else None,
                }
                for c in code_set.codes
            ],
        }

    def revoke_all(self, user_id: str) -> bool:
        """Revoke all backup codes for user.

        Args:
            user_id: User ID

        Returns:
            True if revoked
        """
        code_set = self.store.get_code_set(user_id)
        if not code_set:
            return False

        for code in code_set.codes:
            if code.status == BackupCodeStatus.ACTIVE:
                code.status = BackupCodeStatus.REVOKED
                self.store.update_code(code)

        logger.info(f"Revoked all backup codes for user {user_id}")
        return True

    def delete(self, user_id: str) -> bool:
        """Delete all backup codes for user.

        Args:
            user_id: User ID

        Returns:
            True if deleted
        """
        result = self.store.delete_code_set(user_id)
        if result:
            logger.info(f"Deleted backup codes for user {user_id}")
        return result

    def has_codes(self, user_id: str) -> bool:
        """Check if user has backup codes.

        Args:
            user_id: User ID

        Returns:
            True if has codes
        """
        return self.get_remaining_count(user_id) > 0

    def should_regenerate(self, user_id: str, threshold: int = 2) -> bool:
        """Check if user should regenerate codes.

        Args:
            user_id: User ID
            threshold: Minimum remaining codes

        Returns:
            True if should regenerate
        """
        remaining = self.get_remaining_count(user_id)
        return remaining <= threshold

    def _is_locked_out(self, user_id: str) -> bool:
        """Check if user is locked out."""
        with self._lock:
            lockout_until = self._lockouts.get(user_id)
            if lockout_until and datetime.now() < lockout_until:
                return True
            return False

    def _record_failed_attempt(self, user_id: str) -> None:
        """Record failed verification attempt."""
        with self._lock:
            attempts = self._failed_attempts.get(user_id, 0) + 1
            self._failed_attempts[user_id] = attempts

            if attempts >= self.max_attempts:
                self._lockouts[user_id] = datetime.now() + timedelta(
                    seconds=self.lockout_duration
                )
                logger.warning(f"Backup codes locked for user {user_id}")

    def _reset_failed_attempts(self, user_id: str) -> None:
        """Reset failed attempts counter."""
        with self._lock:
            self._failed_attempts.pop(user_id, None)
            self._lockouts.pop(user_id, None)

    def unlock(self, user_id: str) -> bool:
        """Unlock backup codes for user (admin action).

        Args:
            user_id: User ID

        Returns:
            True if unlocked
        """
        with self._lock:
            was_locked = user_id in self._lockouts
            self._failed_attempts.pop(user_id, None)
            self._lockouts.pop(user_id, None)

            if was_locked:
                logger.info(f"Backup codes unlocked for user {user_id}")
            return was_locked


class BackupCodeFormatter:
    """Formats backup codes for display."""

    @staticmethod
    def format_code(code: str) -> str:
        """Format code for display.

        Args:
            code: Plaintext code

        Returns:
            Formatted code
        """
        # Already formatted as XXXX-XXXX-XXXX
        return code

    @staticmethod
    def format_codes_for_download(codes: List[str], username: str) -> str:
        """Format codes for download as text file.

        Args:
            codes: List of plaintext codes
            username: Username

        Returns:
            Formatted text content
        """
        lines = [
            "RoadAuth Backup Codes",
            f"User: {username}",
            f"Generated: {datetime.now().isoformat()}",
            "",
            "IMPORTANT: Keep these codes in a safe place.",
            "Each code can only be used once.",
            "",
            "Codes:",
            "-" * 20,
        ]

        for i, code in enumerate(codes, 1):
            lines.append(f"{i:2}. {code}")

        lines.extend([
            "-" * 20,
            "",
            "If you lose access to your authenticator app,",
            "use one of these codes to sign in.",
        ])

        return "\n".join(lines)

    @staticmethod
    def format_codes_for_print(codes: List[str], username: str) -> str:
        """Format codes for printing.

        Args:
            codes: List of plaintext codes
            username: Username

        Returns:
            Formatted HTML content
        """
        code_items = "\n".join(
            f"<li><code>{code}</code></li>"
            for code in codes
        )

        return f"""
        <html>
        <head>
            <title>Backup Codes - {username}</title>
            <style>
                body {{ font-family: monospace; padding: 20px; }}
                h1 {{ font-size: 18px; }}
                ul {{ list-style: none; padding: 0; }}
                li {{ margin: 10px 0; }}
                code {{ font-size: 16px; background: #f0f0f0; padding: 5px 10px; }}
            </style>
        </head>
        <body>
            <h1>RoadAuth Backup Codes</h1>
            <p>User: {username}</p>
            <p>Generated: {datetime.now().isoformat()}</p>
            <ul>{code_items}</ul>
            <p><small>Each code can only be used once.</small></p>
        </body>
        </html>
        """


__all__ = [
    "BackupCode",
    "BackupCodeSet",
    "BackupCodeStatus",
    "BackupCodeStore",
    "BackupCodesManager",
    "BackupCodeFormatter",
]
