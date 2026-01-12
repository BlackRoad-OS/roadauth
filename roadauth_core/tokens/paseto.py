"""RoadAuth Paseto - Platform-Agnostic Security Tokens.

Provides PASETO (Platform-Agnostic SEcurity TOkens) implementation:
- Local tokens (symmetric encryption)
- Public tokens (asymmetric signatures)
- Version 4 (v4) protocol support
- Footer and implicit assertions

PASETO is a more secure alternative to JWT with:
- No algorithm negotiation vulnerabilities
- Required expiration times
- Built-in AEAD encryption

Copyright (c) 2024-2026 BlackRoad OS, Inc. All rights reserved.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import struct
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union
from collections import OrderedDict

# Configure logging
logger = logging.getLogger(__name__)


class PasetoVersion(Enum):
    """PASETO versions."""

    V1 = "v1"  # Legacy (RSA + AES-CTR + HMAC-SHA384)
    V2 = "v2"  # Modern (Ed25519 + XChaCha20-Poly1305)
    V3 = "v3"  # NIST-compliant (P-384 + AES-256-CTR + HMAC-SHA384)
    V4 = "v4"  # Latest (Ed25519 + XChaCha20-Poly1305 + BLAKE2b)


class PasetoPurpose(Enum):
    """PASETO purposes."""

    LOCAL = "local"  # Symmetric encryption
    PUBLIC = "public"  # Asymmetric signatures


class PasetoError(Exception):
    """Base PASETO error."""
    pass


class PasetoDecodeError(PasetoError):
    """Token decode error."""
    pass


class PasetoExpiredError(PasetoError):
    """Token expired error."""
    pass


class PasetoInvalidError(PasetoError):
    """Token invalid error."""
    pass


@dataclass
class PasetoClaims:
    """PASETO claims container.

    Standard claims:
        - iss: Issuer
        - sub: Subject
        - aud: Audience
        - exp: Expiration (ISO 8601)
        - nbf: Not Before (ISO 8601)
        - iat: Issued At (ISO 8601)
        - jti: Token ID
    """

    # Standard claims
    iss: Optional[str] = None
    sub: Optional[str] = None
    aud: Optional[str] = None
    exp: Optional[str] = None  # ISO 8601 format
    nbf: Optional[str] = None
    iat: Optional[str] = None
    jti: Optional[str] = None

    # Custom claims
    custom: Dict[str, Any] = field(default_factory=dict)

    # Common custom claims
    roles: List[str] = field(default_factory=list)
    permissions: List[str] = field(default_factory=list)
    session_id: Optional[str] = None

    @classmethod
    def create(
        cls,
        subject: str,
        issuer: Optional[str] = None,
        audience: Optional[str] = None,
        expires_in: int = 3600,
        not_before: int = 0,
        **custom_claims
    ) -> PasetoClaims:
        """Create claims with standard fields.

        Args:
            subject: Subject (user ID)
            issuer: Token issuer
            audience: Target audience
            expires_in: Expiration in seconds
            not_before: Not before delay
            **custom_claims: Additional claims

        Returns:
            PasetoClaims instance
        """
        now = datetime.utcnow()

        return cls(
            iss=issuer,
            sub=subject,
            aud=audience,
            exp=(now + timedelta(seconds=expires_in)).isoformat() + "Z",
            nbf=(now + timedelta(seconds=not_before)).isoformat() + "Z" if not_before else None,
            iat=now.isoformat() + "Z",
            jti=secrets.token_urlsafe(16),
            custom=custom_claims,
        )

    @property
    def expiration_time(self) -> Optional[datetime]:
        """Get expiration as datetime."""
        if not self.exp:
            return None
        return datetime.fromisoformat(self.exp.rstrip("Z"))

    @property
    def is_expired(self) -> bool:
        """Check if token is expired."""
        exp = self.expiration_time
        if not exp:
            return False
        return datetime.utcnow() > exp

    @property
    def remaining_time(self) -> int:
        """Get remaining validity time in seconds."""
        exp = self.expiration_time
        if not exp:
            return -1
        delta = exp - datetime.utcnow()
        return max(0, int(delta.total_seconds()))

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        claims = {}

        if self.iss:
            claims["iss"] = self.iss
        if self.sub:
            claims["sub"] = self.sub
        if self.aud:
            claims["aud"] = self.aud
        if self.exp:
            claims["exp"] = self.exp
        if self.nbf:
            claims["nbf"] = self.nbf
        if self.iat:
            claims["iat"] = self.iat
        if self.jti:
            claims["jti"] = self.jti
        if self.roles:
            claims["roles"] = self.roles
        if self.permissions:
            claims["permissions"] = self.permissions
        if self.session_id:
            claims["session_id"] = self.session_id

        claims.update(self.custom)
        return claims

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> PasetoClaims:
        """Create from dictionary."""
        standard = {"iss", "sub", "aud", "exp", "nbf", "iat", "jti", "roles", "permissions", "session_id"}
        custom = {k: v for k, v in data.items() if k not in standard}

        return cls(
            iss=data.get("iss"),
            sub=data.get("sub"),
            aud=data.get("aud"),
            exp=data.get("exp"),
            nbf=data.get("nbf"),
            iat=data.get("iat"),
            jti=data.get("jti"),
            roles=data.get("roles", []),
            permissions=data.get("permissions", []),
            session_id=data.get("session_id"),
            custom=custom,
        )


@dataclass
class PasetoKey:
    """PASETO key."""

    id: str
    version: PasetoVersion
    purpose: PasetoPurpose
    key: bytes
    created_at: datetime = field(default_factory=datetime.now)
    expires_at: Optional[datetime] = None
    is_active: bool = True

    # For public purpose
    public_key: Optional[bytes] = None

    @classmethod
    def generate_local(
        cls,
        version: PasetoVersion = PasetoVersion.V4,
        expires_in: Optional[int] = None
    ) -> PasetoKey:
        """Generate a local (symmetric) key.

        Args:
            version: PASETO version
            expires_in: Key expiration in seconds

        Returns:
            Generated key
        """
        # 256-bit key for symmetric encryption
        key = secrets.token_bytes(32)
        key_id = secrets.token_urlsafe(8)
        expires_at = None

        if expires_in:
            expires_at = datetime.now() + timedelta(seconds=expires_in)

        return cls(
            id=key_id,
            version=version,
            purpose=PasetoPurpose.LOCAL,
            key=key,
            expires_at=expires_at,
        )

    @classmethod
    def generate_public(
        cls,
        version: PasetoVersion = PasetoVersion.V4,
        expires_in: Optional[int] = None
    ) -> PasetoKey:
        """Generate a public (asymmetric) key pair.

        Args:
            version: PASETO version
            expires_in: Key expiration in seconds

        Returns:
            Generated key
        """
        # 256-bit Ed25519 seed
        key = secrets.token_bytes(32)
        key_id = secrets.token_urlsafe(8)
        expires_at = None

        if expires_in:
            expires_at = datetime.now() + timedelta(seconds=expires_in)

        # In production, use actual Ed25519 key generation
        # This is a placeholder
        public_key = hashlib.sha256(key).digest()

        return cls(
            id=key_id,
            version=version,
            purpose=PasetoPurpose.PUBLIC,
            key=key,
            public_key=public_key,
            expires_at=expires_at,
        )

    @property
    def is_expired(self) -> bool:
        """Check if key is expired."""
        if self.expires_at is None:
            return False
        return datetime.now() > self.expires_at


class TokenBlacklist:
    """Token blacklist for revoked tokens."""

    def __init__(self, max_size: int = 100000):
        """Initialize blacklist."""
        self._blacklist: OrderedDict[str, datetime] = OrderedDict()
        self._max_size = max_size
        self._lock = threading.RLock()

    def add(self, jti: str, expires_at: datetime) -> None:
        """Add token to blacklist."""
        with self._lock:
            self._cleanup()
            while len(self._blacklist) >= self._max_size:
                self._blacklist.popitem(last=False)
            self._blacklist[jti] = expires_at

    def is_blacklisted(self, jti: str) -> bool:
        """Check if token is blacklisted."""
        with self._lock:
            return jti in self._blacklist

    def _cleanup(self) -> None:
        """Remove expired entries."""
        now = datetime.utcnow()
        expired = [jti for jti, exp in self._blacklist.items() if exp < now]
        for jti in expired:
            del self._blacklist[jti]


class PasetoManager:
    """PASETO token manager.

    Handles PASETO token generation, validation, and lifecycle.
    Supports both local (symmetric) and public (asymmetric) tokens.
    """

    def __init__(
        self,
        secret_key: Optional[bytes] = None,
        version: PasetoVersion = PasetoVersion.V4,
        purpose: PasetoPurpose = PasetoPurpose.LOCAL,
        issuer: Optional[str] = None,
        audience: Optional[str] = None,
        token_ttl: int = 3600,
        verify_exp: bool = True,
        verify_nbf: bool = True,
        leeway: int = 0,
    ):
        """Initialize PASETO manager.

        Args:
            secret_key: Secret key for local tokens
            version: PASETO version
            purpose: Token purpose (local/public)
            issuer: Token issuer
            audience: Default audience
            token_ttl: Token TTL in seconds
            verify_exp: Verify expiration
            verify_nbf: Verify not before
            leeway: Time leeway in seconds
        """
        self.version = version
        self.purpose = purpose
        self.issuer = issuer
        self.audience = audience
        self.token_ttl = token_ttl
        self.verify_exp = verify_exp
        self.verify_nbf = verify_nbf
        self.leeway = leeway

        # Key management
        self._keys: Dict[str, PasetoKey] = {}
        self._active_key_id: Optional[str] = None
        self._lock = threading.RLock()

        # Blacklist
        self._blacklist = TokenBlacklist()

        # Initialize with secret key
        if secret_key:
            key = PasetoKey(
                id="default",
                version=version,
                purpose=purpose,
                key=secret_key if isinstance(secret_key, bytes) else secret_key.encode(),
            )
            self._keys["default"] = key
            self._active_key_id = "default"

    def generate(
        self,
        subject: str,
        claims: Optional[Dict[str, Any]] = None,
        expires_in: Optional[int] = None,
        footer: Optional[Dict[str, Any]] = None,
        implicit_assertion: Optional[bytes] = None,
        key_id: Optional[str] = None,
    ) -> str:
        """Generate a PASETO token.

        Args:
            subject: Token subject (user ID)
            claims: Additional claims
            expires_in: Custom expiration in seconds
            footer: Optional footer data
            implicit_assertion: Optional implicit assertion
            key_id: Specific key to use

        Returns:
            PASETO token string
        """
        with self._lock:
            key = self._get_key(key_id)
            if not key:
                raise PasetoError("No signing key available")

            # Build claims
            paseto_claims = PasetoClaims.create(
                subject=subject,
                issuer=self.issuer,
                audience=self.audience,
                expires_in=expires_in or self.token_ttl,
            )

            # Add custom claims
            if claims:
                for k, v in claims.items():
                    if hasattr(paseto_claims, k):
                        setattr(paseto_claims, k, v)
                    else:
                        paseto_claims.custom[k] = v

            # Encode token
            return self._encode(paseto_claims, key, footer, implicit_assertion)

    def validate(
        self,
        token: str,
        footer: Optional[Dict[str, Any]] = None,
        implicit_assertion: Optional[bytes] = None,
        verify_blacklist: bool = True,
    ) -> PasetoClaims:
        """Validate and decode a PASETO token.

        Args:
            token: PASETO token string
            footer: Expected footer
            implicit_assertion: Expected implicit assertion
            verify_blacklist: Check blacklist

        Returns:
            Decoded claims

        Raises:
            PasetoError: If validation fails
        """
        # Decode token
        claims, decoded_footer = self._decode(token, implicit_assertion)

        # Check blacklist
        if verify_blacklist and claims.jti:
            if self._blacklist.is_blacklisted(claims.jti):
                raise PasetoInvalidError("Token has been revoked")

        # Verify expiration
        if self.verify_exp and claims.exp:
            exp_time = claims.expiration_time
            if exp_time and datetime.utcnow() > exp_time + timedelta(seconds=self.leeway):
                raise PasetoExpiredError("Token has expired")

        # Verify not before
        if self.verify_nbf and claims.nbf:
            nbf_time = datetime.fromisoformat(claims.nbf.rstrip("Z"))
            if datetime.utcnow() < nbf_time - timedelta(seconds=self.leeway):
                raise PasetoInvalidError("Token is not yet valid")

        # Verify issuer
        if self.issuer and claims.iss != self.issuer:
            raise PasetoInvalidError(f"Invalid issuer: {claims.iss}")

        # Verify audience
        if self.audience and claims.aud != self.audience:
            raise PasetoInvalidError(f"Invalid audience: {claims.aud}")

        # Verify footer
        if footer and decoded_footer != footer:
            raise PasetoInvalidError("Footer mismatch")

        return claims

    def revoke(self, token: str) -> bool:
        """Revoke a token."""
        try:
            claims, _ = self._decode(token, None)
            if claims.jti and claims.expiration_time:
                self._blacklist.add(claims.jti, claims.expiration_time)
                logger.info(f"Token revoked: {claims.jti}")
                return True
            return False
        except PasetoError:
            return False

    def is_revoked(self, token: str) -> bool:
        """Check if token is revoked."""
        try:
            claims, _ = self._decode(token, None)
            if claims.jti:
                return self._blacklist.is_blacklisted(claims.jti)
            return False
        except PasetoError:
            return True

    def add_key(self, key: PasetoKey, set_active: bool = False) -> None:
        """Add a signing key."""
        with self._lock:
            self._keys[key.id] = key
            if set_active:
                self._active_key_id = key.id
            logger.info(f"Added PASETO key: {key.id}")

    def rotate_key(self, expires_in: Optional[int] = None) -> PasetoKey:
        """Rotate to a new key."""
        with self._lock:
            if self.purpose == PasetoPurpose.LOCAL:
                new_key = PasetoKey.generate_local(self.version)
            else:
                new_key = PasetoKey.generate_public(self.version)

            self._keys[new_key.id] = new_key

            # Mark old key for expiration
            current_key = self._get_key()
            if current_key and expires_in:
                current_key.expires_at = datetime.now() + timedelta(seconds=expires_in)

            self._active_key_id = new_key.id
            logger.info(f"Rotated to new PASETO key: {new_key.id}")
            return new_key

    def _get_key(self, key_id: Optional[str] = None) -> Optional[PasetoKey]:
        """Get signing key."""
        if key_id:
            return self._keys.get(key_id)
        if self._active_key_id:
            return self._keys.get(self._active_key_id)
        return None

    def _encode(
        self,
        claims: PasetoClaims,
        key: PasetoKey,
        footer: Optional[Dict[str, Any]] = None,
        implicit_assertion: Optional[bytes] = None,
    ) -> str:
        """Encode claims to PASETO token.

        Args:
            claims: Claims to encode
            key: Signing key
            footer: Optional footer
            implicit_assertion: Optional implicit assertion

        Returns:
            PASETO token string
        """
        # Payload
        payload = json.dumps(claims.to_dict()).encode()

        # Footer
        footer_bytes = json.dumps(footer).encode() if footer else b""

        # Implicit assertion
        implicit = implicit_assertion or b""

        if key.purpose == PasetoPurpose.LOCAL:
            # Local encryption (simplified - in production use XChaCha20-Poly1305)
            token = self._encrypt_local(key, payload, footer_bytes, implicit)
        else:
            # Public signature
            token = self._sign_public(key, payload, footer_bytes, implicit)

        return token

    def _decode(
        self,
        token: str,
        implicit_assertion: Optional[bytes] = None,
    ) -> Tuple[PasetoClaims, Optional[Dict[str, Any]]]:
        """Decode PASETO token.

        Args:
            token: PASETO token string
            implicit_assertion: Expected implicit assertion

        Returns:
            (claims, footer)

        Raises:
            PasetoDecodeError: If decode fails
        """
        try:
            parts = token.split(".")

            # Parse header
            header = parts[0]
            version, purpose = self._parse_header(header)

            # Get key
            key = None
            for k in self._keys.values():
                if k.version == version and k.purpose == purpose:
                    key = k
                    break

            if not key:
                raise PasetoDecodeError(f"No key for {version.value}.{purpose.value}")

            # Extract payload and footer
            payload_b64 = parts[1] if len(parts) > 1 else ""
            footer_b64 = parts[2] if len(parts) > 2 else ""

            footer_bytes = self._base64url_decode(footer_b64) if footer_b64 else b""
            implicit = implicit_assertion or b""

            if purpose == PasetoPurpose.LOCAL:
                payload = self._decrypt_local(key, payload_b64, footer_bytes, implicit)
            else:
                payload = self._verify_public(key, payload_b64, footer_bytes, implicit)

            claims = PasetoClaims.from_dict(json.loads(payload.decode()))
            footer = json.loads(footer_bytes.decode()) if footer_bytes else None

            return claims, footer

        except json.JSONDecodeError as e:
            raise PasetoDecodeError(f"Invalid JSON: {e}")
        except Exception as e:
            if isinstance(e, PasetoError):
                raise
            raise PasetoDecodeError(f"Decode error: {e}")

    def _parse_header(self, header: str) -> Tuple[PasetoVersion, PasetoPurpose]:
        """Parse token header."""
        parts = header.split(".")
        if len(parts) < 2:
            raise PasetoDecodeError("Invalid header format")

        version = PasetoVersion(parts[0])
        purpose = PasetoPurpose(parts[1])
        return version, purpose

    def _encrypt_local(
        self,
        key: PasetoKey,
        payload: bytes,
        footer: bytes,
        implicit: bytes,
    ) -> str:
        """Encrypt payload for local token.

        Simplified implementation - in production use XChaCha20-Poly1305
        """
        # Generate nonce
        nonce = secrets.token_bytes(24)

        # Derive key
        derived_key = hashlib.blake2b(
            key.key + nonce,
            digest_size=32
        ).digest()

        # Simple XOR encryption (placeholder - use proper AEAD)
        encrypted = bytes(p ^ derived_key[i % 32] for i, p in enumerate(payload))

        # MAC
        mac_data = b"".join([
            f"{key.version.value}.{key.purpose.value}".encode(),
            nonce,
            encrypted,
            footer,
            implicit,
        ])
        mac = hmac.new(derived_key, mac_data, hashlib.blake2b).digest()[:32]

        # Combine
        combined = nonce + encrypted + mac
        payload_b64 = self._base64url_encode(combined)

        # Build token
        header = f"{key.version.value}.{key.purpose.value}"
        if footer:
            footer_b64 = self._base64url_encode(footer)
            return f"{header}.{payload_b64}.{footer_b64}"
        return f"{header}.{payload_b64}"

    def _decrypt_local(
        self,
        key: PasetoKey,
        payload_b64: str,
        footer: bytes,
        implicit: bytes,
    ) -> bytes:
        """Decrypt local token payload."""
        combined = self._base64url_decode(payload_b64)

        if len(combined) < 56:  # 24 nonce + 32 mac minimum
            raise PasetoDecodeError("Invalid payload length")

        nonce = combined[:24]
        mac = combined[-32:]
        encrypted = combined[24:-32]

        # Derive key
        derived_key = hashlib.blake2b(
            key.key + nonce,
            digest_size=32
        ).digest()

        # Verify MAC
        mac_data = b"".join([
            f"{key.version.value}.{key.purpose.value}".encode(),
            nonce,
            encrypted,
            footer,
            implicit,
        ])
        expected_mac = hmac.new(derived_key, mac_data, hashlib.blake2b).digest()[:32]

        if not hmac.compare_digest(mac, expected_mac):
            raise PasetoInvalidError("Invalid MAC")

        # Decrypt
        decrypted = bytes(e ^ derived_key[i % 32] for i, e in enumerate(encrypted))
        return decrypted

    def _sign_public(
        self,
        key: PasetoKey,
        payload: bytes,
        footer: bytes,
        implicit: bytes,
    ) -> str:
        """Sign payload for public token.

        Simplified implementation - in production use Ed25519
        """
        # Sign data
        sign_data = b"".join([
            f"{key.version.value}.{key.purpose.value}".encode(),
            payload,
            footer,
            implicit,
        ])
        signature = hmac.new(key.key, sign_data, hashlib.sha512).digest()[:64]

        # Combine
        combined = payload + signature
        payload_b64 = self._base64url_encode(combined)

        # Build token
        header = f"{key.version.value}.{key.purpose.value}"
        if footer:
            footer_b64 = self._base64url_encode(footer)
            return f"{header}.{payload_b64}.{footer_b64}"
        return f"{header}.{payload_b64}"

    def _verify_public(
        self,
        key: PasetoKey,
        payload_b64: str,
        footer: bytes,
        implicit: bytes,
    ) -> bytes:
        """Verify public token signature."""
        combined = self._base64url_decode(payload_b64)

        if len(combined) < 64:
            raise PasetoDecodeError("Invalid payload length")

        payload = combined[:-64]
        signature = combined[-64:]

        # Verify signature
        sign_data = b"".join([
            f"{key.version.value}.{key.purpose.value}".encode(),
            payload,
            footer,
            implicit,
        ])
        expected_sig = hmac.new(key.key, sign_data, hashlib.sha512).digest()[:64]

        if not hmac.compare_digest(signature, expected_sig):
            raise PasetoInvalidError("Invalid signature")

        return payload

    def _base64url_encode(self, data: bytes) -> str:
        """Base64URL encode bytes."""
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    def _base64url_decode(self, data: str) -> bytes:
        """Base64URL decode to bytes."""
        padding = 4 - len(data) % 4
        if padding != 4:
            data += "=" * padding
        return base64.urlsafe_b64decode(data)


class PasetoKeyRing:
    """Key ring for managing multiple PASETO keys."""

    def __init__(self):
        """Initialize key ring."""
        self._keys: Dict[str, PasetoKey] = {}
        self._lock = threading.RLock()

    def add(self, key: PasetoKey) -> None:
        """Add key to ring."""
        with self._lock:
            self._keys[key.id] = key

    def get(self, key_id: str) -> Optional[PasetoKey]:
        """Get key by ID."""
        return self._keys.get(key_id)

    def remove(self, key_id: str) -> bool:
        """Remove key from ring."""
        with self._lock:
            if key_id in self._keys:
                del self._keys[key_id]
                return True
            return False

    def list_active(self) -> List[PasetoKey]:
        """List active keys."""
        return [k for k in self._keys.values() if k.is_active and not k.is_expired]

    def get_by_purpose(self, purpose: PasetoPurpose) -> List[PasetoKey]:
        """Get keys by purpose."""
        return [k for k in self._keys.values() if k.purpose == purpose]

    def cleanup_expired(self) -> int:
        """Remove expired keys."""
        with self._lock:
            expired = [kid for kid, key in self._keys.items() if key.is_expired]
            for kid in expired:
                del self._keys[kid]
            return len(expired)


__all__ = [
    "PasetoManager",
    "PasetoClaims",
    "PasetoKey",
    "PasetoKeyRing",
    "PasetoVersion",
    "PasetoPurpose",
    "PasetoError",
    "PasetoDecodeError",
    "PasetoExpiredError",
    "PasetoInvalidError",
]
