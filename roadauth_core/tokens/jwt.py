"""RoadAuth JWT - JSON Web Token Management.

Provides comprehensive JWT handling including:
- Token generation with multiple algorithms
- Token validation and verification
- Claim management
- Key rotation support
- Token blacklisting

Copyright (c) 2024-2026 BlackRoad OS, Inc. All rights reserved.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import secrets
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from collections import OrderedDict

# Configure logging
logger = logging.getLogger(__name__)


class JWTAlgorithm(Enum):
    """Supported JWT algorithms."""

    # HMAC
    HS256 = "HS256"
    HS384 = "HS384"
    HS512 = "HS512"

    # RSA
    RS256 = "RS256"
    RS384 = "RS384"
    RS512 = "RS512"

    # ECDSA
    ES256 = "ES256"
    ES384 = "ES384"
    ES512 = "ES512"

    # EdDSA
    EdDSA = "EdDSA"

    # None (for testing only)
    NONE = "none"


class JWTError(Exception):
    """Base JWT error."""
    pass


class JWTDecodeError(JWTError):
    """Token decode error."""
    pass


class JWTExpiredError(JWTError):
    """Token expired error."""
    pass


class JWTInvalidError(JWTError):
    """Token invalid error."""
    pass


class JWTBlacklistedError(JWTError):
    """Token blacklisted error."""
    pass


@dataclass
class JWTClaims:
    """JWT claims container.

    Standard claims (RFC 7519):
        - iss: Issuer
        - sub: Subject
        - aud: Audience
        - exp: Expiration Time
        - nbf: Not Before
        - iat: Issued At
        - jti: JWT ID
    """

    # Standard claims
    iss: Optional[str] = None  # Issuer
    sub: Optional[str] = None  # Subject (typically user ID)
    aud: Optional[Union[str, List[str]]] = None  # Audience
    exp: Optional[int] = None  # Expiration timestamp
    nbf: Optional[int] = None  # Not before timestamp
    iat: Optional[int] = None  # Issued at timestamp
    jti: Optional[str] = None  # JWT ID

    # Custom claims
    custom: Dict[str, Any] = field(default_factory=dict)

    # Common custom claims
    roles: List[str] = field(default_factory=list)
    permissions: List[str] = field(default_factory=list)
    scope: Optional[str] = None
    email: Optional[str] = None
    name: Optional[str] = None

    # Session binding
    session_id: Optional[str] = None
    device_id: Optional[str] = None

    # Security flags
    mfa_verified: bool = False
    email_verified: bool = False

    @classmethod
    def create(
        cls,
        subject: str,
        issuer: Optional[str] = None,
        audience: Optional[Union[str, List[str]]] = None,
        expires_in: int = 3600,
        not_before: int = 0,
        **custom_claims
    ) -> JWTClaims:
        """Create claims with standard fields populated.

        Args:
            subject: Subject (user ID)
            issuer: Token issuer
            audience: Target audience
            expires_in: Expiration in seconds
            not_before: Not before delay in seconds
            **custom_claims: Additional custom claims

        Returns:
            JWTClaims instance
        """
        now = int(time.time())

        return cls(
            iss=issuer,
            sub=subject,
            aud=audience,
            exp=now + expires_in,
            nbf=now + not_before,
            iat=now,
            jti=secrets.token_urlsafe(16),
            custom=custom_claims,
        )

    @property
    def is_expired(self) -> bool:
        """Check if token is expired."""
        if self.exp is None:
            return False
        return int(time.time()) > self.exp

    @property
    def is_not_yet_valid(self) -> bool:
        """Check if token is not yet valid."""
        if self.nbf is None:
            return False
        return int(time.time()) < self.nbf

    @property
    def remaining_time(self) -> int:
        """Get remaining validity time in seconds."""
        if self.exp is None:
            return -1
        return max(0, self.exp - int(time.time()))

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for encoding."""
        claims = {}

        # Add standard claims
        if self.iss:
            claims["iss"] = self.iss
        if self.sub:
            claims["sub"] = self.sub
        if self.aud:
            claims["aud"] = self.aud
        if self.exp is not None:
            claims["exp"] = self.exp
        if self.nbf is not None:
            claims["nbf"] = self.nbf
        if self.iat is not None:
            claims["iat"] = self.iat
        if self.jti:
            claims["jti"] = self.jti

        # Add common custom claims
        if self.roles:
            claims["roles"] = self.roles
        if self.permissions:
            claims["permissions"] = self.permissions
        if self.scope:
            claims["scope"] = self.scope
        if self.email:
            claims["email"] = self.email
        if self.name:
            claims["name"] = self.name
        if self.session_id:
            claims["session_id"] = self.session_id
        if self.device_id:
            claims["device_id"] = self.device_id
        if self.mfa_verified:
            claims["mfa_verified"] = self.mfa_verified
        if self.email_verified:
            claims["email_verified"] = self.email_verified

        # Add additional custom claims
        claims.update(self.custom)

        return claims

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> JWTClaims:
        """Create from dictionary.

        Args:
            data: Claims dictionary

        Returns:
            JWTClaims instance
        """
        # Extract standard claims
        standard = {
            "iss", "sub", "aud", "exp", "nbf", "iat", "jti",
            "roles", "permissions", "scope", "email", "name",
            "session_id", "device_id", "mfa_verified", "email_verified"
        }

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
            scope=data.get("scope"),
            email=data.get("email"),
            name=data.get("name"),
            session_id=data.get("session_id"),
            device_id=data.get("device_id"),
            mfa_verified=data.get("mfa_verified", False),
            email_verified=data.get("email_verified", False),
            custom=custom,
        )


@dataclass
class JWTKey:
    """JWT signing key."""

    id: str
    algorithm: JWTAlgorithm
    secret: bytes
    created_at: datetime = field(default_factory=datetime.now)
    expires_at: Optional[datetime] = None
    is_active: bool = True

    # For asymmetric keys
    public_key: Optional[bytes] = None

    @classmethod
    def generate(
        cls,
        algorithm: JWTAlgorithm = JWTAlgorithm.HS256,
        key_size: int = 32,
        expires_in: Optional[int] = None
    ) -> JWTKey:
        """Generate a new key.

        Args:
            algorithm: Algorithm to use
            key_size: Key size in bytes
            expires_in: Expiration in seconds

        Returns:
            Generated key
        """
        key_id = secrets.token_urlsafe(8)
        secret = secrets.token_bytes(key_size)
        expires_at = None

        if expires_in:
            expires_at = datetime.now() + timedelta(seconds=expires_in)

        return cls(
            id=key_id,
            algorithm=algorithm,
            secret=secret,
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
        """Initialize blacklist.

        Args:
            max_size: Maximum entries to store
        """
        self._blacklist: OrderedDict[str, int] = OrderedDict()
        self._max_size = max_size
        self._lock = threading.RLock()

    def add(self, jti: str, expires_at: int) -> None:
        """Add token to blacklist.

        Args:
            jti: JWT ID
            expires_at: Expiration timestamp
        """
        with self._lock:
            # Clean up expired entries
            self._cleanup()

            # Evict oldest if at capacity
            while len(self._blacklist) >= self._max_size:
                self._blacklist.popitem(last=False)

            self._blacklist[jti] = expires_at

    def is_blacklisted(self, jti: str) -> bool:
        """Check if token is blacklisted.

        Args:
            jti: JWT ID

        Returns:
            True if blacklisted
        """
        with self._lock:
            return jti in self._blacklist

    def remove(self, jti: str) -> bool:
        """Remove from blacklist.

        Args:
            jti: JWT ID

        Returns:
            True if removed
        """
        with self._lock:
            if jti in self._blacklist:
                del self._blacklist[jti]
                return True
            return False

    def _cleanup(self) -> None:
        """Remove expired entries."""
        now = int(time.time())
        expired = [
            jti for jti, exp in self._blacklist.items()
            if exp < now
        ]
        for jti in expired:
            del self._blacklist[jti]

    @property
    def size(self) -> int:
        """Get blacklist size."""
        return len(self._blacklist)


class JWTManager:
    """JWT token manager.

    Handles token generation, validation, and lifecycle management
    with support for key rotation and blacklisting.
    """

    def __init__(
        self,
        secret_key: Optional[str] = None,
        algorithm: JWTAlgorithm = JWTAlgorithm.HS256,
        issuer: Optional[str] = None,
        audience: Optional[str] = None,
        access_token_ttl: int = 3600,
        verify_exp: bool = True,
        verify_nbf: bool = True,
        verify_aud: bool = True,
        verify_iss: bool = True,
        leeway: int = 0,
    ):
        """Initialize JWT manager.

        Args:
            secret_key: Secret key for signing
            algorithm: Default algorithm
            issuer: Token issuer
            audience: Default audience
            access_token_ttl: Access token TTL in seconds
            verify_exp: Verify expiration
            verify_nbf: Verify not before
            verify_aud: Verify audience
            verify_iss: Verify issuer
            leeway: Time leeway in seconds
        """
        self.issuer = issuer
        self.audience = audience
        self.access_token_ttl = access_token_ttl
        self.verify_exp = verify_exp
        self.verify_nbf = verify_nbf
        self.verify_aud = verify_aud
        self.verify_iss = verify_iss
        self.leeway = leeway

        # Key management
        self._keys: Dict[str, JWTKey] = {}
        self._active_key_id: Optional[str] = None
        self._lock = threading.RLock()

        # Blacklist
        self._blacklist = TokenBlacklist()

        # Initialize with secret key
        if secret_key:
            key = JWTKey(
                id="default",
                algorithm=algorithm,
                secret=secret_key.encode() if isinstance(secret_key, str) else secret_key,
            )
            self._keys["default"] = key
            self._active_key_id = "default"

    def generate(
        self,
        subject: str,
        claims: Optional[Dict[str, Any]] = None,
        expires_in: Optional[int] = None,
        algorithm: Optional[JWTAlgorithm] = None,
        key_id: Optional[str] = None,
    ) -> str:
        """Generate a JWT token.

        Args:
            subject: Token subject (user ID)
            claims: Additional claims
            expires_in: Custom expiration in seconds
            algorithm: Algorithm override
            key_id: Specific key to use

        Returns:
            JWT token string
        """
        with self._lock:
            # Get signing key
            key = self._get_key(key_id)
            if not key:
                raise JWTError("No signing key available")

            # Build claims
            jwt_claims = JWTClaims.create(
                subject=subject,
                issuer=self.issuer,
                audience=self.audience,
                expires_in=expires_in or self.access_token_ttl,
            )

            # Add custom claims
            if claims:
                for k, v in claims.items():
                    if hasattr(jwt_claims, k):
                        setattr(jwt_claims, k, v)
                    else:
                        jwt_claims.custom[k] = v

            # Build token
            alg = algorithm or key.algorithm
            return self._encode(jwt_claims, key, alg)

    def validate(
        self,
        token: str,
        verify_blacklist: bool = True,
    ) -> JWTClaims:
        """Validate and decode a JWT token.

        Args:
            token: JWT token string
            verify_blacklist: Check blacklist

        Returns:
            Decoded claims

        Raises:
            JWTError: If validation fails
        """
        # Decode token
        claims = self._decode(token)

        # Check blacklist
        if verify_blacklist and claims.jti:
            if self._blacklist.is_blacklisted(claims.jti):
                raise JWTBlacklistedError("Token has been revoked")

        # Verify expiration
        if self.verify_exp and claims.exp:
            if int(time.time()) > claims.exp + self.leeway:
                raise JWTExpiredError("Token has expired")

        # Verify not before
        if self.verify_nbf and claims.nbf:
            if int(time.time()) < claims.nbf - self.leeway:
                raise JWTInvalidError("Token is not yet valid")

        # Verify issuer
        if self.verify_iss and self.issuer and claims.iss != self.issuer:
            raise JWTInvalidError(f"Invalid issuer: {claims.iss}")

        # Verify audience
        if self.verify_aud and self.audience and claims.aud:
            aud_list = claims.aud if isinstance(claims.aud, list) else [claims.aud]
            if self.audience not in aud_list:
                raise JWTInvalidError(f"Invalid audience: {claims.aud}")

        return claims

    def revoke(self, token: str) -> bool:
        """Revoke a token.

        Args:
            token: JWT token string

        Returns:
            True if revoked
        """
        try:
            claims = self._decode(token)
            if claims.jti and claims.exp:
                self._blacklist.add(claims.jti, claims.exp)
                logger.info(f"Token revoked: {claims.jti}")
                return True
            return False
        except JWTError:
            return False

    def is_revoked(self, token: str) -> bool:
        """Check if token is revoked.

        Args:
            token: JWT token string

        Returns:
            True if revoked
        """
        try:
            claims = self._decode(token)
            if claims.jti:
                return self._blacklist.is_blacklisted(claims.jti)
            return False
        except JWTError:
            return True

    def refresh(self, token: str) -> str:
        """Refresh a token.

        Args:
            token: Current token

        Returns:
            New token

        Raises:
            JWTError: If refresh fails
        """
        claims = self.validate(token)

        # Revoke old token
        self.revoke(token)

        # Generate new token
        return self.generate(
            subject=claims.sub,
            claims=claims.to_dict(),
        )

    def add_key(self, key: JWTKey, set_active: bool = False) -> None:
        """Add a signing key.

        Args:
            key: JWT key
            set_active: Set as active key
        """
        with self._lock:
            self._keys[key.id] = key
            if set_active:
                self._active_key_id = key.id
            logger.info(f"Added JWT key: {key.id}")

    def rotate_key(self, expires_in: Optional[int] = None) -> JWTKey:
        """Rotate to a new key.

        Args:
            expires_in: Old key expiration in seconds

        Returns:
            New key
        """
        with self._lock:
            # Get current algorithm
            current_key = self._get_key()
            algorithm = current_key.algorithm if current_key else JWTAlgorithm.HS256

            # Generate new key
            new_key = JWTKey.generate(algorithm=algorithm)
            self._keys[new_key.id] = new_key

            # Mark old key for expiration
            if current_key and expires_in:
                current_key.expires_at = datetime.now() + timedelta(seconds=expires_in)

            # Set new key as active
            self._active_key_id = new_key.id

            logger.info(f"Rotated to new JWT key: {new_key.id}")
            return new_key

    def remove_key(self, key_id: str) -> bool:
        """Remove a key.

        Args:
            key_id: Key ID

        Returns:
            True if removed
        """
        with self._lock:
            if key_id in self._keys:
                del self._keys[key_id]
                if self._active_key_id == key_id:
                    self._active_key_id = next(iter(self._keys), None)
                logger.info(f"Removed JWT key: {key_id}")
                return True
            return False

    def _get_key(self, key_id: Optional[str] = None) -> Optional[JWTKey]:
        """Get signing key."""
        if key_id:
            return self._keys.get(key_id)
        if self._active_key_id:
            return self._keys.get(self._active_key_id)
        return None

    def _encode(self, claims: JWTClaims, key: JWTKey, algorithm: JWTAlgorithm) -> str:
        """Encode claims to JWT.

        Args:
            claims: Claims to encode
            key: Signing key
            algorithm: Algorithm to use

        Returns:
            JWT string
        """
        # Build header
        header = {
            "alg": algorithm.value,
            "typ": "JWT",
            "kid": key.id,
        }

        # Encode header and payload
        header_b64 = self._base64url_encode(json.dumps(header))
        payload_b64 = self._base64url_encode(json.dumps(claims.to_dict()))

        # Create signature
        message = f"{header_b64}.{payload_b64}"
        signature = self._sign(message.encode(), key, algorithm)
        signature_b64 = self._base64url_encode_bytes(signature)

        return f"{header_b64}.{payload_b64}.{signature_b64}"

    def _decode(self, token: str) -> JWTClaims:
        """Decode JWT to claims.

        Args:
            token: JWT string

        Returns:
            Decoded claims

        Raises:
            JWTDecodeError: If decode fails
        """
        try:
            parts = token.split(".")
            if len(parts) != 3:
                raise JWTDecodeError("Invalid token format")

            header_b64, payload_b64, signature_b64 = parts

            # Decode header
            header = json.loads(self._base64url_decode(header_b64))
            algorithm = JWTAlgorithm(header.get("alg", "HS256"))
            key_id = header.get("kid")

            # Get verification key
            key = self._get_key(key_id)
            if not key:
                raise JWTDecodeError(f"Unknown key: {key_id}")

            # Verify signature
            message = f"{header_b64}.{payload_b64}"
            signature = self._base64url_decode_bytes(signature_b64)

            if not self._verify(message.encode(), signature, key, algorithm):
                raise JWTInvalidError("Invalid signature")

            # Decode payload
            payload = json.loads(self._base64url_decode(payload_b64))
            return JWTClaims.from_dict(payload)

        except json.JSONDecodeError as e:
            raise JWTDecodeError(f"Invalid JSON: {e}")
        except Exception as e:
            if isinstance(e, JWTError):
                raise
            raise JWTDecodeError(f"Decode error: {e}")

    def _sign(self, message: bytes, key: JWTKey, algorithm: JWTAlgorithm) -> bytes:
        """Create signature.

        Args:
            message: Message to sign
            key: Signing key
            algorithm: Algorithm

        Returns:
            Signature bytes
        """
        if algorithm == JWTAlgorithm.HS256:
            return hmac.new(key.secret, message, hashlib.sha256).digest()
        elif algorithm == JWTAlgorithm.HS384:
            return hmac.new(key.secret, message, hashlib.sha384).digest()
        elif algorithm == JWTAlgorithm.HS512:
            return hmac.new(key.secret, message, hashlib.sha512).digest()
        elif algorithm == JWTAlgorithm.NONE:
            return b""
        else:
            # For RSA/ECDSA, would need cryptography library
            raise JWTError(f"Algorithm not supported: {algorithm.value}")

    def _verify(
        self,
        message: bytes,
        signature: bytes,
        key: JWTKey,
        algorithm: JWTAlgorithm
    ) -> bool:
        """Verify signature.

        Args:
            message: Original message
            signature: Signature to verify
            key: Verification key
            algorithm: Algorithm

        Returns:
            True if valid
        """
        expected = self._sign(message, key, algorithm)
        return hmac.compare_digest(signature, expected)

    def _base64url_encode(self, data: str) -> str:
        """Base64URL encode string."""
        return base64.urlsafe_b64encode(data.encode()).rstrip(b"=").decode()

    def _base64url_encode_bytes(self, data: bytes) -> str:
        """Base64URL encode bytes."""
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    def _base64url_decode(self, data: str) -> str:
        """Base64URL decode to string."""
        # Add padding
        padding = 4 - len(data) % 4
        if padding != 4:
            data += "=" * padding
        return base64.urlsafe_b64decode(data).decode()

    def _base64url_decode_bytes(self, data: str) -> bytes:
        """Base64URL decode to bytes."""
        # Add padding
        padding = 4 - len(data) % 4
        if padding != 4:
            data += "=" * padding
        return base64.urlsafe_b64decode(data)


class JWTTokenPair:
    """Access and refresh token pair."""

    def __init__(
        self,
        access_token: str,
        refresh_token: str,
        access_expires_at: datetime,
        refresh_expires_at: datetime,
        token_type: str = "Bearer",
    ):
        """Initialize token pair.

        Args:
            access_token: Access token
            refresh_token: Refresh token
            access_expires_at: Access token expiration
            refresh_expires_at: Refresh token expiration
            token_type: Token type
        """
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.access_expires_at = access_expires_at
        self.refresh_expires_at = refresh_expires_at
        self.token_type = token_type

    @property
    def access_expires_in(self) -> int:
        """Get access token remaining time."""
        return max(0, int((self.access_expires_at - datetime.now()).total_seconds()))

    @property
    def refresh_expires_in(self) -> int:
        """Get refresh token remaining time."""
        return max(0, int((self.refresh_expires_at - datetime.now()).total_seconds()))

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "token_type": self.token_type,
            "expires_in": self.access_expires_in,
            "refresh_expires_in": self.refresh_expires_in,
        }


class JWTKeyStore:
    """Key store for managing JWT keys."""

    def __init__(self):
        """Initialize key store."""
        self._keys: Dict[str, JWTKey] = {}
        self._lock = threading.RLock()

    def add(self, key: JWTKey) -> None:
        """Add key to store."""
        with self._lock:
            self._keys[key.id] = key

    def get(self, key_id: str) -> Optional[JWTKey]:
        """Get key by ID."""
        return self._keys.get(key_id)

    def remove(self, key_id: str) -> bool:
        """Remove key."""
        with self._lock:
            if key_id in self._keys:
                del self._keys[key_id]
                return True
            return False

    def list_active(self) -> List[JWTKey]:
        """List active keys."""
        return [k for k in self._keys.values() if k.is_active and not k.is_expired]

    def cleanup_expired(self) -> int:
        """Remove expired keys."""
        with self._lock:
            expired = [kid for kid, key in self._keys.items() if key.is_expired]
            for kid in expired:
                del self._keys[kid]
            return len(expired)


__all__ = [
    "JWTManager",
    "JWTClaims",
    "JWTKey",
    "JWTKeyStore",
    "JWTTokenPair",
    "JWTAlgorithm",
    "JWTError",
    "JWTDecodeError",
    "JWTExpiredError",
    "JWTInvalidError",
    "JWTBlacklistedError",
    "TokenBlacklist",
]
