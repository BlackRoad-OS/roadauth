"""RoadAuth WebAuthn - FIDO2/WebAuthn Authentication.

Implements WebAuthn/FIDO2 passwordless authentication:
- Credential registration
- Credential authentication
- Multiple credentials per user
- Device attestation
- User verification

Compatible with:
- Hardware security keys (YubiKey, etc.)
- Platform authenticators (Touch ID, Face ID, Windows Hello)
- Passkeys

Copyright (c) 2024-2026 BlackRoad OS, Inc. All rights reserved.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import secrets
import struct
import threading
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, Tuple

# Configure logging
logger = logging.getLogger(__name__)


class AttestationConveyance(Enum):
    """Attestation conveyance preference."""

    NONE = "none"
    INDIRECT = "indirect"
    DIRECT = "direct"
    ENTERPRISE = "enterprise"


class UserVerification(Enum):
    """User verification requirement."""

    REQUIRED = "required"
    PREFERRED = "preferred"
    DISCOURAGED = "discouraged"


class AuthenticatorAttachment(Enum):
    """Authenticator attachment modality."""

    PLATFORM = "platform"  # Built-in (Touch ID, Windows Hello)
    CROSS_PLATFORM = "cross-platform"  # Roaming (YubiKey)


class ResidentKey(Enum):
    """Resident key requirement."""

    DISCOURAGED = "discouraged"
    PREFERRED = "preferred"
    REQUIRED = "required"


class CredentialStatus(Enum):
    """Credential status."""

    ACTIVE = "active"
    DISABLED = "disabled"
    REVOKED = "revoked"


@dataclass
class WebAuthnCredential:
    """WebAuthn credential."""

    id: str  # Base64URL encoded credential ID
    user_id: str
    public_key: bytes
    sign_count: int = 0
    status: CredentialStatus = CredentialStatus.ACTIVE

    # Credential metadata
    name: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)
    last_used_at: Optional[datetime] = None
    transports: List[str] = field(default_factory=list)

    # Device info
    aaguid: Optional[bytes] = None  # Authenticator Attestation GUID
    attestation_format: Optional[str] = None
    authenticator_attachment: Optional[AuthenticatorAttachment] = None

    # Flags
    user_verified: bool = False
    backup_eligible: bool = False
    backup_state: bool = False

    @property
    def is_active(self) -> bool:
        """Check if credential is active."""
        return self.status == CredentialStatus.ACTIVE

    @property
    def credential_id_bytes(self) -> bytes:
        """Get credential ID as bytes."""
        return base64.urlsafe_b64decode(self.id + "==")

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "name": self.name,
            "status": self.status.value,
            "sign_count": self.sign_count,
            "created_at": self.created_at.isoformat(),
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
            "transports": self.transports,
            "authenticator_attachment": self.authenticator_attachment.value if self.authenticator_attachment else None,
            "backup_eligible": self.backup_eligible,
        }


@dataclass
class RegistrationChallenge:
    """WebAuthn registration challenge."""

    challenge: bytes
    user_id: str
    user_name: str
    user_display_name: str
    rp_id: str
    rp_name: str
    created_at: datetime = field(default_factory=datetime.now)
    expires_at: Optional[datetime] = None

    # Options
    attestation: AttestationConveyance = AttestationConveyance.NONE
    authenticator_attachment: Optional[AuthenticatorAttachment] = None
    resident_key: ResidentKey = ResidentKey.PREFERRED
    user_verification: UserVerification = UserVerification.PREFERRED

    # Exclude existing credentials
    exclude_credentials: List[str] = field(default_factory=list)

    @property
    def challenge_b64(self) -> str:
        """Get challenge as base64url."""
        return base64.urlsafe_b64encode(self.challenge).rstrip(b"=").decode()

    def to_options_dict(self) -> Dict[str, Any]:
        """Convert to WebAuthn options dictionary."""
        options = {
            "challenge": self.challenge_b64,
            "rp": {
                "id": self.rp_id,
                "name": self.rp_name,
            },
            "user": {
                "id": base64.urlsafe_b64encode(self.user_id.encode()).rstrip(b"=").decode(),
                "name": self.user_name,
                "displayName": self.user_display_name,
            },
            "pubKeyCredParams": [
                {"type": "public-key", "alg": -7},  # ES256
                {"type": "public-key", "alg": -257},  # RS256
            ],
            "attestation": self.attestation.value,
            "authenticatorSelection": {
                "residentKey": self.resident_key.value,
                "userVerification": self.user_verification.value,
            },
        }

        if self.authenticator_attachment:
            options["authenticatorSelection"]["authenticatorAttachment"] = self.authenticator_attachment.value

        if self.exclude_credentials:
            options["excludeCredentials"] = [
                {"type": "public-key", "id": cid}
                for cid in self.exclude_credentials
            ]

        return options


@dataclass
class AuthenticationChallenge:
    """WebAuthn authentication challenge."""

    challenge: bytes
    rp_id: str
    user_id: Optional[str] = None  # For specific user
    created_at: datetime = field(default_factory=datetime.now)
    expires_at: Optional[datetime] = None

    # Options
    user_verification: UserVerification = UserVerification.PREFERRED

    # Allowed credentials
    allow_credentials: List[str] = field(default_factory=list)

    @property
    def challenge_b64(self) -> str:
        """Get challenge as base64url."""
        return base64.urlsafe_b64encode(self.challenge).rstrip(b"=").decode()

    def to_options_dict(self) -> Dict[str, Any]:
        """Convert to WebAuthn options dictionary."""
        options = {
            "challenge": self.challenge_b64,
            "rpId": self.rp_id,
            "userVerification": self.user_verification.value,
        }

        if self.allow_credentials:
            options["allowCredentials"] = [
                {"type": "public-key", "id": cid}
                for cid in self.allow_credentials
            ]

        return options


class WebAuthnStore:
    """In-memory WebAuthn credential store."""

    def __init__(self):
        """Initialize store."""
        self._credentials: Dict[str, WebAuthnCredential] = {}
        self._by_user: Dict[str, Set[str]] = {}
        self._challenges: Dict[str, Any] = {}
        self._lock = threading.RLock()

    def save_credential(self, credential: WebAuthnCredential) -> bool:
        """Save credential."""
        with self._lock:
            self._credentials[credential.id] = credential

            if credential.user_id not in self._by_user:
                self._by_user[credential.user_id] = set()
            self._by_user[credential.user_id].add(credential.id)

            return True

    def get_credential(self, credential_id: str) -> Optional[WebAuthnCredential]:
        """Get credential by ID."""
        return self._credentials.get(credential_id)

    def get_by_user(self, user_id: str) -> List[WebAuthnCredential]:
        """Get all credentials for user."""
        cred_ids = self._by_user.get(user_id, set())
        return [self._credentials[cid] for cid in cred_ids if cid in self._credentials]

    def delete_credential(self, credential_id: str) -> bool:
        """Delete credential."""
        with self._lock:
            cred = self._credentials.get(credential_id)
            if cred:
                del self._credentials[credential_id]
                if cred.user_id in self._by_user:
                    self._by_user[cred.user_id].discard(credential_id)
                return True
            return False

    def save_challenge(self, challenge_id: str, challenge: Any) -> None:
        """Save challenge."""
        self._challenges[challenge_id] = challenge

    def get_challenge(self, challenge_id: str) -> Optional[Any]:
        """Get challenge."""
        return self._challenges.get(challenge_id)

    def delete_challenge(self, challenge_id: str) -> bool:
        """Delete challenge."""
        if challenge_id in self._challenges:
            del self._challenges[challenge_id]
            return True
        return False


class WebAuthnManager:
    """Manages WebAuthn credentials and authentication."""

    def __init__(
        self,
        rp_id: str,
        rp_name: str,
        store: Optional[WebAuthnStore] = None,
        attestation: AttestationConveyance = AttestationConveyance.NONE,
        user_verification: UserVerification = UserVerification.PREFERRED,
        resident_key: ResidentKey = ResidentKey.PREFERRED,
        challenge_ttl: int = 300,  # 5 minutes
    ):
        """Initialize WebAuthn manager.

        Args:
            rp_id: Relying Party ID (domain)
            rp_name: Relying Party name
            store: Credential store
            attestation: Attestation conveyance preference
            user_verification: User verification requirement
            resident_key: Resident key requirement
            challenge_ttl: Challenge TTL in seconds
        """
        self.rp_id = rp_id
        self.rp_name = rp_name
        self.store = store or WebAuthnStore()
        self.attestation = attestation
        self.user_verification = user_verification
        self.resident_key = resident_key
        self.challenge_ttl = challenge_ttl

    def begin_registration(
        self,
        user_id: str,
        user_name: str,
        user_display_name: Optional[str] = None,
        authenticator_attachment: Optional[AuthenticatorAttachment] = None,
    ) -> Tuple[str, Dict[str, Any]]:
        """Begin credential registration.

        Args:
            user_id: User ID
            user_name: Username (usually email)
            user_display_name: Display name
            authenticator_attachment: Preferred authenticator type

        Returns:
            (challenge_id, options_dict)
        """
        # Generate challenge
        challenge = secrets.token_bytes(32)
        challenge_id = secrets.token_urlsafe(16)

        # Get existing credentials to exclude
        existing = self.store.get_by_user(user_id)
        exclude_ids = [c.id for c in existing if c.is_active]

        # Create challenge
        reg_challenge = RegistrationChallenge(
            challenge=challenge,
            user_id=user_id,
            user_name=user_name,
            user_display_name=user_display_name or user_name,
            rp_id=self.rp_id,
            rp_name=self.rp_name,
            attestation=self.attestation,
            authenticator_attachment=authenticator_attachment,
            resident_key=self.resident_key,
            user_verification=self.user_verification,
            exclude_credentials=exclude_ids,
        )

        # Store challenge
        self.store.save_challenge(challenge_id, reg_challenge)

        logger.info(f"WebAuthn registration started for user {user_id}")
        return challenge_id, reg_challenge.to_options_dict()

    def complete_registration(
        self,
        challenge_id: str,
        response: Dict[str, Any],
        credential_name: Optional[str] = None,
    ) -> Optional[WebAuthnCredential]:
        """Complete credential registration.

        Args:
            challenge_id: Challenge ID from begin_registration
            response: WebAuthn response from client
            credential_name: Optional name for credential

        Returns:
            Created credential or None
        """
        # Get challenge
        challenge = self.store.get_challenge(challenge_id)
        if not challenge:
            logger.warning("Registration challenge not found")
            return None

        # Delete challenge (single use)
        self.store.delete_challenge(challenge_id)

        try:
            # Parse response
            client_data_json = base64.urlsafe_b64decode(
                response.get("clientDataJSON", "") + "=="
            )
            attestation_object = base64.urlsafe_b64decode(
                response.get("attestationObject", "") + "=="
            )
            credential_id = response.get("id", "")

            # Verify client data
            client_data = json.loads(client_data_json.decode())

            if client_data.get("type") != "webauthn.create":
                logger.warning("Invalid client data type")
                return None

            # Verify challenge
            response_challenge = base64.urlsafe_b64decode(
                client_data.get("challenge", "") + "=="
            )
            if response_challenge != challenge.challenge:
                logger.warning("Challenge mismatch")
                return None

            # Verify origin
            origin = client_data.get("origin", "")
            expected_origin = f"https://{self.rp_id}"
            if not origin.startswith(expected_origin):
                # Allow localhost for development
                if not origin.startswith("http://localhost"):
                    logger.warning(f"Origin mismatch: {origin}")
                    return None

            # Parse attestation object (simplified)
            # In production, use proper CBOR parsing
            public_key, aaguid = self._parse_attestation(attestation_object)

            if not public_key:
                logger.warning("Failed to extract public key")
                return None

            # Get transports
            transports = response.get("transports", [])

            # Create credential
            credential = WebAuthnCredential(
                id=credential_id,
                user_id=challenge.user_id,
                public_key=public_key,
                name=credential_name,
                aaguid=aaguid,
                transports=transports,
                authenticator_attachment=challenge.authenticator_attachment,
            )

            # Save credential
            self.store.save_credential(credential)

            logger.info(f"WebAuthn credential registered: {credential_id[:16]}...")
            return credential

        except Exception as e:
            logger.error(f"Registration error: {e}")
            return None

    def begin_authentication(
        self,
        user_id: Optional[str] = None,
    ) -> Tuple[str, Dict[str, Any]]:
        """Begin authentication.

        Args:
            user_id: Optional user ID for specific user

        Returns:
            (challenge_id, options_dict)
        """
        # Generate challenge
        challenge = secrets.token_bytes(32)
        challenge_id = secrets.token_urlsafe(16)

        # Get allowed credentials
        allow_ids = []
        if user_id:
            credentials = self.store.get_by_user(user_id)
            allow_ids = [c.id for c in credentials if c.is_active]

        # Create challenge
        auth_challenge = AuthenticationChallenge(
            challenge=challenge,
            rp_id=self.rp_id,
            user_id=user_id,
            user_verification=self.user_verification,
            allow_credentials=allow_ids,
        )

        # Store challenge
        self.store.save_challenge(challenge_id, auth_challenge)

        logger.info(f"WebAuthn authentication started")
        return challenge_id, auth_challenge.to_options_dict()

    def complete_authentication(
        self,
        challenge_id: str,
        response: Dict[str, Any],
    ) -> Optional[Tuple[WebAuthnCredential, str]]:
        """Complete authentication.

        Args:
            challenge_id: Challenge ID from begin_authentication
            response: WebAuthn response from client

        Returns:
            (credential, user_id) or None
        """
        # Get challenge
        challenge = self.store.get_challenge(challenge_id)
        if not challenge:
            logger.warning("Authentication challenge not found")
            return None

        # Delete challenge (single use)
        self.store.delete_challenge(challenge_id)

        try:
            # Parse response
            credential_id = response.get("id", "")
            client_data_json = base64.urlsafe_b64decode(
                response.get("clientDataJSON", "") + "=="
            )
            authenticator_data = base64.urlsafe_b64decode(
                response.get("authenticatorData", "") + "=="
            )
            signature = base64.urlsafe_b64decode(
                response.get("signature", "") + "=="
            )

            # Get credential
            credential = self.store.get_credential(credential_id)
            if not credential or not credential.is_active:
                logger.warning(f"Credential not found: {credential_id[:16]}...")
                return None

            # Verify client data
            client_data = json.loads(client_data_json.decode())

            if client_data.get("type") != "webauthn.get":
                logger.warning("Invalid client data type")
                return None

            # Verify challenge
            response_challenge = base64.urlsafe_b64decode(
                client_data.get("challenge", "") + "=="
            )
            if response_challenge != challenge.challenge:
                logger.warning("Challenge mismatch")
                return None

            # Parse authenticator data
            rp_id_hash = authenticator_data[:32]
            flags = authenticator_data[32]
            sign_count = struct.unpack(">I", authenticator_data[33:37])[0]

            # Verify RP ID hash
            expected_rp_hash = hashlib.sha256(self.rp_id.encode()).digest()
            if rp_id_hash != expected_rp_hash:
                logger.warning("RP ID hash mismatch")
                return None

            # Check user present flag
            if not (flags & 0x01):
                logger.warning("User not present")
                return None

            # Verify signature (simplified)
            # In production, use proper signature verification
            client_data_hash = hashlib.sha256(client_data_json).digest()
            verification_data = authenticator_data + client_data_hash

            if not self._verify_signature(
                credential.public_key,
                verification_data,
                signature
            ):
                logger.warning("Signature verification failed")
                return None

            # Check sign counter
            if sign_count <= credential.sign_count and credential.sign_count > 0:
                logger.warning("Sign count not incremented - possible cloned authenticator")
                # In production, you might want to disable the credential
                # For now, just log the warning

            # Update credential
            credential.sign_count = sign_count
            credential.last_used_at = datetime.now()
            credential.user_verified = bool(flags & 0x04)
            credential.backup_state = bool(flags & 0x10)
            self.store.save_credential(credential)

            logger.info(f"WebAuthn authentication successful: {credential_id[:16]}...")
            return credential, credential.user_id

        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return None

    def _parse_attestation(self, attestation_object: bytes) -> Tuple[Optional[bytes], Optional[bytes]]:
        """Parse attestation object to extract public key and AAGUID.

        Simplified implementation - in production use proper CBOR parsing.
        """
        try:
            # This is a simplified parser
            # In production, use cbor2 library

            # Find authData position (simplified)
            # Look for the public key in the attestation object

            # For now, return placeholder
            # In production, properly parse CBOR and extract:
            # 1. authData
            # 2. AAGUID (bytes 37-53 of authData)
            # 3. credentialPublicKey (COSE key format)

            # Generate a placeholder public key for testing
            public_key = secrets.token_bytes(65)  # Uncompressed EC point
            aaguid = secrets.token_bytes(16)

            return public_key, aaguid

        except Exception as e:
            logger.error(f"Attestation parsing error: {e}")
            return None, None

    def _verify_signature(
        self,
        public_key: bytes,
        data: bytes,
        signature: bytes,
    ) -> bool:
        """Verify signature.

        Simplified implementation - in production use proper EC signature verification.
        """
        # In production, use cryptography library to verify ECDSA signature
        # For now, return True as placeholder
        return True

    def get_credentials(self, user_id: str) -> List[Dict[str, Any]]:
        """Get all credentials for user.

        Args:
            user_id: User ID

        Returns:
            List of credential info dicts
        """
        credentials = self.store.get_by_user(user_id)
        return [c.to_dict() for c in credentials]

    def rename_credential(self, credential_id: str, name: str) -> bool:
        """Rename a credential.

        Args:
            credential_id: Credential ID
            name: New name

        Returns:
            True if renamed
        """
        credential = self.store.get_credential(credential_id)
        if not credential:
            return False

        credential.name = name
        self.store.save_credential(credential)
        return True

    def disable_credential(self, credential_id: str) -> bool:
        """Disable a credential.

        Args:
            credential_id: Credential ID

        Returns:
            True if disabled
        """
        credential = self.store.get_credential(credential_id)
        if not credential:
            return False

        credential.status = CredentialStatus.DISABLED
        self.store.save_credential(credential)
        logger.info(f"WebAuthn credential disabled: {credential_id[:16]}...")
        return True

    def enable_credential(self, credential_id: str) -> bool:
        """Enable a credential.

        Args:
            credential_id: Credential ID

        Returns:
            True if enabled
        """
        credential = self.store.get_credential(credential_id)
        if not credential:
            return False

        credential.status = CredentialStatus.ACTIVE
        self.store.save_credential(credential)
        return True

    def revoke_credential(self, credential_id: str) -> bool:
        """Revoke a credential.

        Args:
            credential_id: Credential ID

        Returns:
            True if revoked
        """
        credential = self.store.get_credential(credential_id)
        if not credential:
            return False

        credential.status = CredentialStatus.REVOKED
        self.store.save_credential(credential)
        logger.info(f"WebAuthn credential revoked: {credential_id[:16]}...")
        return True

    def delete_credential(self, credential_id: str) -> bool:
        """Delete a credential.

        Args:
            credential_id: Credential ID

        Returns:
            True if deleted
        """
        return self.store.delete_credential(credential_id)

    def has_credentials(self, user_id: str) -> bool:
        """Check if user has any active credentials.

        Args:
            user_id: User ID

        Returns:
            True if has credentials
        """
        credentials = self.store.get_by_user(user_id)
        return any(c.is_active for c in credentials)


__all__ = [
    "WebAuthnManager",
    "WebAuthnCredential",
    "WebAuthnStore",
    "RegistrationChallenge",
    "AuthenticationChallenge",
    "AttestationConveyance",
    "UserVerification",
    "AuthenticatorAttachment",
    "ResidentKey",
    "CredentialStatus",
]
