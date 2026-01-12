"""RoadAuth Base Provider - Abstract Authentication Provider.

Defines the interface for all authentication providers.

Copyright (c) 2024-2026 BlackRoad OS, Inc. All rights reserved.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

# Configure logging
logger = logging.getLogger(__name__)


class AuthProviderType(Enum):
    """Authentication provider types."""

    LOCAL = "local"
    OAUTH2 = "oauth2"
    OIDC = "oidc"
    SAML = "saml"
    LDAP = "ldap"
    RADIUS = "radius"
    KERBEROS = "kerberos"
    CUSTOM = "custom"


class AuthStatus(Enum):
    """Authentication result status."""

    SUCCESS = "success"
    FAILURE = "failure"
    MFA_REQUIRED = "mfa_required"
    PASSWORD_EXPIRED = "password_expired"
    ACCOUNT_LOCKED = "account_locked"
    ACCOUNT_DISABLED = "account_disabled"
    INVALID_CREDENTIALS = "invalid_credentials"
    USER_NOT_FOUND = "user_not_found"
    PROVIDER_ERROR = "provider_error"


@dataclass
class AuthProviderResult:
    """Authentication provider result."""

    success: bool
    status: AuthStatus
    user_id: Optional[str] = None
    email: Optional[str] = None
    username: Optional[str] = None
    display_name: Optional[str] = None
    message: Optional[str] = None

    # Additional user info from provider
    profile: Dict[str, Any] = field(default_factory=dict)

    # Provider metadata
    provider_id: Optional[str] = None
    provider_type: Optional[AuthProviderType] = None
    provider_user_id: Optional[str] = None

    # Groups/roles from provider
    groups: List[str] = field(default_factory=list)
    roles: List[str] = field(default_factory=list)

    # Session hints
    requires_mfa: bool = False
    requires_password_change: bool = False
    session_metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def success_result(
        cls,
        user_id: str,
        email: Optional[str] = None,
        **kwargs
    ) -> AuthProviderResult:
        """Create success result."""
        return cls(
            success=True,
            status=AuthStatus.SUCCESS,
            user_id=user_id,
            email=email,
            **kwargs
        )

    @classmethod
    def failure_result(
        cls,
        status: AuthStatus,
        message: Optional[str] = None,
        **kwargs
    ) -> AuthProviderResult:
        """Create failure result."""
        return cls(
            success=False,
            status=status,
            message=message,
            **kwargs
        )


@dataclass
class AuthProviderConfig:
    """Base authentication provider configuration."""

    provider_id: str
    provider_type: AuthProviderType
    enabled: bool = True
    priority: int = 0  # Lower = higher priority
    display_name: Optional[str] = None
    description: Optional[str] = None

    # User provisioning
    auto_create_users: bool = False
    auto_update_users: bool = True

    # Attribute mapping
    attribute_mapping: Dict[str, str] = field(default_factory=dict)

    # Group/role mapping
    group_mapping: Dict[str, List[str]] = field(default_factory=dict)
    role_mapping: Dict[str, List[str]] = field(default_factory=dict)

    # Security
    require_mfa: bool = False
    allowed_domains: List[str] = field(default_factory=list)
    blocked_domains: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "provider_id": self.provider_id,
            "provider_type": self.provider_type.value,
            "enabled": self.enabled,
            "priority": self.priority,
            "display_name": self.display_name,
            "description": self.description,
            "auto_create_users": self.auto_create_users,
            "auto_update_users": self.auto_update_users,
            "require_mfa": self.require_mfa,
        }


class AuthProvider(ABC):
    """Abstract base class for authentication providers."""

    def __init__(self, config: AuthProviderConfig):
        """Initialize provider.

        Args:
            config: Provider configuration
        """
        self.config = config
        self._initialized = False

    @property
    def provider_id(self) -> str:
        """Get provider ID."""
        return self.config.provider_id

    @property
    def provider_type(self) -> AuthProviderType:
        """Get provider type."""
        return self.config.provider_type

    @property
    def is_enabled(self) -> bool:
        """Check if provider is enabled."""
        return self.config.enabled

    @abstractmethod
    async def initialize(self) -> bool:
        """Initialize provider.

        Returns:
            True if successful
        """
        pass

    @abstractmethod
    async def authenticate(
        self,
        credentials: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> AuthProviderResult:
        """Authenticate user.

        Args:
            credentials: Authentication credentials
            context: Additional context

        Returns:
            Authentication result
        """
        pass

    @abstractmethod
    async def validate_user(self, user_id: str) -> bool:
        """Validate that user still exists/is valid.

        Args:
            user_id: User ID

        Returns:
            True if valid
        """
        pass

    async def get_user_info(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user information from provider.

        Args:
            user_id: User ID

        Returns:
            User info or None
        """
        return None

    async def get_user_groups(self, user_id: str) -> List[str]:
        """Get user groups from provider.

        Args:
            user_id: User ID

        Returns:
            List of group names
        """
        return []

    async def search_users(
        self,
        query: str,
        limit: int = 10,
    ) -> List[Dict[str, Any]]:
        """Search for users.

        Args:
            query: Search query
            limit: Maximum results

        Returns:
            List of user info dicts
        """
        return []

    async def sync_user(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Sync user data from provider.

        Args:
            user_id: User ID

        Returns:
            Updated user data or None
        """
        return None

    async def health_check(self) -> Tuple[bool, str]:
        """Check provider health.

        Returns:
            (is_healthy, message)
        """
        return True, "OK"

    async def shutdown(self) -> None:
        """Shutdown provider."""
        pass

    def map_attributes(self, provider_data: Dict[str, Any]) -> Dict[str, Any]:
        """Map provider attributes to internal format.

        Args:
            provider_data: Data from provider

        Returns:
            Mapped data
        """
        if not self.config.attribute_mapping:
            return provider_data

        mapped = {}
        for internal_key, provider_key in self.config.attribute_mapping.items():
            if provider_key in provider_data:
                mapped[internal_key] = provider_data[provider_key]

        return mapped

    def map_groups(self, provider_groups: List[str]) -> List[str]:
        """Map provider groups to internal groups.

        Args:
            provider_groups: Groups from provider

        Returns:
            Mapped group names
        """
        if not self.config.group_mapping:
            return provider_groups

        mapped = set()
        for provider_group in provider_groups:
            if provider_group in self.config.group_mapping:
                mapped.update(self.config.group_mapping[provider_group])
            else:
                mapped.add(provider_group)

        return list(mapped)

    def map_roles(self, provider_groups: List[str]) -> List[str]:
        """Map provider groups to internal roles.

        Args:
            provider_groups: Groups from provider

        Returns:
            Mapped role names
        """
        if not self.config.role_mapping:
            return []

        roles = set()
        for provider_group in provider_groups:
            if provider_group in self.config.role_mapping:
                roles.update(self.config.role_mapping[provider_group])

        return list(roles)

    def is_domain_allowed(self, email: str) -> bool:
        """Check if email domain is allowed.

        Args:
            email: Email address

        Returns:
            True if allowed
        """
        if not email or "@" not in email:
            return False

        domain = email.split("@")[1].lower()

        # Check blocked domains
        if self.config.blocked_domains:
            if domain in self.config.blocked_domains:
                return False

        # Check allowed domains
        if self.config.allowed_domains:
            if domain not in self.config.allowed_domains:
                return False

        return True


class ProviderRegistry:
    """Registry of authentication providers."""

    def __init__(self):
        """Initialize registry."""
        self._providers: Dict[str, AuthProvider] = {}

    def register(self, provider: AuthProvider) -> None:
        """Register provider.

        Args:
            provider: Provider to register
        """
        self._providers[provider.provider_id] = provider
        logger.info(f"Registered auth provider: {provider.provider_id}")

    def unregister(self, provider_id: str) -> bool:
        """Unregister provider.

        Args:
            provider_id: Provider ID

        Returns:
            True if removed
        """
        if provider_id in self._providers:
            del self._providers[provider_id]
            logger.info(f"Unregistered auth provider: {provider_id}")
            return True
        return False

    def get(self, provider_id: str) -> Optional[AuthProvider]:
        """Get provider by ID.

        Args:
            provider_id: Provider ID

        Returns:
            Provider or None
        """
        return self._providers.get(provider_id)

    def get_by_type(self, provider_type: AuthProviderType) -> List[AuthProvider]:
        """Get providers by type.

        Args:
            provider_type: Provider type

        Returns:
            List of providers
        """
        return [
            p for p in self._providers.values()
            if p.provider_type == provider_type
        ]

    def list_enabled(self) -> List[AuthProvider]:
        """List enabled providers (sorted by priority).

        Returns:
            List of enabled providers
        """
        enabled = [p for p in self._providers.values() if p.is_enabled]
        return sorted(enabled, key=lambda p: p.config.priority)

    def list_all(self) -> List[AuthProvider]:
        """List all providers.

        Returns:
            List of all providers
        """
        return list(self._providers.values())


__all__ = [
    "AuthProvider",
    "AuthProviderConfig",
    "AuthProviderResult",
    "AuthProviderType",
    "AuthStatus",
    "ProviderRegistry",
]
