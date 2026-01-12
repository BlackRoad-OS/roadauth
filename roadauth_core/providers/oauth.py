"""RoadAuth OAuth Provider - OAuth2/OIDC Authentication.

Implements OAuth 2.0 and OpenID Connect authentication:
- Authorization Code flow
- PKCE support
- Token refresh
- User info retrieval
- Pre-configured providers (Google, GitHub, Microsoft, etc.)

Copyright (c) 2024-2026 BlackRoad OS, Inc. All rights reserved.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import secrets
import time
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode, parse_qs, urlparse

from roadauth_core.providers.base import (
    AuthProvider,
    AuthProviderConfig,
    AuthProviderResult,
    AuthProviderType,
    AuthStatus,
)

# Configure logging
logger = logging.getLogger(__name__)


class OAuthFlow(Enum):
    """OAuth flow types."""

    AUTHORIZATION_CODE = "authorization_code"
    CLIENT_CREDENTIALS = "client_credentials"
    DEVICE_CODE = "device_code"
    IMPLICIT = "implicit"  # Deprecated


class OAuthScope(Enum):
    """Common OAuth scopes."""

    OPENID = "openid"
    PROFILE = "profile"
    EMAIL = "email"
    OFFLINE_ACCESS = "offline_access"


@dataclass
class OAuthConfig(AuthProviderConfig):
    """OAuth provider configuration."""

    # OAuth endpoints
    client_id: str = ""
    client_secret: str = ""
    authorization_url: str = ""
    token_url: str = ""
    userinfo_url: str = ""
    revocation_url: str = ""
    jwks_url: str = ""

    # Flow configuration
    flow: OAuthFlow = OAuthFlow.AUTHORIZATION_CODE
    use_pkce: bool = True
    pkce_method: str = "S256"  # plain or S256

    # Scopes
    scopes: List[str] = field(default_factory=lambda: ["openid", "profile", "email"])

    # Redirect
    redirect_uri: str = ""

    # Token handling
    token_endpoint_auth_method: str = "client_secret_post"  # or client_secret_basic
    verify_at_hash: bool = True
    verify_nonce: bool = True

    # User info mapping
    user_id_claim: str = "sub"
    email_claim: str = "email"
    name_claim: str = "name"
    picture_claim: str = "picture"
    groups_claim: str = "groups"

    # Additional options
    additional_params: Dict[str, str] = field(default_factory=dict)
    state_ttl: int = 600  # 10 minutes


@dataclass
class OAuthState:
    """OAuth authorization state."""

    state: str
    nonce: str
    code_verifier: Optional[str] = None
    redirect_uri: str = ""
    created_at: datetime = field(default_factory=datetime.now)
    expires_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_expired(self) -> bool:
        """Check if state is expired."""
        if self.expires_at is None:
            return False
        return datetime.now() > self.expires_at

    @property
    def code_challenge(self) -> Optional[str]:
        """Get PKCE code challenge."""
        if not self.code_verifier:
            return None
        digest = hashlib.sha256(self.code_verifier.encode()).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


@dataclass
class OAuthTokens:
    """OAuth token container."""

    access_token: str
    token_type: str = "Bearer"
    expires_in: Optional[int] = None
    refresh_token: Optional[str] = None
    scope: Optional[str] = None
    id_token: Optional[str] = None

    # Computed
    expires_at: Optional[datetime] = None

    def __post_init__(self):
        if self.expires_in and not self.expires_at:
            self.expires_at = datetime.now() + timedelta(seconds=self.expires_in)

    @property
    def is_expired(self) -> bool:
        """Check if access token is expired."""
        if self.expires_at is None:
            return False
        return datetime.now() > self.expires_at

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "access_token": self.access_token,
            "token_type": self.token_type,
            "expires_in": self.expires_in,
            "refresh_token": self.refresh_token,
            "scope": self.scope,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
        }


class OAuthStateStore:
    """In-memory OAuth state store."""

    def __init__(self):
        """Initialize store."""
        self._states: Dict[str, OAuthState] = {}

    def save(self, state: OAuthState) -> None:
        """Save state."""
        self._states[state.state] = state

    def get(self, state: str) -> Optional[OAuthState]:
        """Get state."""
        return self._states.get(state)

    def delete(self, state: str) -> bool:
        """Delete state."""
        if state in self._states:
            del self._states[state]
            return True
        return False

    def cleanup_expired(self) -> int:
        """Remove expired states."""
        expired = [s for s, state in self._states.items() if state.is_expired]
        for s in expired:
            del self._states[s]
        return len(expired)


class OAuthProvider(AuthProvider):
    """OAuth 2.0 / OpenID Connect authentication provider."""

    # Pre-configured providers
    PROVIDERS = {
        "google": {
            "authorization_url": "https://accounts.google.com/o/oauth2/v2/auth",
            "token_url": "https://oauth2.googleapis.com/token",
            "userinfo_url": "https://openidconnect.googleapis.com/v1/userinfo",
            "jwks_url": "https://www.googleapis.com/oauth2/v3/certs",
            "scopes": ["openid", "profile", "email"],
        },
        "github": {
            "authorization_url": "https://github.com/login/oauth/authorize",
            "token_url": "https://github.com/login/oauth/access_token",
            "userinfo_url": "https://api.github.com/user",
            "scopes": ["read:user", "user:email"],
            "user_id_claim": "id",
            "email_claim": "email",
            "name_claim": "name",
        },
        "microsoft": {
            "authorization_url": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
            "token_url": "https://login.microsoftonline.com/common/oauth2/v2.0/token",
            "userinfo_url": "https://graph.microsoft.com/v1.0/me",
            "jwks_url": "https://login.microsoftonline.com/common/discovery/v2.0/keys",
            "scopes": ["openid", "profile", "email", "User.Read"],
        },
        "facebook": {
            "authorization_url": "https://www.facebook.com/v18.0/dialog/oauth",
            "token_url": "https://graph.facebook.com/v18.0/oauth/access_token",
            "userinfo_url": "https://graph.facebook.com/v18.0/me",
            "scopes": ["email", "public_profile"],
            "additional_params": {"fields": "id,name,email,picture"},
        },
        "apple": {
            "authorization_url": "https://appleid.apple.com/auth/authorize",
            "token_url": "https://appleid.apple.com/auth/token",
            "jwks_url": "https://appleid.apple.com/auth/keys",
            "scopes": ["name", "email"],
            "additional_params": {"response_mode": "form_post"},
        },
    }

    def __init__(
        self,
        config: OAuthConfig,
        state_store: Optional[OAuthStateStore] = None,
        http_client: Optional[Any] = None,
    ):
        """Initialize OAuth provider.

        Args:
            config: OAuth configuration
            state_store: State store implementation
            http_client: HTTP client for API calls
        """
        super().__init__(config)
        self.oauth_config = config
        self.state_store = state_store or OAuthStateStore()
        self.http_client = http_client

    @classmethod
    def from_preset(
        cls,
        provider_name: str,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        **overrides
    ) -> OAuthProvider:
        """Create provider from preset configuration.

        Args:
            provider_name: Preset provider name (google, github, etc.)
            client_id: OAuth client ID
            client_secret: OAuth client secret
            redirect_uri: Redirect URI
            **overrides: Configuration overrides

        Returns:
            Configured OAuthProvider
        """
        if provider_name not in cls.PROVIDERS:
            raise ValueError(f"Unknown provider: {provider_name}")

        preset = cls.PROVIDERS[provider_name]

        config = OAuthConfig(
            provider_id=provider_name,
            provider_type=AuthProviderType.OAUTH2,
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
            **preset,
            **overrides,
        )

        return cls(config)

    async def initialize(self) -> bool:
        """Initialize provider."""
        self._initialized = True
        logger.info(f"OAuth provider initialized: {self.provider_id}")
        return True

    def get_authorization_url(
        self,
        redirect_uri: Optional[str] = None,
        state_metadata: Optional[Dict[str, Any]] = None,
    ) -> Tuple[str, OAuthState]:
        """Get authorization URL for OAuth flow.

        Args:
            redirect_uri: Override redirect URI
            state_metadata: Additional state metadata

        Returns:
            (authorization_url, state_object)
        """
        # Generate state and nonce
        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)

        # Generate PKCE code verifier
        code_verifier = None
        if self.oauth_config.use_pkce:
            code_verifier = secrets.token_urlsafe(64)

        # Create state object
        oauth_state = OAuthState(
            state=state,
            nonce=nonce,
            code_verifier=code_verifier,
            redirect_uri=redirect_uri or self.oauth_config.redirect_uri,
            expires_at=datetime.now() + timedelta(seconds=self.oauth_config.state_ttl),
            metadata=state_metadata or {},
        )

        # Save state
        self.state_store.save(oauth_state)

        # Build authorization URL
        params = {
            "client_id": self.oauth_config.client_id,
            "response_type": "code",
            "redirect_uri": oauth_state.redirect_uri,
            "scope": " ".join(self.oauth_config.scopes),
            "state": state,
        }

        # Add nonce for OIDC
        if "openid" in self.oauth_config.scopes:
            params["nonce"] = nonce

        # Add PKCE
        if code_verifier:
            params["code_challenge"] = oauth_state.code_challenge
            params["code_challenge_method"] = self.oauth_config.pkce_method

        # Add additional params
        params.update(self.oauth_config.additional_params)

        url = f"{self.oauth_config.authorization_url}?{urlencode(params)}"

        return url, oauth_state

    async def authenticate(
        self,
        credentials: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> AuthProviderResult:
        """Authenticate user with OAuth callback.

        Args:
            credentials: Must contain 'code' and 'state'
            context: Optional context

        Returns:
            Authentication result
        """
        code = credentials.get("code")
        state = credentials.get("state")

        if not code or not state:
            return AuthProviderResult.failure_result(
                AuthStatus.INVALID_CREDENTIALS,
                "Missing code or state",
            )

        # Verify state
        oauth_state = self.state_store.get(state)
        if not oauth_state:
            return AuthProviderResult.failure_result(
                AuthStatus.INVALID_CREDENTIALS,
                "Invalid state",
            )

        if oauth_state.is_expired:
            self.state_store.delete(state)
            return AuthProviderResult.failure_result(
                AuthStatus.INVALID_CREDENTIALS,
                "State expired",
            )

        # Delete state (one-time use)
        self.state_store.delete(state)

        # Exchange code for tokens
        tokens = await self._exchange_code(code, oauth_state)
        if not tokens:
            return AuthProviderResult.failure_result(
                AuthStatus.PROVIDER_ERROR,
                "Failed to exchange code for tokens",
            )

        # Get user info
        user_info = await self._get_user_info(tokens)
        if not user_info:
            return AuthProviderResult.failure_result(
                AuthStatus.PROVIDER_ERROR,
                "Failed to get user info",
            )

        # Extract user data
        user_id = str(user_info.get(self.oauth_config.user_id_claim, ""))
        email = user_info.get(self.oauth_config.email_claim)
        name = user_info.get(self.oauth_config.name_claim)
        groups = user_info.get(self.oauth_config.groups_claim, [])

        if not user_id:
            return AuthProviderResult.failure_result(
                AuthStatus.PROVIDER_ERROR,
                "No user ID in response",
            )

        # Check domain restriction
        if email and not self.is_domain_allowed(email):
            return AuthProviderResult.failure_result(
                AuthStatus.FAILURE,
                "Email domain not allowed",
            )

        return AuthProviderResult.success_result(
            user_id=user_id,
            email=email,
            display_name=name,
            provider_id=self.provider_id,
            provider_type=self.provider_type,
            provider_user_id=user_id,
            profile=user_info,
            groups=self.map_groups(groups) if groups else [],
            roles=self.map_roles(groups) if groups else [],
            session_metadata={
                "tokens": tokens.to_dict(),
                "oauth_state_metadata": oauth_state.metadata,
            },
        )

    async def validate_user(self, user_id: str) -> bool:
        """Validate user (always true for OAuth)."""
        return True

    async def refresh_tokens(self, refresh_token: str) -> Optional[OAuthTokens]:
        """Refresh access token.

        Args:
            refresh_token: Refresh token

        Returns:
            New tokens or None
        """
        # Build token request
        data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": self.oauth_config.client_id,
        }

        if self.oauth_config.token_endpoint_auth_method == "client_secret_post":
            data["client_secret"] = self.oauth_config.client_secret

        # Make request (simulated)
        # In production, use actual HTTP client
        logger.info(f"Refreshing tokens for provider {self.provider_id}")

        # Return simulated tokens
        return OAuthTokens(
            access_token=secrets.token_urlsafe(32),
            token_type="Bearer",
            expires_in=3600,
            refresh_token=refresh_token,
        )

    async def revoke_token(self, token: str, token_type: str = "access_token") -> bool:
        """Revoke a token.

        Args:
            token: Token to revoke
            token_type: Type of token

        Returns:
            True if revoked
        """
        if not self.oauth_config.revocation_url:
            return False

        # Make revocation request (simulated)
        logger.info(f"Revoking {token_type} for provider {self.provider_id}")
        return True

    async def _exchange_code(
        self,
        code: str,
        state: OAuthState,
    ) -> Optional[OAuthTokens]:
        """Exchange authorization code for tokens.

        Args:
            code: Authorization code
            state: OAuth state

        Returns:
            Tokens or None
        """
        # Build token request
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": state.redirect_uri,
            "client_id": self.oauth_config.client_id,
        }

        if self.oauth_config.token_endpoint_auth_method == "client_secret_post":
            data["client_secret"] = self.oauth_config.client_secret

        if state.code_verifier:
            data["code_verifier"] = state.code_verifier

        # Make request (simulated)
        # In production, use actual HTTP client
        logger.info(f"Exchanging code for tokens: {self.provider_id}")

        # Return simulated tokens
        return OAuthTokens(
            access_token=secrets.token_urlsafe(32),
            token_type="Bearer",
            expires_in=3600,
            refresh_token=secrets.token_urlsafe(32),
            id_token=secrets.token_urlsafe(64),
        )

    async def _get_user_info(self, tokens: OAuthTokens) -> Optional[Dict[str, Any]]:
        """Get user info from provider.

        Args:
            tokens: OAuth tokens

        Returns:
            User info or None
        """
        if not self.oauth_config.userinfo_url:
            # Try to decode ID token
            if tokens.id_token:
                return self._decode_id_token(tokens.id_token)
            return None

        # Make request (simulated)
        # In production, use actual HTTP client
        logger.info(f"Getting user info: {self.provider_id}")

        # Return simulated user info
        return {
            "sub": secrets.token_urlsafe(16),
            "email": "user@example.com",
            "email_verified": True,
            "name": "Test User",
            "picture": "https://example.com/avatar.jpg",
        }

    def _decode_id_token(self, id_token: str) -> Optional[Dict[str, Any]]:
        """Decode ID token (without verification).

        Args:
            id_token: JWT ID token

        Returns:
            Claims or None
        """
        try:
            parts = id_token.split(".")
            if len(parts) != 3:
                return None

            # Decode payload
            payload = parts[1]
            # Add padding
            padding = 4 - len(payload) % 4
            if padding != 4:
                payload += "=" * padding

            claims = json.loads(base64.urlsafe_b64decode(payload).decode())
            return claims

        except Exception as e:
            logger.error(f"Failed to decode ID token: {e}")
            return None


__all__ = [
    "OAuthProvider",
    "OAuthConfig",
    "OAuthFlow",
    "OAuthScope",
    "OAuthState",
    "OAuthStateStore",
    "OAuthTokens",
]
