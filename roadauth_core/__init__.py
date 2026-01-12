"""RoadAuth - Enterprise Authentication & Authorization for BlackRoad OS.

RoadAuth is a comprehensive identity and access management system that provides:
- Multiple authentication providers (Local, LDAP, OAuth2, SAML, OIDC)
- Role-Based Access Control (RBAC) and Attribute-Based Access Control (ABAC)
- Multi-Factor Authentication (TOTP, SMS, Email, WebAuthn/FIDO2)
- JWT/Paseto token management with rotation
- Session management with distributed support
- Agent-based security (Sentinel, Auditor, Enforcer, Provisioner)

Architecture:
    ┌─────────────────────────────────────────────────────────────────────┐
    │                        RoadAuth Engine                             │
    ├─────────────────────────────────────────────────────────────────────┤
    │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                 │
    │  │   Auth      │  │   Token     │  │   Session   │                 │
    │  │   Manager   │──│   Manager   │──│   Manager   │                 │
    │  └─────────────┘  └─────────────┘  └─────────────┘                 │
    │         │               │               │                           │
    │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                 │
    │  │  Provider   │  │    MFA      │  │   Agents    │                 │
    │  │   Registry  │──│   Manager   │──│   (AI/ML)   │                 │
    │  └─────────────┘  └─────────────┘  └─────────────┘                 │
    └─────────────────────────────────────────────────────────────────────┘

Usage:
    from roadauth_core import RoadAuth, User, Role, Permission

    # Initialize auth system
    auth = RoadAuth(secret_key="your-secret-key")

    # Register user
    user = auth.register("user@example.com", "password123")

    # Authenticate
    result = auth.authenticate("user@example.com", "password123")
    if result.success:
        token = result.access_token

    # Check permissions
    if auth.authorize(user, "resource:action"):
        # Allowed
        pass

CLI:
    $ roadauth init --config ./auth.yaml
    $ roadauth user create --email user@example.com
    $ roadauth role create admin --permissions "*"
    $ roadauth token issue --user user@example.com --expires 1h

API:
    POST /api/v1/auth/login
    POST /api/v1/auth/register
    POST /api/v1/auth/refresh
    POST /api/v1/auth/logout
    GET  /api/v1/auth/me
    POST /api/v1/mfa/setup
    POST /api/v1/mfa/verify

Copyright (c) 2024-2026 BlackRoad OS, Inc. All rights reserved.
"""

from __future__ import annotations

__version__ = "2.0.0"
__author__ = "BlackRoad OS, Inc."
__email__ = "engineering@blackroad.io"

# Core exports
from roadauth_core.engine import RoadAuth, AuthResult, AuthConfig
from roadauth_core.users import User, UserManager, UserStatus
from roadauth_core.roles import Role, Permission, RoleManager, RBAC
from roadauth_core.sessions import Session, SessionManager, SessionStore

# Token exports
from roadauth_core.tokens.jwt import JWTManager, JWTClaims
from roadauth_core.tokens.paseto import PasetoManager
from roadauth_core.tokens.refresh import RefreshTokenManager

# MFA exports
from roadauth_core.mfa.totp import TOTPManager
from roadauth_core.mfa.webauthn import WebAuthnManager
from roadauth_core.mfa.backup import BackupCodesManager

# Provider exports
from roadauth_core.providers.base import AuthProvider
from roadauth_core.providers.local import LocalProvider
from roadauth_core.providers.oauth import OAuthProvider
from roadauth_core.providers.ldap import LDAPProvider
from roadauth_core.providers.saml import SAMLProvider

# Agent exports
from roadauth_core.agents.sentinel import Sentinel
from roadauth_core.agents.auditor import Auditor
from roadauth_core.agents.enforcer import Enforcer
from roadauth_core.agents.provisioner import Provisioner

__all__ = [
    # Version
    "__version__",

    # Core
    "RoadAuth",
    "AuthResult",
    "AuthConfig",

    # Users
    "User",
    "UserManager",
    "UserStatus",

    # Roles & Permissions
    "Role",
    "Permission",
    "RoleManager",
    "RBAC",

    # Sessions
    "Session",
    "SessionManager",
    "SessionStore",

    # Tokens
    "JWTManager",
    "JWTClaims",
    "PasetoManager",
    "RefreshTokenManager",

    # MFA
    "TOTPManager",
    "WebAuthnManager",
    "BackupCodesManager",

    # Providers
    "AuthProvider",
    "LocalProvider",
    "OAuthProvider",
    "LDAPProvider",
    "SAMLProvider",

    # Agents
    "Sentinel",
    "Auditor",
    "Enforcer",
    "Provisioner",
]
