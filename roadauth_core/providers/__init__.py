"""RoadAuth Providers - Authentication Provider System.

Copyright (c) 2024-2026 BlackRoad OS, Inc. All rights reserved.
"""

from roadauth_core.providers.base import AuthProvider, AuthProviderResult
from roadauth_core.providers.local import LocalProvider
from roadauth_core.providers.oauth import OAuthProvider, OAuthConfig
from roadauth_core.providers.ldap import LDAPProvider, LDAPConfig
from roadauth_core.providers.saml import SAMLProvider, SAMLConfig

__all__ = [
    "AuthProvider",
    "AuthProviderResult",
    "LocalProvider",
    "OAuthProvider",
    "OAuthConfig",
    "LDAPProvider",
    "LDAPConfig",
    "SAMLProvider",
    "SAMLConfig",
]
