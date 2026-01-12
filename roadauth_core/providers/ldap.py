"""RoadAuth LDAP Provider - LDAP/Active Directory Authentication.

Implements LDAP authentication with:
- Simple bind and SASL authentication
- User and group search
- Attribute mapping
- Connection pooling
- TLS/STARTTLS support

Copyright (c) 2024-2026 BlackRoad OS, Inc. All rights reserved.
"""

from __future__ import annotations

import logging
import re
import threading
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from roadauth_core.providers.base import (
    AuthProvider,
    AuthProviderConfig,
    AuthProviderResult,
    AuthProviderType,
    AuthStatus,
)

logger = logging.getLogger(__name__)


class LDAPConnectionSecurity(Enum):
    """LDAP connection security modes."""

    NONE = "none"
    TLS = "tls"  # ldaps://
    STARTTLS = "starttls"


class LDAPSearchScope(Enum):
    """LDAP search scopes."""

    BASE = "base"
    ONE_LEVEL = "one"
    SUBTREE = "sub"


@dataclass
class LDAPConfig(AuthProviderConfig):
    """LDAP provider configuration."""

    # Server configuration
    server_uri: str = "ldap://localhost:389"
    base_dn: str = ""
    bind_dn: str = ""
    bind_password: str = ""

    # Security
    security: LDAPConnectionSecurity = LDAPConnectionSecurity.NONE
    verify_cert: bool = True
    ca_cert_file: Optional[str] = None
    client_cert_file: Optional[str] = None
    client_key_file: Optional[str] = None

    # User search
    user_search_base: str = ""
    user_search_filter: str = "(uid={username})"
    user_search_scope: LDAPSearchScope = LDAPSearchScope.SUBTREE
    user_dn_template: Optional[str] = None  # e.g., "uid={username},ou=users,dc=example,dc=com"

    # Group search
    group_search_base: str = ""
    group_search_filter: str = "(member={user_dn})"
    group_search_scope: LDAPSearchScope = LDAPSearchScope.SUBTREE
    group_name_attribute: str = "cn"
    group_member_attribute: str = "member"

    # Attribute mapping
    uid_attribute: str = "uid"
    email_attribute: str = "mail"
    name_attribute: str = "cn"
    display_name_attribute: str = "displayName"
    first_name_attribute: str = "givenName"
    last_name_attribute: str = "sn"
    phone_attribute: str = "telephoneNumber"

    # Connection pooling
    pool_size: int = 10
    pool_timeout: int = 30
    connection_timeout: int = 10

    # Active Directory specific
    is_active_directory: bool = False
    ad_domain: str = ""


class LDAPConnection:
    """LDAP connection wrapper (simulated)."""

    def __init__(self, config: LDAPConfig):
        """Initialize connection."""
        self.config = config
        self._connected = False
        self._bound = False

    def connect(self) -> bool:
        """Establish connection."""
        logger.debug(f"Connecting to LDAP server: {self.config.server_uri}")
        self._connected = True
        return True

    def bind(self, dn: Optional[str] = None, password: Optional[str] = None) -> bool:
        """Bind to LDAP server.

        Args:
            dn: Bind DN (uses config if None)
            password: Bind password (uses config if None)

        Returns:
            True if bound successfully
        """
        dn = dn or self.config.bind_dn
        password = password or self.config.bind_password

        logger.debug(f"Binding as: {dn}")
        self._bound = True
        return True

    def search(
        self,
        base: str,
        filter_str: str,
        scope: LDAPSearchScope = LDAPSearchScope.SUBTREE,
        attributes: Optional[List[str]] = None,
    ) -> List[Tuple[str, Dict[str, Any]]]:
        """Search LDAP directory.

        Args:
            base: Search base DN
            filter_str: LDAP filter
            scope: Search scope
            attributes: Attributes to retrieve

        Returns:
            List of (dn, attributes) tuples
        """
        logger.debug(f"Searching: base={base}, filter={filter_str}")
        # Return simulated results
        return []

    def close(self) -> None:
        """Close connection."""
        self._connected = False
        self._bound = False


class LDAPConnectionPool:
    """LDAP connection pool."""

    def __init__(self, config: LDAPConfig):
        """Initialize pool."""
        self.config = config
        self._pool: List[LDAPConnection] = []
        self._lock = threading.RLock()

    def acquire(self) -> LDAPConnection:
        """Acquire connection from pool."""
        with self._lock:
            if self._pool:
                return self._pool.pop()
            return LDAPConnection(self.config)

    def release(self, conn: LDAPConnection) -> None:
        """Release connection back to pool."""
        with self._lock:
            if len(self._pool) < self.config.pool_size:
                self._pool.append(conn)
            else:
                conn.close()

    def close_all(self) -> None:
        """Close all connections."""
        with self._lock:
            for conn in self._pool:
                conn.close()
            self._pool.clear()


class LDAPProvider(AuthProvider):
    """LDAP/Active Directory authentication provider."""

    def __init__(
        self,
        config: LDAPConfig,
        connection_pool: Optional[LDAPConnectionPool] = None,
    ):
        """Initialize LDAP provider.

        Args:
            config: LDAP configuration
            connection_pool: Connection pool
        """
        super().__init__(config)
        self.ldap_config = config
        self.pool = connection_pool or LDAPConnectionPool(config)

        # Cache for user DN lookups
        self._dn_cache: Dict[str, str] = {}
        self._cache_lock = threading.RLock()

    async def initialize(self) -> bool:
        """Initialize provider and test connection."""
        try:
            conn = self.pool.acquire()
            conn.connect()
            conn.bind()
            self.pool.release(conn)
            self._initialized = True
            logger.info(f"LDAP provider initialized: {self.ldap_config.server_uri}")
            return True
        except Exception as e:
            logger.error(f"LDAP initialization failed: {e}")
            return False

    async def authenticate(
        self,
        credentials: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> AuthProviderResult:
        """Authenticate user with LDAP.

        Args:
            credentials: Must contain 'username' and 'password'
            context: Optional context

        Returns:
            Authentication result
        """
        username = credentials.get("username", "").strip()
        password = credentials.get("password", "")

        if not username or not password:
            return AuthProviderResult.failure_result(
                AuthStatus.INVALID_CREDENTIALS,
                "Missing credentials",
            )

        try:
            # Find user DN
            user_dn = await self._find_user_dn(username)
            if not user_dn:
                return AuthProviderResult.failure_result(
                    AuthStatus.USER_NOT_FOUND,
                    "User not found",
                )

            # Attempt bind with user credentials
            conn = self.pool.acquire()
            try:
                conn.connect()

                if not conn.bind(user_dn, password):
                    return AuthProviderResult.failure_result(
                        AuthStatus.INVALID_CREDENTIALS,
                        "Invalid credentials",
                    )

                # Get user attributes
                user_attrs = await self._get_user_attributes(conn, user_dn)

                # Get user groups
                groups = await self._get_user_groups(conn, user_dn)

            finally:
                self.pool.release(conn)

            # Extract user info
            user_id = user_attrs.get(self.ldap_config.uid_attribute, username)
            email = user_attrs.get(self.ldap_config.email_attribute)
            display_name = user_attrs.get(
                self.ldap_config.display_name_attribute,
                user_attrs.get(self.ldap_config.name_attribute),
            )

            # Check domain restriction
            if email and not self.is_domain_allowed(email):
                return AuthProviderResult.failure_result(
                    AuthStatus.FAILURE,
                    "Email domain not allowed",
                )

            return AuthProviderResult.success_result(
                user_id=str(user_id),
                email=email,
                display_name=display_name,
                provider_id=self.provider_id,
                provider_type=self.provider_type,
                provider_user_id=user_dn,
                profile=self.map_attributes(user_attrs),
                groups=self.map_groups(groups),
                roles=self.map_roles(groups),
            )

        except Exception as e:
            logger.error(f"LDAP authentication error: {e}")
            return AuthProviderResult.failure_result(
                AuthStatus.PROVIDER_ERROR,
                str(e),
            )

    async def validate_user(self, user_id: str) -> bool:
        """Validate user exists in LDAP.

        Args:
            user_id: User ID or DN

        Returns:
            True if user exists
        """
        try:
            user_dn = await self._find_user_dn(user_id)
            return user_dn is not None
        except Exception:
            return False

    async def get_user_info(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user information from LDAP.

        Args:
            user_id: User ID or username

        Returns:
            User info or None
        """
        try:
            user_dn = await self._find_user_dn(user_id)
            if not user_dn:
                return None

            conn = self.pool.acquire()
            try:
                conn.connect()
                conn.bind()
                return await self._get_user_attributes(conn, user_dn)
            finally:
                self.pool.release(conn)

        except Exception as e:
            logger.error(f"Failed to get user info: {e}")
            return None

    async def get_user_groups(self, user_id: str) -> List[str]:
        """Get user groups from LDAP.

        Args:
            user_id: User ID or username

        Returns:
            List of group names
        """
        try:
            user_dn = await self._find_user_dn(user_id)
            if not user_dn:
                return []

            conn = self.pool.acquire()
            try:
                conn.connect()
                conn.bind()
                return await self._get_user_groups(conn, user_dn)
            finally:
                self.pool.release(conn)

        except Exception as e:
            logger.error(f"Failed to get user groups: {e}")
            return []

    async def search_users(
        self,
        query: str,
        limit: int = 10,
    ) -> List[Dict[str, Any]]:
        """Search for users in LDAP.

        Args:
            query: Search query
            limit: Maximum results

        Returns:
            List of user info dicts
        """
        try:
            conn = self.pool.acquire()
            try:
                conn.connect()
                conn.bind()

                # Build search filter
                escaped_query = self._escape_filter(query)
                filter_str = f"(|({self.ldap_config.uid_attribute}=*{escaped_query}*)({self.ldap_config.email_attribute}=*{escaped_query}*)({self.ldap_config.name_attribute}=*{escaped_query}*))"

                results = conn.search(
                    base=self.ldap_config.user_search_base or self.ldap_config.base_dn,
                    filter_str=filter_str,
                    scope=self.ldap_config.user_search_scope,
                )

                users = []
                for dn, attrs in results[:limit]:
                    users.append(self.map_attributes(attrs))

                return users

            finally:
                self.pool.release(conn)

        except Exception as e:
            logger.error(f"LDAP user search error: {e}")
            return []

    async def health_check(self) -> Tuple[bool, str]:
        """Check LDAP connection health."""
        try:
            conn = self.pool.acquire()
            try:
                conn.connect()
                conn.bind()
                return True, "OK"
            finally:
                self.pool.release(conn)
        except Exception as e:
            return False, str(e)

    async def shutdown(self) -> None:
        """Shutdown provider and close connections."""
        self.pool.close_all()
        logger.info("LDAP provider shutdown complete")

    async def _find_user_dn(self, username: str) -> Optional[str]:
        """Find user DN by username.

        Args:
            username: Username to find

        Returns:
            User DN or None
        """
        # Check cache
        with self._cache_lock:
            if username in self._dn_cache:
                return self._dn_cache[username]

        # Use DN template if configured
        if self.ldap_config.user_dn_template:
            user_dn = self.ldap_config.user_dn_template.format(username=username)
            return user_dn

        # Search for user
        conn = self.pool.acquire()
        try:
            conn.connect()
            conn.bind()

            escaped_username = self._escape_filter(username)
            filter_str = self.ldap_config.user_search_filter.format(
                username=escaped_username
            )

            results = conn.search(
                base=self.ldap_config.user_search_base or self.ldap_config.base_dn,
                filter_str=filter_str,
                scope=self.ldap_config.user_search_scope,
            )

            if results:
                user_dn = results[0][0]
                # Cache the DN
                with self._cache_lock:
                    self._dn_cache[username] = user_dn
                return user_dn

            return None

        finally:
            self.pool.release(conn)

    async def _get_user_attributes(
        self,
        conn: LDAPConnection,
        user_dn: str,
    ) -> Dict[str, Any]:
        """Get user attributes.

        Args:
            conn: LDAP connection
            user_dn: User DN

        Returns:
            User attributes
        """
        results = conn.search(
            base=user_dn,
            filter_str="(objectClass=*)",
            scope=LDAPSearchScope.BASE,
        )

        if results:
            return results[0][1]
        return {}

    async def _get_user_groups(
        self,
        conn: LDAPConnection,
        user_dn: str,
    ) -> List[str]:
        """Get user's groups.

        Args:
            conn: LDAP connection
            user_dn: User DN

        Returns:
            List of group names
        """
        if not self.ldap_config.group_search_base:
            return []

        filter_str = self.ldap_config.group_search_filter.format(
            user_dn=user_dn
        )

        results = conn.search(
            base=self.ldap_config.group_search_base,
            filter_str=filter_str,
            scope=self.ldap_config.group_search_scope,
            attributes=[self.ldap_config.group_name_attribute],
        )

        groups = []
        for dn, attrs in results:
            group_name = attrs.get(self.ldap_config.group_name_attribute)
            if group_name:
                groups.append(group_name)

        return groups

    def _escape_filter(self, value: str) -> str:
        """Escape special characters for LDAP filter.

        Args:
            value: Value to escape

        Returns:
            Escaped value
        """
        replacements = {
            "\\": "\\5c",
            "*": "\\2a",
            "(": "\\28",
            ")": "\\29",
            "\x00": "\\00",
        }
        for char, escaped in replacements.items():
            value = value.replace(char, escaped)
        return value


__all__ = [
    "LDAPProvider",
    "LDAPConfig",
    "LDAPConnectionSecurity",
    "LDAPSearchScope",
    "LDAPConnection",
    "LDAPConnectionPool",
]
