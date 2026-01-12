"""RoadAuth Roles - Role-Based Access Control (RBAC) system.

Provides comprehensive RBAC including:
- Role definitions with hierarchies
- Permission management
- Policy evaluation
- Attribute-Based Access Control (ABAC) support

Copyright (c) 2024-2026 BlackRoad OS, Inc. All rights reserved.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

# Configure logging
logger = logging.getLogger(__name__)


class PermissionEffect(Enum):
    """Permission effect."""

    ALLOW = "allow"
    DENY = "deny"


@dataclass
class Permission:
    """Permission definition.

    Permissions follow the format: resource:action or resource:action:scope
    Examples:
        - users:read
        - users:write
        - posts:delete:own
        - admin:*
        - *
    """

    resource: str
    action: str
    scope: Optional[str] = None
    effect: PermissionEffect = PermissionEffect.ALLOW
    conditions: Dict[str, Any] = field(default_factory=dict)

    @property
    def name(self) -> str:
        """Get permission name."""
        parts = [self.resource, self.action]
        if self.scope:
            parts.append(self.scope)
        return ":".join(parts)

    @classmethod
    def from_string(cls, permission_str: str, effect: PermissionEffect = PermissionEffect.ALLOW) -> Permission:
        """Create permission from string.

        Args:
            permission_str: Permission string (e.g., "users:read")
            effect: Permission effect

        Returns:
            Permission instance
        """
        parts = permission_str.split(":")
        resource = parts[0] if parts else "*"
        action = parts[1] if len(parts) > 1 else "*"
        scope = parts[2] if len(parts) > 2 else None

        return cls(resource=resource, action=action, scope=scope, effect=effect)

    def matches(self, resource: str, action: str, scope: Optional[str] = None) -> bool:
        """Check if this permission matches the given resource/action.

        Args:
            resource: Resource to check
            action: Action to check
            scope: Optional scope to check

        Returns:
            True if matches
        """
        # Check resource
        if self.resource != "*" and self.resource != resource:
            return False

        # Check action
        if self.action != "*" and self.action != action:
            return False

        # Check scope
        if self.scope and scope and self.scope != "*" and self.scope != scope:
            return False

        return True

    def __hash__(self) -> int:
        return hash(self.name)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Permission):
            return self.name == other.name
        return False


@dataclass
class Role:
    """Role definition.

    Roles group permissions and can inherit from parent roles.
    """

    name: str
    description: Optional[str] = None
    permissions: Set[Permission] = field(default_factory=set)
    parent_roles: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)

    # System flag - system roles cannot be modified
    is_system: bool = False

    def add_permission(self, permission: Union[str, Permission]) -> None:
        """Add permission to role.

        Args:
            permission: Permission to add
        """
        if isinstance(permission, str):
            permission = Permission.from_string(permission)
        self.permissions.add(permission)
        self.updated_at = datetime.now()

    def remove_permission(self, permission: Union[str, Permission]) -> bool:
        """Remove permission from role.

        Args:
            permission: Permission to remove

        Returns:
            True if removed
        """
        if isinstance(permission, str):
            permission = Permission.from_string(permission)

        try:
            self.permissions.remove(permission)
            self.updated_at = datetime.now()
            return True
        except KeyError:
            return False

    def has_permission(self, resource: str, action: str, scope: Optional[str] = None) -> bool:
        """Check if role has permission.

        Args:
            resource: Resource to check
            action: Action to check
            scope: Optional scope

        Returns:
            True if role has permission
        """
        for perm in self.permissions:
            if perm.matches(resource, action, scope):
                return perm.effect == PermissionEffect.ALLOW
        return False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "description": self.description,
            "permissions": [p.name for p in self.permissions],
            "parent_roles": self.parent_roles,
            "is_system": self.is_system,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "metadata": self.metadata,
        }


class RoleManager:
    """Manages roles and their permissions."""

    # Built-in system roles
    SYSTEM_ROLES = {
        "admin": Role(
            name="admin",
            description="Full administrative access",
            permissions={Permission.from_string("*")},
            is_system=True,
        ),
        "user": Role(
            name="user",
            description="Standard user access",
            permissions={
                Permission.from_string("profile:read"),
                Permission.from_string("profile:update:own"),
            },
            is_system=True,
        ),
        "guest": Role(
            name="guest",
            description="Limited guest access",
            permissions={
                Permission.from_string("public:read"),
            },
            is_system=True,
        ),
    }

    def __init__(self):
        """Initialize role manager."""
        self._roles: Dict[str, Role] = {}
        self._lock = threading.RLock()

        # Initialize system roles
        for name, role in self.SYSTEM_ROLES.items():
            self._roles[name] = role

    def create(
        self,
        name: str,
        description: Optional[str] = None,
        permissions: Optional[List[str]] = None,
        parent_roles: Optional[List[str]] = None,
    ) -> Role:
        """Create a new role.

        Args:
            name: Role name
            description: Role description
            permissions: Initial permissions
            parent_roles: Parent roles to inherit from

        Returns:
            Created role

        Raises:
            ValueError: If role exists or parent doesn't exist
        """
        with self._lock:
            if name in self._roles:
                raise ValueError(f"Role already exists: {name}")

            # Validate parent roles
            for parent in (parent_roles or []):
                if parent not in self._roles:
                    raise ValueError(f"Parent role not found: {parent}")

            role = Role(
                name=name,
                description=description,
                parent_roles=parent_roles or [],
            )

            # Add permissions
            for perm_str in (permissions or []):
                role.add_permission(perm_str)

            self._roles[name] = role
            logger.info(f"Role created: {name}")
            return role

    def get(self, name: str) -> Optional[Role]:
        """Get role by name."""
        return self._roles.get(name)

    def update(self, name: str, **updates) -> Optional[Role]:
        """Update role.

        Args:
            name: Role name
            **updates: Fields to update

        Returns:
            Updated role or None
        """
        with self._lock:
            role = self._roles.get(name)
            if not role:
                return None

            if role.is_system:
                raise ValueError("Cannot modify system roles")

            for key, value in updates.items():
                if hasattr(role, key) and key not in ("name", "is_system", "created_at"):
                    setattr(role, key, value)

            role.updated_at = datetime.now()
            return role

    def delete(self, name: str) -> bool:
        """Delete role.

        Args:
            name: Role name

        Returns:
            True if deleted
        """
        with self._lock:
            role = self._roles.get(name)
            if not role:
                return False

            if role.is_system:
                raise ValueError("Cannot delete system roles")

            del self._roles[name]
            logger.info(f"Role deleted: {name}")
            return True

    def list_roles(self) -> List[Role]:
        """List all roles."""
        return list(self._roles.values())

    def add_permission(self, role_name: str, permission: str) -> bool:
        """Add permission to role.

        Args:
            role_name: Role name
            permission: Permission to add

        Returns:
            True if added
        """
        with self._lock:
            role = self._roles.get(role_name)
            if not role:
                return False

            if role.is_system:
                raise ValueError("Cannot modify system roles")

            role.add_permission(permission)
            return True

    def remove_permission(self, role_name: str, permission: str) -> bool:
        """Remove permission from role.

        Args:
            role_name: Role name
            permission: Permission to remove

        Returns:
            True if removed
        """
        with self._lock:
            role = self._roles.get(role_name)
            if not role:
                return False

            if role.is_system:
                raise ValueError("Cannot modify system roles")

            return role.remove_permission(permission)

    def get_effective_permissions(self, role_name: str, visited: Optional[Set[str]] = None) -> Set[Permission]:
        """Get all effective permissions including inherited.

        Args:
            role_name: Role name
            visited: Set of visited roles (for cycle detection)

        Returns:
            Set of all permissions
        """
        if visited is None:
            visited = set()

        if role_name in visited:
            return set()  # Cycle detected

        visited.add(role_name)

        role = self._roles.get(role_name)
        if not role:
            return set()

        # Start with role's own permissions
        permissions = set(role.permissions)

        # Add inherited permissions
        for parent_name in role.parent_roles:
            permissions.update(self.get_effective_permissions(parent_name, visited))

        return permissions


class RBAC:
    """Role-Based Access Control evaluator.

    Evaluates permissions for users based on their assigned roles.
    Supports both RBAC and ABAC (Attribute-Based Access Control).
    """

    def __init__(self, role_manager: Optional[RoleManager] = None):
        """Initialize RBAC.

        Args:
            role_manager: Role manager instance
        """
        self.role_manager = role_manager or RoleManager()
        self._policies: List[Policy] = []
        self._lock = threading.RLock()

    def check(
        self,
        user_roles: List[str],
        resource: str,
        action: str,
        scope: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, str]:
        """Check if user has permission.

        Args:
            user_roles: User's assigned roles
            resource: Resource to access
            action: Action to perform
            scope: Optional scope
            context: Additional context for ABAC

        Returns:
            (is_allowed, reason)
        """
        # Collect all permissions from all roles
        all_permissions: Set[Permission] = set()
        for role_name in user_roles:
            all_permissions.update(self.role_manager.get_effective_permissions(role_name))

        # Check deny permissions first
        for perm in all_permissions:
            if perm.effect == PermissionEffect.DENY and perm.matches(resource, action, scope):
                return False, f"Denied by permission: {perm.name}"

        # Check allow permissions
        for perm in all_permissions:
            if perm.effect == PermissionEffect.ALLOW and perm.matches(resource, action, scope):
                # Check conditions if any
                if perm.conditions and context:
                    if not self._evaluate_conditions(perm.conditions, context):
                        continue
                return True, f"Allowed by permission: {perm.name}"

        # Check policies
        for policy in self._policies:
            result, reason = policy.evaluate(user_roles, resource, action, scope, context)
            if result is not None:
                return result, reason

        return False, "No matching permission"

    def add_policy(self, policy: Policy) -> None:
        """Add an access policy.

        Args:
            policy: Policy to add
        """
        with self._lock:
            self._policies.append(policy)
            # Sort by priority (higher priority first)
            self._policies.sort(key=lambda p: p.priority, reverse=True)

    def remove_policy(self, policy_name: str) -> bool:
        """Remove a policy by name.

        Args:
            policy_name: Policy name

        Returns:
            True if removed
        """
        with self._lock:
            for i, policy in enumerate(self._policies):
                if policy.name == policy_name:
                    del self._policies[i]
                    return True
            return False

    def _evaluate_conditions(self, conditions: Dict[str, Any], context: Dict[str, Any]) -> bool:
        """Evaluate ABAC conditions.

        Args:
            conditions: Condition dictionary
            context: Context dictionary

        Returns:
            True if all conditions are met
        """
        for key, expected in conditions.items():
            actual = context.get(key)

            # Handle operators
            if key.endswith("_in"):
                base_key = key[:-3]
                actual = context.get(base_key)
                if actual not in expected:
                    return False
            elif key.endswith("_not_in"):
                base_key = key[:-7]
                actual = context.get(base_key)
                if actual in expected:
                    return False
            elif key.endswith("_gt"):
                base_key = key[:-3]
                actual = context.get(base_key)
                if actual is None or actual <= expected:
                    return False
            elif key.endswith("_lt"):
                base_key = key[:-3]
                actual = context.get(base_key)
                if actual is None or actual >= expected:
                    return False
            elif actual != expected:
                return False

        return True


@dataclass
class Policy:
    """Access control policy for ABAC.

    Policies provide fine-grained access control based on
    attributes of the user, resource, and environment.
    """

    name: str
    description: Optional[str] = None
    priority: int = 0
    effect: PermissionEffect = PermissionEffect.ALLOW

    # Matching criteria
    roles: Optional[List[str]] = None
    resources: Optional[List[str]] = None
    actions: Optional[List[str]] = None

    # Conditions
    conditions: Dict[str, Any] = field(default_factory=dict)

    def evaluate(
        self,
        user_roles: List[str],
        resource: str,
        action: str,
        scope: Optional[str],
        context: Optional[Dict[str, Any]],
    ) -> Tuple[Optional[bool], str]:
        """Evaluate policy for access request.

        Args:
            user_roles: User's roles
            resource: Target resource
            action: Requested action
            scope: Optional scope
            context: Additional context

        Returns:
            (result, reason) or (None, "") if policy doesn't apply
        """
        # Check if policy applies to roles
        if self.roles and not any(r in self.roles for r in user_roles):
            return None, ""

        # Check if policy applies to resource
        if self.resources and not self._matches_any(resource, self.resources):
            return None, ""

        # Check if policy applies to action
        if self.actions and not self._matches_any(action, self.actions):
            return None, ""

        # Evaluate conditions
        if self.conditions and context:
            for key, expected in self.conditions.items():
                actual = context.get(key)
                if not self._matches_condition(key, expected, actual, context):
                    return None, ""

        # Policy applies
        result = self.effect == PermissionEffect.ALLOW
        reason = f"{'Allowed' if result else 'Denied'} by policy: {self.name}"
        return result, reason

    def _matches_any(self, value: str, patterns: List[str]) -> bool:
        """Check if value matches any pattern."""
        for pattern in patterns:
            if pattern == "*":
                return True
            if pattern.endswith("*"):
                if value.startswith(pattern[:-1]):
                    return True
            elif pattern == value:
                return True
        return False

    def _matches_condition(
        self,
        key: str,
        expected: Any,
        actual: Any,
        context: Dict[str, Any],
    ) -> bool:
        """Check if condition is met."""
        if key.endswith("_eq"):
            return actual == expected
        if key.endswith("_ne"):
            return actual != expected
        if key.endswith("_in"):
            return actual in expected
        if key.endswith("_contains"):
            return expected in actual if actual else False
        return actual == expected


__all__ = [
    "Permission",
    "PermissionEffect",
    "Role",
    "RoleManager",
    "RBAC",
    "Policy",
]
