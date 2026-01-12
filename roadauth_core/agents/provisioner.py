"""RoadAuth Provisioner Agent - User Lifecycle Management.

The Provisioner agent handles automated user lifecycle:
- Just-in-time (JIT) user provisioning
- SCIM 2.0 support
- User synchronization from identity providers
- Account deprovisioning
- Group membership management

Copyright (c) 2024-2026 BlackRoad OS, Inc. All rights reserved.
"""

from __future__ import annotations

import logging
import secrets
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class ProvisioningAction(Enum):
    """Provisioning actions."""

    CREATE = auto()
    UPDATE = auto()
    DISABLE = auto()
    ENABLE = auto()
    DELETE = auto()
    SYNC = auto()


class ProvisioningStatus(Enum):
    """Provisioning operation status."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    RETRYING = "retrying"


@dataclass
class ProvisioningOperation:
    """Provisioning operation record."""

    id: str
    action: ProvisioningAction
    status: ProvisioningStatus = ProvisioningStatus.PENDING
    created_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    # User info
    user_id: Optional[str] = None
    external_id: Optional[str] = None
    provider_id: Optional[str] = None

    # Operation data
    data: Dict[str, Any] = field(default_factory=dict)
    result: Dict[str, Any] = field(default_factory=dict)

    # Error handling
    error: Optional[str] = None
    retry_count: int = 0
    max_retries: int = 3

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "action": self.action.name,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "user_id": self.user_id,
            "external_id": self.external_id,
            "provider_id": self.provider_id,
            "error": self.error,
            "retry_count": self.retry_count,
        }


@dataclass
class ProvisioningRule:
    """Rule for automatic provisioning."""

    id: str
    name: str
    enabled: bool = True
    priority: int = 0

    # Matching conditions
    provider_id: Optional[str] = None
    email_domains: List[str] = field(default_factory=list)
    group_patterns: List[str] = field(default_factory=list)

    # Provisioning settings
    default_roles: List[str] = field(default_factory=list)
    default_groups: List[str] = field(default_factory=list)

    # Options
    auto_enable: bool = True
    require_email_verification: bool = False
    sync_groups: bool = True
    sync_attributes: List[str] = field(default_factory=list)


@dataclass
class UserProvisioningData:
    """Data for user provisioning."""

    external_id: str
    email: str
    username: Optional[str] = None
    display_name: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    phone: Optional[str] = None
    groups: List[str] = field(default_factory=list)
    roles: List[str] = field(default_factory=list)
    attributes: Dict[str, Any] = field(default_factory=dict)
    provider_id: Optional[str] = None


class ProvisioningStore:
    """In-memory provisioning store."""

    def __init__(self):
        """Initialize store."""
        self._operations: Dict[str, ProvisioningOperation] = {}
        self._by_user: Dict[str, List[str]] = defaultdict(list)
        self._pending: List[str] = []
        self._lock = threading.RLock()

    def save(self, operation: ProvisioningOperation) -> None:
        """Save operation."""
        with self._lock:
            self._operations[operation.id] = operation
            if operation.user_id:
                self._by_user[operation.user_id].append(operation.id)
            if operation.status == ProvisioningStatus.PENDING:
                if operation.id not in self._pending:
                    self._pending.append(operation.id)

    def get(self, operation_id: str) -> Optional[ProvisioningOperation]:
        """Get operation by ID."""
        return self._operations.get(operation_id)

    def get_pending(self, limit: int = 10) -> List[ProvisioningOperation]:
        """Get pending operations."""
        with self._lock:
            operations = []
            for op_id in self._pending[:limit]:
                op = self._operations.get(op_id)
                if op and op.status == ProvisioningStatus.PENDING:
                    operations.append(op)
            return operations

    def complete(self, operation_id: str) -> None:
        """Mark operation as completed."""
        with self._lock:
            if operation_id in self._pending:
                self._pending.remove(operation_id)

    def get_by_user(self, user_id: str) -> List[ProvisioningOperation]:
        """Get operations for user."""
        op_ids = self._by_user.get(user_id, [])
        return [self._operations[oid] for oid in op_ids if oid in self._operations]


class SCIMParser:
    """SCIM 2.0 message parser."""

    @staticmethod
    def parse_user(scim_data: Dict[str, Any]) -> UserProvisioningData:
        """Parse SCIM user resource.

        Args:
            scim_data: SCIM user JSON

        Returns:
            Parsed user data
        """
        # Extract core attributes
        external_id = scim_data.get("externalId") or scim_data.get("id", "")
        username = scim_data.get("userName", "")

        # Extract name
        name = scim_data.get("name", {})
        display_name = scim_data.get("displayName")
        first_name = name.get("givenName")
        last_name = name.get("familyName")

        if not display_name and first_name and last_name:
            display_name = f"{first_name} {last_name}"

        # Extract email
        emails = scim_data.get("emails", [])
        primary_email = ""
        for email in emails:
            if isinstance(email, dict):
                if email.get("primary"):
                    primary_email = email.get("value", "")
                    break
                elif not primary_email:
                    primary_email = email.get("value", "")
            elif isinstance(email, str):
                primary_email = email
                break

        # Extract phone
        phones = scim_data.get("phoneNumbers", [])
        phone = ""
        for p in phones:
            if isinstance(p, dict):
                if p.get("primary"):
                    phone = p.get("value", "")
                    break
                elif not phone:
                    phone = p.get("value", "")

        # Extract groups
        groups = []
        for group in scim_data.get("groups", []):
            if isinstance(group, dict):
                groups.append(group.get("display") or group.get("value", ""))
            elif isinstance(group, str):
                groups.append(group)

        # Extract roles
        roles = []
        for role in scim_data.get("roles", []):
            if isinstance(role, dict):
                roles.append(role.get("value", ""))
            elif isinstance(role, str):
                roles.append(role)

        return UserProvisioningData(
            external_id=external_id,
            email=primary_email,
            username=username,
            display_name=display_name,
            first_name=first_name,
            last_name=last_name,
            phone=phone,
            groups=groups,
            roles=roles,
            attributes=scim_data.get("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User", {}),
        )

    @staticmethod
    def to_scim_user(user: Dict[str, Any]) -> Dict[str, Any]:
        """Convert user to SCIM format.

        Args:
            user: Internal user data

        Returns:
            SCIM user resource
        """
        scim = {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "id": user.get("id"),
            "externalId": user.get("external_id"),
            "userName": user.get("username") or user.get("email"),
            "name": {
                "givenName": user.get("first_name"),
                "familyName": user.get("last_name"),
                "formatted": user.get("display_name"),
            },
            "displayName": user.get("display_name"),
            "active": user.get("is_active", True),
            "emails": [
                {
                    "value": user.get("email"),
                    "type": "work",
                    "primary": True,
                }
            ] if user.get("email") else [],
            "meta": {
                "resourceType": "User",
                "created": user.get("created_at"),
                "lastModified": user.get("updated_at"),
            },
        }

        if user.get("phone"):
            scim["phoneNumbers"] = [
                {
                    "value": user.get("phone"),
                    "type": "work",
                    "primary": True,
                }
            ]

        return scim


class Provisioner:
    """Provisioner Agent - User Lifecycle Management.

    The Provisioner handles automated user provisioning,
    synchronization, and lifecycle management across
    identity providers.
    """

    def __init__(
        self,
        store: Optional[ProvisioningStore] = None,
        user_callback: Optional[Callable[[str, Dict[str, Any]], Optional[Dict[str, Any]]]] = None,
    ):
        """Initialize Provisioner.

        Args:
            store: Provisioning store
            user_callback: Callback for user operations
        """
        self.store = store or ProvisioningStore()
        self._user_callback = user_callback

        # Rules
        self._rules: Dict[str, ProvisioningRule] = {}
        self._rule_order: List[str] = []

        # Mappings
        self._external_to_internal: Dict[str, str] = {}  # external_id -> internal_id
        self._internal_to_external: Dict[str, str] = {}

        # Statistics
        self._stats = {
            "created": 0,
            "updated": 0,
            "disabled": 0,
            "enabled": 0,
            "deleted": 0,
            "synced": 0,
            "failed": 0,
        }

        self._lock = threading.RLock()

    def provision(
        self,
        user_data: UserProvisioningData,
        force_create: bool = False,
    ) -> Tuple[str, ProvisioningOperation]:
        """Provision a user.

        Args:
            user_data: User provisioning data
            force_create: Force creation even if user exists

        Returns:
            (user_id, operation)
        """
        # Check if user exists
        existing_user_id = self._external_to_internal.get(user_data.external_id)

        if existing_user_id and not force_create:
            # Update existing user
            return self.update(existing_user_id, user_data)

        # Create new user
        return self.create(user_data)

    def create(self, user_data: UserProvisioningData) -> Tuple[str, ProvisioningOperation]:
        """Create a new user.

        Args:
            user_data: User data

        Returns:
            (user_id, operation)
        """
        operation = ProvisioningOperation(
            id=secrets.token_urlsafe(16),
            action=ProvisioningAction.CREATE,
            external_id=user_data.external_id,
            provider_id=user_data.provider_id,
            data=self._user_data_to_dict(user_data),
        )

        try:
            operation.status = ProvisioningStatus.IN_PROGRESS
            operation.started_at = datetime.now()

            # Apply rules
            rules = self._match_rules(user_data)
            for rule in rules:
                user_data.roles.extend(rule.default_roles)
                user_data.groups.extend(rule.default_groups)

            # Create user via callback
            if self._user_callback:
                result = self._user_callback("create", self._user_data_to_dict(user_data))
                if result:
                    user_id = result.get("id", secrets.token_urlsafe(16))
                else:
                    raise Exception("User creation failed")
            else:
                user_id = secrets.token_urlsafe(16)

            # Update mappings
            with self._lock:
                self._external_to_internal[user_data.external_id] = user_id
                self._internal_to_external[user_id] = user_data.external_id

            operation.user_id = user_id
            operation.status = ProvisioningStatus.COMPLETED
            operation.completed_at = datetime.now()
            operation.result = {"user_id": user_id}

            self._stats["created"] += 1
            logger.info(f"Provisioned user: {user_id}")

        except Exception as e:
            operation.status = ProvisioningStatus.FAILED
            operation.error = str(e)
            self._stats["failed"] += 1
            logger.error(f"Provisioning failed: {e}")

        self.store.save(operation)
        return operation.user_id or "", operation

    def update(
        self,
        user_id: str,
        user_data: UserProvisioningData,
    ) -> Tuple[str, ProvisioningOperation]:
        """Update an existing user.

        Args:
            user_id: Internal user ID
            user_data: Updated data

        Returns:
            (user_id, operation)
        """
        operation = ProvisioningOperation(
            id=secrets.token_urlsafe(16),
            action=ProvisioningAction.UPDATE,
            user_id=user_id,
            external_id=user_data.external_id,
            provider_id=user_data.provider_id,
            data=self._user_data_to_dict(user_data),
        )

        try:
            operation.status = ProvisioningStatus.IN_PROGRESS
            operation.started_at = datetime.now()

            # Update via callback
            if self._user_callback:
                result = self._user_callback("update", {
                    "id": user_id,
                    **self._user_data_to_dict(user_data)
                })

            operation.status = ProvisioningStatus.COMPLETED
            operation.completed_at = datetime.now()
            self._stats["updated"] += 1
            logger.info(f"Updated user: {user_id}")

        except Exception as e:
            operation.status = ProvisioningStatus.FAILED
            operation.error = str(e)
            self._stats["failed"] += 1

        self.store.save(operation)
        return user_id, operation

    def disable(self, user_id: str, reason: str = "") -> ProvisioningOperation:
        """Disable a user.

        Args:
            user_id: User ID
            reason: Disable reason

        Returns:
            Operation record
        """
        operation = ProvisioningOperation(
            id=secrets.token_urlsafe(16),
            action=ProvisioningAction.DISABLE,
            user_id=user_id,
            data={"reason": reason},
        )

        try:
            operation.status = ProvisioningStatus.IN_PROGRESS
            operation.started_at = datetime.now()

            if self._user_callback:
                self._user_callback("disable", {"id": user_id, "reason": reason})

            operation.status = ProvisioningStatus.COMPLETED
            operation.completed_at = datetime.now()
            self._stats["disabled"] += 1
            logger.info(f"Disabled user: {user_id}")

        except Exception as e:
            operation.status = ProvisioningStatus.FAILED
            operation.error = str(e)
            self._stats["failed"] += 1

        self.store.save(operation)
        return operation

    def enable(self, user_id: str) -> ProvisioningOperation:
        """Enable a user.

        Args:
            user_id: User ID

        Returns:
            Operation record
        """
        operation = ProvisioningOperation(
            id=secrets.token_urlsafe(16),
            action=ProvisioningAction.ENABLE,
            user_id=user_id,
        )

        try:
            operation.status = ProvisioningStatus.IN_PROGRESS
            operation.started_at = datetime.now()

            if self._user_callback:
                self._user_callback("enable", {"id": user_id})

            operation.status = ProvisioningStatus.COMPLETED
            operation.completed_at = datetime.now()
            self._stats["enabled"] += 1
            logger.info(f"Enabled user: {user_id}")

        except Exception as e:
            operation.status = ProvisioningStatus.FAILED
            operation.error = str(e)
            self._stats["failed"] += 1

        self.store.save(operation)
        return operation

    def deprovision(self, user_id: str, hard_delete: bool = False) -> ProvisioningOperation:
        """Deprovision (delete) a user.

        Args:
            user_id: User ID
            hard_delete: Permanently delete user data

        Returns:
            Operation record
        """
        operation = ProvisioningOperation(
            id=secrets.token_urlsafe(16),
            action=ProvisioningAction.DELETE,
            user_id=user_id,
            data={"hard_delete": hard_delete},
        )

        try:
            operation.status = ProvisioningStatus.IN_PROGRESS
            operation.started_at = datetime.now()

            # Remove from mappings
            with self._lock:
                external_id = self._internal_to_external.pop(user_id, None)
                if external_id:
                    self._external_to_internal.pop(external_id, None)

            if self._user_callback:
                self._user_callback("delete", {"id": user_id, "hard_delete": hard_delete})

            operation.status = ProvisioningStatus.COMPLETED
            operation.completed_at = datetime.now()
            self._stats["deleted"] += 1
            logger.info(f"Deprovisioned user: {user_id}")

        except Exception as e:
            operation.status = ProvisioningStatus.FAILED
            operation.error = str(e)
            self._stats["failed"] += 1

        self.store.save(operation)
        return operation

    def sync_from_provider(
        self,
        provider_id: str,
        users: List[UserProvisioningData],
    ) -> List[ProvisioningOperation]:
        """Sync users from identity provider.

        Args:
            provider_id: Provider ID
            users: List of user data from provider

        Returns:
            List of operations performed
        """
        operations = []

        for user_data in users:
            user_data.provider_id = provider_id
            user_id, operation = self.provision(user_data)
            operations.append(operation)

        self._stats["synced"] += len([o for o in operations if o.status == ProvisioningStatus.COMPLETED])
        return operations

    def handle_scim_request(
        self,
        method: str,
        resource_type: str,
        resource_id: Optional[str] = None,
        data: Optional[Dict[str, Any]] = None,
    ) -> Tuple[int, Dict[str, Any]]:
        """Handle SCIM 2.0 request.

        Args:
            method: HTTP method
            resource_type: Resource type (Users, Groups)
            resource_id: Resource ID
            data: Request body

        Returns:
            (status_code, response_body)
        """
        if resource_type != "Users":
            return 501, {"detail": "Resource type not supported"}

        if method == "POST":
            # Create user
            if not data:
                return 400, {"detail": "Missing request body"}

            user_data = SCIMParser.parse_user(data)
            user_id, operation = self.create(user_data)

            if operation.status == ProvisioningStatus.COMPLETED:
                return 201, {
                    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                    "id": user_id,
                    "externalId": user_data.external_id,
                    "meta": {
                        "resourceType": "User",
                        "created": operation.completed_at.isoformat() if operation.completed_at else None,
                    },
                }
            else:
                return 400, {"detail": operation.error or "Creation failed"}

        elif method == "PUT":
            # Update user
            if not resource_id or not data:
                return 400, {"detail": "Missing resource ID or body"}

            user_id = self._external_to_internal.get(resource_id, resource_id)
            user_data = SCIMParser.parse_user(data)
            _, operation = self.update(user_id, user_data)

            if operation.status == ProvisioningStatus.COMPLETED:
                return 200, {"id": user_id}
            else:
                return 400, {"detail": operation.error or "Update failed"}

        elif method == "DELETE":
            # Delete user
            if not resource_id:
                return 400, {"detail": "Missing resource ID"}

            user_id = self._external_to_internal.get(resource_id, resource_id)
            operation = self.deprovision(user_id)

            if operation.status == ProvisioningStatus.COMPLETED:
                return 204, {}
            else:
                return 400, {"detail": operation.error or "Delete failed"}

        else:
            return 405, {"detail": "Method not allowed"}

    def add_rule(self, rule: ProvisioningRule) -> None:
        """Add provisioning rule."""
        with self._lock:
            self._rules[rule.id] = rule
            self._rule_order.append(rule.id)
            self._rule_order.sort(key=lambda rid: self._rules[rid].priority)

    def remove_rule(self, rule_id: str) -> bool:
        """Remove provisioning rule."""
        with self._lock:
            if rule_id in self._rules:
                del self._rules[rule_id]
                self._rule_order.remove(rule_id)
                return True
            return False

    def _match_rules(self, user_data: UserProvisioningData) -> List[ProvisioningRule]:
        """Find matching provisioning rules."""
        matched = []

        for rule_id in self._rule_order:
            rule = self._rules.get(rule_id)
            if not rule or not rule.enabled:
                continue

            # Check provider match
            if rule.provider_id and rule.provider_id != user_data.provider_id:
                continue

            # Check email domain
            if rule.email_domains:
                domain = user_data.email.split("@")[1] if "@" in user_data.email else ""
                if domain not in rule.email_domains:
                    continue

            # Check group patterns
            if rule.group_patterns:
                has_match = False
                for pattern in rule.group_patterns:
                    for group in user_data.groups:
                        if pattern in group:
                            has_match = True
                            break
                    if has_match:
                        break
                if not has_match:
                    continue

            matched.append(rule)

        return matched

    def _user_data_to_dict(self, user_data: UserProvisioningData) -> Dict[str, Any]:
        """Convert user data to dictionary."""
        return {
            "external_id": user_data.external_id,
            "email": user_data.email,
            "username": user_data.username,
            "display_name": user_data.display_name,
            "first_name": user_data.first_name,
            "last_name": user_data.last_name,
            "phone": user_data.phone,
            "groups": user_data.groups,
            "roles": user_data.roles,
            "attributes": user_data.attributes,
            "provider_id": user_data.provider_id,
        }

    def get_statistics(self) -> Dict[str, Any]:
        """Get provisioner statistics."""
        return {
            **self._stats,
            "mapped_users": len(self._external_to_internal),
            "rules": len(self._rules),
        }


__all__ = [
    "Provisioner",
    "ProvisioningOperation",
    "ProvisioningAction",
    "ProvisioningStatus",
    "ProvisioningRule",
    "UserProvisioningData",
    "ProvisioningStore",
    "SCIMParser",
]
