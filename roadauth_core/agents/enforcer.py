"""RoadAuth Enforcer Agent - Policy Enforcement & Access Control.

The Enforcer agent ensures security policies are applied:
- Real-time policy evaluation
- Dynamic access control
- IP/geo blocking
- Rate limiting enforcement
- Risk-based authentication

Copyright (c) 2024-2026 BlackRoad OS, Inc. All rights reserved.
"""

from __future__ import annotations

import ipaddress
import logging
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class EnforcementAction(Enum):
    """Enforcement actions."""

    ALLOW = "allow"
    DENY = "deny"
    CHALLENGE = "challenge"  # Require additional verification
    DELAY = "delay"  # Rate limit delay
    BLOCK = "block"  # Temporary block
    BAN = "ban"  # Permanent ban


class RiskLevel(Enum):
    """Risk assessment levels."""

    MINIMAL = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class EnforcementResult:
    """Result of enforcement check."""

    action: EnforcementAction
    risk_level: RiskLevel = RiskLevel.MINIMAL
    reason: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    challenges: List[str] = field(default_factory=list)
    delay_seconds: int = 0
    block_until: Optional[datetime] = None

    @property
    def is_allowed(self) -> bool:
        """Check if action is allowed."""
        return self.action == EnforcementAction.ALLOW


@dataclass
class SecurityPolicy:
    """Security policy definition."""

    id: str
    name: str
    enabled: bool = True
    priority: int = 0

    # Conditions
    conditions: Dict[str, Any] = field(default_factory=dict)

    # Actions
    action_on_match: EnforcementAction = EnforcementAction.DENY
    risk_score: int = 0
    challenges: List[str] = field(default_factory=list)

    # Metadata
    description: str = ""
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)


class IPBlocklist:
    """IP address blocklist."""

    def __init__(self):
        """Initialize blocklist."""
        self._blocked_ips: Dict[str, datetime] = {}
        self._blocked_ranges: List[ipaddress.IPv4Network] = []
        self._permanent_blocks: Set[str] = set()
        self._lock = threading.RLock()

    def block(
        self,
        ip: str,
        duration_seconds: Optional[int] = None,
        permanent: bool = False,
    ) -> None:
        """Block an IP address.

        Args:
            ip: IP address to block
            duration_seconds: Block duration (None for permanent)
            permanent: Permanent block flag
        """
        with self._lock:
            if permanent:
                self._permanent_blocks.add(ip)
            elif duration_seconds:
                self._blocked_ips[ip] = datetime.now() + timedelta(seconds=duration_seconds)
            else:
                self._permanent_blocks.add(ip)

    def unblock(self, ip: str) -> bool:
        """Unblock an IP address.

        Args:
            ip: IP address to unblock

        Returns:
            True if was blocked
        """
        with self._lock:
            was_blocked = False
            if ip in self._blocked_ips:
                del self._blocked_ips[ip]
                was_blocked = True
            if ip in self._permanent_blocks:
                self._permanent_blocks.discard(ip)
                was_blocked = True
            return was_blocked

    def is_blocked(self, ip: str) -> Tuple[bool, Optional[datetime]]:
        """Check if IP is blocked.

        Args:
            ip: IP address to check

        Returns:
            (is_blocked, block_until)
        """
        with self._lock:
            # Check permanent blocks
            if ip in self._permanent_blocks:
                return True, None

            # Check temporary blocks
            if ip in self._blocked_ips:
                block_until = self._blocked_ips[ip]
                if datetime.now() < block_until:
                    return True, block_until
                else:
                    del self._blocked_ips[ip]

            # Check blocked ranges
            try:
                ip_obj = ipaddress.ip_address(ip)
                for network in self._blocked_ranges:
                    if ip_obj in network:
                        return True, None
            except ValueError:
                pass

            return False, None

    def add_range(self, cidr: str) -> None:
        """Add blocked IP range.

        Args:
            cidr: CIDR notation range
        """
        with self._lock:
            try:
                network = ipaddress.ip_network(cidr, strict=False)
                self._blocked_ranges.append(network)
            except ValueError as e:
                logger.error(f"Invalid CIDR: {cidr} - {e}")

    def cleanup_expired(self) -> int:
        """Remove expired blocks."""
        with self._lock:
            now = datetime.now()
            expired = [ip for ip, until in self._blocked_ips.items() if until <= now]
            for ip in expired:
                del self._blocked_ips[ip]
            return len(expired)


class RateLimiter:
    """Rate limiter with token bucket algorithm."""

    def __init__(
        self,
        rate: float = 10.0,  # tokens per second
        capacity: float = 100.0,  # bucket capacity
    ):
        """Initialize rate limiter.

        Args:
            rate: Token refill rate per second
            capacity: Maximum bucket capacity
        """
        self.rate = rate
        self.capacity = capacity
        self._buckets: Dict[str, Tuple[float, float]] = {}  # key -> (tokens, last_update)
        self._lock = threading.RLock()

    def check(self, key: str, tokens: float = 1.0) -> Tuple[bool, float]:
        """Check if request should be allowed.

        Args:
            key: Rate limit key (IP, user ID, etc.)
            tokens: Tokens to consume

        Returns:
            (allowed, wait_seconds)
        """
        with self._lock:
            now = time.time()

            if key not in self._buckets:
                self._buckets[key] = (self.capacity - tokens, now)
                return True, 0

            current_tokens, last_update = self._buckets[key]

            # Add tokens since last update
            elapsed = now - last_update
            current_tokens = min(self.capacity, current_tokens + elapsed * self.rate)

            if current_tokens >= tokens:
                self._buckets[key] = (current_tokens - tokens, now)
                return True, 0
            else:
                # Calculate wait time
                needed = tokens - current_tokens
                wait_seconds = needed / self.rate
                return False, wait_seconds

    def reset(self, key: str) -> None:
        """Reset rate limit for key."""
        with self._lock:
            if key in self._buckets:
                del self._buckets[key]


class GeoBlocker:
    """Geographic-based blocking."""

    def __init__(self):
        """Initialize geo blocker."""
        self._blocked_countries: Set[str] = set()
        self._allowed_countries: Set[str] = set()  # If set, only these allowed
        self._lock = threading.RLock()

    def block_country(self, country_code: str) -> None:
        """Block a country."""
        with self._lock:
            self._blocked_countries.add(country_code.upper())

    def unblock_country(self, country_code: str) -> None:
        """Unblock a country."""
        with self._lock:
            self._blocked_countries.discard(country_code.upper())

    def allow_only(self, country_codes: List[str]) -> None:
        """Allow only specific countries."""
        with self._lock:
            self._allowed_countries = {c.upper() for c in country_codes}

    def is_blocked(self, country_code: str) -> bool:
        """Check if country is blocked."""
        with self._lock:
            country = country_code.upper()

            # Check allowlist first
            if self._allowed_countries and country not in self._allowed_countries:
                return True

            # Check blocklist
            return country in self._blocked_countries


class RiskEngine:
    """Risk assessment engine."""

    def __init__(self):
        """Initialize risk engine."""
        self._risk_factors: Dict[str, int] = {
            "new_device": 20,
            "new_location": 15,
            "impossible_travel": 50,
            "tor_exit": 30,
            "vpn_detected": 10,
            "known_bad_ip": 40,
            "failed_mfa": 25,
            "after_hours": 10,
            "unusual_behavior": 20,
        }

    def assess(self, factors: Dict[str, bool]) -> Tuple[int, RiskLevel]:
        """Assess risk based on factors.

        Args:
            factors: Dictionary of risk factors and their presence

        Returns:
            (risk_score, risk_level)
        """
        score = 0
        for factor, present in factors.items():
            if present and factor in self._risk_factors:
                score += self._risk_factors[factor]

        # Determine level
        if score >= 80:
            level = RiskLevel.CRITICAL
        elif score >= 50:
            level = RiskLevel.HIGH
        elif score >= 30:
            level = RiskLevel.MEDIUM
        elif score >= 10:
            level = RiskLevel.LOW
        else:
            level = RiskLevel.MINIMAL

        return score, level

    def set_factor_weight(self, factor: str, weight: int) -> None:
        """Set risk factor weight."""
        self._risk_factors[factor] = weight


class Enforcer:
    """Enforcer Agent - Policy Enforcement & Access Control.

    The Enforcer ensures security policies are consistently
    applied across all authentication and authorization requests.
    """

    def __init__(
        self,
        rate_limit: float = 10.0,
        rate_capacity: float = 100.0,
    ):
        """Initialize Enforcer.

        Args:
            rate_limit: Default rate limit (requests per second)
            rate_capacity: Default rate limit capacity
        """
        self.ip_blocklist = IPBlocklist()
        self.rate_limiter = RateLimiter(rate=rate_limit, capacity=rate_capacity)
        self.geo_blocker = GeoBlocker()
        self.risk_engine = RiskEngine()

        # Policies
        self._policies: Dict[str, SecurityPolicy] = {}
        self._policy_order: List[str] = []
        self._lock = threading.RLock()

        # Statistics
        self._stats = {
            "checks": 0,
            "allowed": 0,
            "denied": 0,
            "challenged": 0,
            "blocked": 0,
        }

    def check(
        self,
        ip_address: str,
        user_id: Optional[str] = None,
        country_code: Optional[str] = None,
        risk_factors: Optional[Dict[str, bool]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> EnforcementResult:
        """Check if request should be allowed.

        Args:
            ip_address: Client IP address
            user_id: User ID (if known)
            country_code: Country code (if known)
            risk_factors: Risk assessment factors
            context: Additional context

        Returns:
            Enforcement result
        """
        self._stats["checks"] += 1
        context = context or {}

        # Check IP blocklist
        blocked, block_until = self.ip_blocklist.is_blocked(ip_address)
        if blocked:
            self._stats["blocked"] += 1
            return EnforcementResult(
                action=EnforcementAction.BLOCK,
                risk_level=RiskLevel.CRITICAL,
                reason="IP address is blocked",
                block_until=block_until,
            )

        # Check geo blocking
        if country_code and self.geo_blocker.is_blocked(country_code):
            self._stats["denied"] += 1
            return EnforcementResult(
                action=EnforcementAction.DENY,
                risk_level=RiskLevel.HIGH,
                reason=f"Country {country_code} is blocked",
            )

        # Check rate limit
        rate_key = user_id or ip_address
        allowed, wait_seconds = self.rate_limiter.check(rate_key)
        if not allowed:
            self._stats["denied"] += 1
            return EnforcementResult(
                action=EnforcementAction.DELAY,
                risk_level=RiskLevel.MEDIUM,
                reason="Rate limit exceeded",
                delay_seconds=int(wait_seconds) + 1,
            )

        # Assess risk
        if risk_factors:
            risk_score, risk_level = self.risk_engine.assess(risk_factors)
        else:
            risk_score, risk_level = 0, RiskLevel.MINIMAL

        # Evaluate policies
        for policy_id in self._policy_order:
            policy = self._policies.get(policy_id)
            if not policy or not policy.enabled:
                continue

            if self._evaluate_policy(policy, ip_address, user_id, context):
                if policy.action_on_match == EnforcementAction.DENY:
                    self._stats["denied"] += 1
                    return EnforcementResult(
                        action=EnforcementAction.DENY,
                        risk_level=risk_level,
                        reason=f"Policy {policy.name} denied access",
                        details={"policy_id": policy.id},
                    )
                elif policy.action_on_match == EnforcementAction.CHALLENGE:
                    self._stats["challenged"] += 1
                    return EnforcementResult(
                        action=EnforcementAction.CHALLENGE,
                        risk_level=risk_level,
                        reason=f"Policy {policy.name} requires challenge",
                        challenges=policy.challenges,
                    )

        # Risk-based decision
        if risk_level == RiskLevel.CRITICAL:
            self._stats["denied"] += 1
            return EnforcementResult(
                action=EnforcementAction.DENY,
                risk_level=risk_level,
                reason="Risk level too high",
                details={"risk_score": risk_score},
            )
        elif risk_level == RiskLevel.HIGH:
            self._stats["challenged"] += 1
            return EnforcementResult(
                action=EnforcementAction.CHALLENGE,
                risk_level=risk_level,
                reason="High risk detected",
                challenges=["mfa", "captcha"],
                details={"risk_score": risk_score},
            )

        # Allow
        self._stats["allowed"] += 1
        return EnforcementResult(
            action=EnforcementAction.ALLOW,
            risk_level=risk_level,
        )

    def add_policy(self, policy: SecurityPolicy) -> None:
        """Add security policy."""
        with self._lock:
            self._policies[policy.id] = policy
            self._policy_order.append(policy.id)
            # Sort by priority
            self._policy_order.sort(key=lambda pid: self._policies[pid].priority)

    def remove_policy(self, policy_id: str) -> bool:
        """Remove security policy."""
        with self._lock:
            if policy_id in self._policies:
                del self._policies[policy_id]
                self._policy_order.remove(policy_id)
                return True
            return False

    def block_ip(
        self,
        ip: str,
        duration_seconds: Optional[int] = None,
        reason: str = "",
    ) -> None:
        """Block an IP address."""
        self.ip_blocklist.block(ip, duration_seconds)
        logger.warning(f"Blocked IP {ip}: {reason}")

    def unblock_ip(self, ip: str) -> bool:
        """Unblock an IP address."""
        return self.ip_blocklist.unblock(ip)

    def block_country(self, country_code: str) -> None:
        """Block a country."""
        self.geo_blocker.block_country(country_code)

    def allow_only_countries(self, country_codes: List[str]) -> None:
        """Allow only specific countries."""
        self.geo_blocker.allow_only(country_codes)

    def _evaluate_policy(
        self,
        policy: SecurityPolicy,
        ip_address: str,
        user_id: Optional[str],
        context: Dict[str, Any],
    ) -> bool:
        """Evaluate if policy matches."""
        conditions = policy.conditions

        # IP condition
        if "ip" in conditions:
            if ip_address != conditions["ip"]:
                return False

        # IP range condition
        if "ip_range" in conditions:
            try:
                network = ipaddress.ip_network(conditions["ip_range"], strict=False)
                if ipaddress.ip_address(ip_address) not in network:
                    return False
            except ValueError:
                return False

        # User condition
        if "user_id" in conditions:
            if user_id != conditions["user_id"]:
                return False

        # Time condition
        if "time_range" in conditions:
            time_range = conditions["time_range"]
            current_hour = datetime.now().hour
            if not (time_range["start"] <= current_hour < time_range["end"]):
                return False

        # Custom conditions
        for key, expected in conditions.items():
            if key.startswith("ctx_"):
                ctx_key = key[4:]
                if context.get(ctx_key) != expected:
                    return False

        return True

    def get_statistics(self) -> Dict[str, Any]:
        """Get enforcer statistics."""
        return {
            **self._stats,
            "blocked_ips": len(self.ip_blocklist._permanent_blocks) + len(self.ip_blocklist._blocked_ips),
            "policies": len(self._policies),
        }


__all__ = [
    "Enforcer",
    "EnforcementResult",
    "EnforcementAction",
    "SecurityPolicy",
    "RiskLevel",
    "IPBlocklist",
    "RateLimiter",
    "GeoBlocker",
    "RiskEngine",
]
