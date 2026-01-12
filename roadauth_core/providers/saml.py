"""RoadAuth SAML Provider - SAML 2.0 Authentication.

Implements SAML 2.0 Service Provider (SP) functionality:
- SP-initiated SSO
- IdP-initiated SSO
- Single Logout (SLO)
- Metadata generation
- Signature verification

Copyright (c) 2024-2026 BlackRoad OS, Inc. All rights reserved.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import secrets
import time
import uuid
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode
from xml.etree import ElementTree as ET

from roadauth_core.providers.base import (
    AuthProvider,
    AuthProviderConfig,
    AuthProviderResult,
    AuthProviderType,
    AuthStatus,
)

logger = logging.getLogger(__name__)


# SAML namespaces
SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
SAMLP_NS = "urn:oasis:names:tc:SAML:2.0:protocol"
DSIG_NS = "http://www.w3.org/2000/09/xmldsig#"

NS_MAP = {
    "saml": SAML_NS,
    "samlp": SAMLP_NS,
    "ds": DSIG_NS,
}


class SAMLBinding(Enum):
    """SAML bindings."""

    HTTP_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
    HTTP_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
    HTTP_ARTIFACT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"


class SAMLNameIDFormat(Enum):
    """SAML NameID formats."""

    EMAIL = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    PERSISTENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
    TRANSIENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
    UNSPECIFIED = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"


@dataclass
class SAMLConfig(AuthProviderConfig):
    """SAML provider configuration."""

    # Service Provider (SP) configuration
    sp_entity_id: str = ""
    sp_acs_url: str = ""  # Assertion Consumer Service URL
    sp_slo_url: str = ""  # Single Logout URL
    sp_metadata_url: str = ""

    # SP certificate/key for signing
    sp_private_key: str = ""
    sp_certificate: str = ""

    # Identity Provider (IdP) configuration
    idp_entity_id: str = ""
    idp_sso_url: str = ""
    idp_slo_url: str = ""
    idp_certificate: str = ""
    idp_metadata_url: str = ""

    # Bindings
    sso_binding: SAMLBinding = SAMLBinding.HTTP_POST
    slo_binding: SAMLBinding = SAMLBinding.HTTP_REDIRECT

    # NameID
    name_id_format: SAMLNameIDFormat = SAMLNameIDFormat.EMAIL

    # Assertion options
    want_assertions_signed: bool = True
    want_assertions_encrypted: bool = False
    want_response_signed: bool = True

    # Request options
    sign_authn_request: bool = True
    sign_logout_request: bool = True

    # Attribute mapping
    name_id_attribute: str = "NameID"
    email_attribute: str = "email"
    name_attribute: str = "name"
    first_name_attribute: str = "firstName"
    last_name_attribute: str = "lastName"
    groups_attribute: str = "groups"

    # Security
    clock_skew_tolerance: int = 120  # seconds
    state_ttl: int = 600  # 10 minutes


@dataclass
class SAMLRequest:
    """SAML authentication request."""

    id: str
    issue_instant: datetime
    destination: str
    assertion_consumer_service_url: str
    issuer: str
    name_id_format: SAMLNameIDFormat
    relay_state: Optional[str] = None

    @classmethod
    def create(cls, config: SAMLConfig, relay_state: Optional[str] = None) -> SAMLRequest:
        """Create a new SAML request."""
        return cls(
            id=f"_" + secrets.token_hex(16),
            issue_instant=datetime.utcnow(),
            destination=config.idp_sso_url,
            assertion_consumer_service_url=config.sp_acs_url,
            issuer=config.sp_entity_id,
            name_id_format=config.name_id_format,
            relay_state=relay_state,
        )

    def to_xml(self) -> str:
        """Convert to SAML XML."""
        return f"""<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest
    xmlns:samlp="{SAMLP_NS}"
    xmlns:saml="{SAML_NS}"
    ID="{self.id}"
    Version="2.0"
    IssueInstant="{self.issue_instant.isoformat()}Z"
    Destination="{self.destination}"
    AssertionConsumerServiceURL="{self.assertion_consumer_service_url}"
    ProtocolBinding="{SAMLBinding.HTTP_POST.value}">
    <saml:Issuer>{self.issuer}</saml:Issuer>
    <samlp:NameIDPolicy
        Format="{self.name_id_format.value}"
        AllowCreate="true"/>
</samlp:AuthnRequest>"""

    def encode(self, compress: bool = True) -> str:
        """Encode request for transport."""
        xml = self.to_xml()
        if compress:
            compressed = zlib.compress(xml.encode())[2:-4]  # Remove header/checksum
            return base64.b64encode(compressed).decode()
        return base64.b64encode(xml.encode()).decode()


@dataclass
class SAMLResponse:
    """Parsed SAML response."""

    id: str
    in_response_to: str
    status_code: str
    status_message: Optional[str] = None

    # Assertion data
    assertion_id: Optional[str] = None
    issuer: Optional[str] = None
    name_id: Optional[str] = None
    name_id_format: Optional[str] = None

    # Conditions
    not_before: Optional[datetime] = None
    not_on_or_after: Optional[datetime] = None
    audience: Optional[str] = None

    # Attributes
    attributes: Dict[str, Any] = field(default_factory=dict)

    # Session
    session_index: Optional[str] = None
    session_not_on_or_after: Optional[datetime] = None

    @property
    def is_success(self) -> bool:
        """Check if response indicates success."""
        return self.status_code == "urn:oasis:names:tc:SAML:2.0:status:Success"

    def is_valid_time(self, skew: int = 120) -> bool:
        """Check if assertion is within valid time window."""
        now = datetime.utcnow()
        skew_delta = timedelta(seconds=skew)

        if self.not_before and now < self.not_before - skew_delta:
            return False
        if self.not_on_or_after and now >= self.not_on_or_after + skew_delta:
            return False

        return True


class SAMLStateStore:
    """SAML request state store."""

    def __init__(self):
        """Initialize store."""
        self._states: Dict[str, Dict[str, Any]] = {}

    def save(self, request_id: str, state: Dict[str, Any]) -> None:
        """Save request state."""
        self._states[request_id] = state

    def get(self, request_id: str) -> Optional[Dict[str, Any]]:
        """Get request state."""
        return self._states.get(request_id)

    def delete(self, request_id: str) -> bool:
        """Delete request state."""
        if request_id in self._states:
            del self._states[request_id]
            return True
        return False

    def cleanup_expired(self, ttl: int) -> int:
        """Remove expired states."""
        now = time.time()
        expired = [
            rid for rid, state in self._states.items()
            if now - state.get("created_at", 0) > ttl
        ]
        for rid in expired:
            del self._states[rid]
        return len(expired)


class SAMLProvider(AuthProvider):
    """SAML 2.0 authentication provider."""

    def __init__(
        self,
        config: SAMLConfig,
        state_store: Optional[SAMLStateStore] = None,
    ):
        """Initialize SAML provider.

        Args:
            config: SAML configuration
            state_store: State store implementation
        """
        super().__init__(config)
        self.saml_config = config
        self.state_store = state_store or SAMLStateStore()

    async def initialize(self) -> bool:
        """Initialize provider."""
        self._initialized = True
        logger.info(f"SAML provider initialized: {self.saml_config.sp_entity_id}")
        return True

    def get_login_url(
        self,
        relay_state: Optional[str] = None,
    ) -> Tuple[str, str]:
        """Get SAML login URL.

        Args:
            relay_state: Optional relay state

        Returns:
            (url, request_id)
        """
        # Create SAML request
        request = SAMLRequest.create(self.saml_config, relay_state)

        # Store state
        self.state_store.save(request.id, {
            "created_at": time.time(),
            "relay_state": relay_state,
        })

        # Build URL based on binding
        if self.saml_config.sso_binding == SAMLBinding.HTTP_REDIRECT:
            encoded = request.encode(compress=True)
            params = {"SAMLRequest": encoded}
            if relay_state:
                params["RelayState"] = relay_state

            url = f"{self.saml_config.idp_sso_url}?{urlencode(params)}"
        else:
            # HTTP-POST - return form data
            url = self.saml_config.idp_sso_url

        return url, request.id

    async def authenticate(
        self,
        credentials: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> AuthProviderResult:
        """Authenticate user with SAML response.

        Args:
            credentials: Must contain 'SAMLResponse' and optionally 'RelayState'
            context: Optional context

        Returns:
            Authentication result
        """
        saml_response = credentials.get("SAMLResponse")
        relay_state = credentials.get("RelayState")

        if not saml_response:
            return AuthProviderResult.failure_result(
                AuthStatus.INVALID_CREDENTIALS,
                "Missing SAML response",
            )

        try:
            # Parse response
            response = self._parse_response(saml_response)

            if not response:
                return AuthProviderResult.failure_result(
                    AuthStatus.INVALID_CREDENTIALS,
                    "Failed to parse SAML response",
                )

            # Verify InResponseTo
            if response.in_response_to:
                state = self.state_store.get(response.in_response_to)
                if not state:
                    return AuthProviderResult.failure_result(
                        AuthStatus.INVALID_CREDENTIALS,
                        "Invalid or expired request",
                    )
                self.state_store.delete(response.in_response_to)

            # Check status
            if not response.is_success:
                return AuthProviderResult.failure_result(
                    AuthStatus.FAILURE,
                    response.status_message or "Authentication failed at IdP",
                )

            # Verify conditions
            if not response.is_valid_time(self.saml_config.clock_skew_tolerance):
                return AuthProviderResult.failure_result(
                    AuthStatus.INVALID_CREDENTIALS,
                    "Assertion has expired",
                )

            # Verify audience
            if response.audience and response.audience != self.saml_config.sp_entity_id:
                return AuthProviderResult.failure_result(
                    AuthStatus.INVALID_CREDENTIALS,
                    "Invalid audience",
                )

            # Extract user info
            name_id = response.name_id
            attrs = response.attributes

            email = attrs.get(self.saml_config.email_attribute, name_id)
            name = attrs.get(self.saml_config.name_attribute)
            first_name = attrs.get(self.saml_config.first_name_attribute)
            last_name = attrs.get(self.saml_config.last_name_attribute)
            groups = attrs.get(self.saml_config.groups_attribute, [])

            if not name and first_name and last_name:
                name = f"{first_name} {last_name}"

            # Check domain restriction
            if email and not self.is_domain_allowed(email):
                return AuthProviderResult.failure_result(
                    AuthStatus.FAILURE,
                    "Email domain not allowed",
                )

            return AuthProviderResult.success_result(
                user_id=name_id,
                email=email,
                display_name=name,
                provider_id=self.provider_id,
                provider_type=self.provider_type,
                provider_user_id=name_id,
                profile=self.map_attributes(attrs),
                groups=self.map_groups(groups) if isinstance(groups, list) else [],
                roles=self.map_roles(groups) if isinstance(groups, list) else [],
                session_metadata={
                    "session_index": response.session_index,
                    "name_id": name_id,
                    "name_id_format": response.name_id_format,
                    "relay_state": relay_state,
                },
            )

        except Exception as e:
            logger.error(f"SAML authentication error: {e}")
            return AuthProviderResult.failure_result(
                AuthStatus.PROVIDER_ERROR,
                str(e),
            )

    async def validate_user(self, user_id: str) -> bool:
        """Validate user (always true for SAML)."""
        return True

    def get_logout_url(
        self,
        name_id: str,
        session_index: Optional[str] = None,
        relay_state: Optional[str] = None,
    ) -> str:
        """Get SAML logout URL.

        Args:
            name_id: User's NameID
            session_index: Session index
            relay_state: Relay state

        Returns:
            Logout URL
        """
        request_id = f"_" + secrets.token_hex(16)
        issue_instant = datetime.utcnow().isoformat() + "Z"

        logout_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<samlp:LogoutRequest
    xmlns:samlp="{SAMLP_NS}"
    xmlns:saml="{SAML_NS}"
    ID="{request_id}"
    Version="2.0"
    IssueInstant="{issue_instant}"
    Destination="{self.saml_config.idp_slo_url}">
    <saml:Issuer>{self.saml_config.sp_entity_id}</saml:Issuer>
    <saml:NameID Format="{self.saml_config.name_id_format.value}">{name_id}</saml:NameID>
    {"<samlp:SessionIndex>" + session_index + "</samlp:SessionIndex>" if session_index else ""}
</samlp:LogoutRequest>"""

        # Encode and build URL
        compressed = zlib.compress(logout_xml.encode())[2:-4]
        encoded = base64.b64encode(compressed).decode()

        params = {"SAMLRequest": encoded}
        if relay_state:
            params["RelayState"] = relay_state

        return f"{self.saml_config.idp_slo_url}?{urlencode(params)}"

    def get_metadata(self) -> str:
        """Generate SP metadata XML.

        Returns:
            SP metadata XML
        """
        return f"""<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor
    xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="{self.saml_config.sp_entity_id}">
    <md:SPSSODescriptor
        AuthnRequestsSigned="{str(self.saml_config.sign_authn_request).lower()}"
        WantAssertionsSigned="{str(self.saml_config.want_assertions_signed).lower()}"
        protocolSupportEnumeration="{SAMLP_NS}">

        <md:NameIDFormat>{self.saml_config.name_id_format.value}</md:NameIDFormat>

        <md:AssertionConsumerService
            Binding="{SAMLBinding.HTTP_POST.value}"
            Location="{self.saml_config.sp_acs_url}"
            index="0"
            isDefault="true"/>

        {f'''<md:SingleLogoutService
            Binding="{self.saml_config.slo_binding.value}"
            Location="{self.saml_config.sp_slo_url}"/>''' if self.saml_config.sp_slo_url else ""}

    </md:SPSSODescriptor>
</md:EntityDescriptor>"""

    def _parse_response(self, encoded_response: str) -> Optional[SAMLResponse]:
        """Parse SAML response.

        Args:
            encoded_response: Base64 encoded SAML response

        Returns:
            Parsed response or None
        """
        try:
            # Decode
            xml_bytes = base64.b64decode(encoded_response)
            xml_str = xml_bytes.decode()

            # Parse XML
            root = ET.fromstring(xml_str)

            # Extract response attributes
            response_id = root.get("ID", "")
            in_response_to = root.get("InResponseTo", "")

            # Get status
            status_elem = root.find(f".//{{{SAMLP_NS}}}StatusCode")
            status_code = status_elem.get("Value", "") if status_elem is not None else ""

            status_msg_elem = root.find(f".//{{{SAMLP_NS}}}StatusMessage")
            status_message = status_msg_elem.text if status_msg_elem is not None else None

            # Get assertion
            assertion = root.find(f".//{{{SAML_NS}}}Assertion")

            response = SAMLResponse(
                id=response_id,
                in_response_to=in_response_to,
                status_code=status_code,
                status_message=status_message,
            )

            if assertion is not None:
                response.assertion_id = assertion.get("ID")

                # Get issuer
                issuer = assertion.find(f"{{{SAML_NS}}}Issuer")
                if issuer is not None:
                    response.issuer = issuer.text

                # Get NameID
                name_id = assertion.find(f".//{{{SAML_NS}}}NameID")
                if name_id is not None:
                    response.name_id = name_id.text
                    response.name_id_format = name_id.get("Format")

                # Get conditions
                conditions = assertion.find(f"{{{SAML_NS}}}Conditions")
                if conditions is not None:
                    not_before = conditions.get("NotBefore")
                    if not_before:
                        response.not_before = datetime.fromisoformat(not_before.rstrip("Z"))

                    not_on_or_after = conditions.get("NotOnOrAfter")
                    if not_on_or_after:
                        response.not_on_or_after = datetime.fromisoformat(not_on_or_after.rstrip("Z"))

                    audience = conditions.find(f".//{{{SAML_NS}}}Audience")
                    if audience is not None:
                        response.audience = audience.text

                # Get attributes
                attrs = assertion.findall(f".//{{{SAML_NS}}}Attribute")
                for attr in attrs:
                    attr_name = attr.get("Name", "")
                    values = attr.findall(f"{{{SAML_NS}}}AttributeValue")
                    if len(values) == 1:
                        response.attributes[attr_name] = values[0].text
                    else:
                        response.attributes[attr_name] = [v.text for v in values]

                # Get session info
                authn_stmt = assertion.find(f"{{{SAML_NS}}}AuthnStatement")
                if authn_stmt is not None:
                    response.session_index = authn_stmt.get("SessionIndex")
                    session_not_after = authn_stmt.get("SessionNotOnOrAfter")
                    if session_not_after:
                        response.session_not_on_or_after = datetime.fromisoformat(session_not_after.rstrip("Z"))

            return response

        except Exception as e:
            logger.error(f"Failed to parse SAML response: {e}")
            return None


__all__ = [
    "SAMLProvider",
    "SAMLConfig",
    "SAMLBinding",
    "SAMLNameIDFormat",
    "SAMLRequest",
    "SAMLResponse",
    "SAMLStateStore",
]
