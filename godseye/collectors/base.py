"""Collector Protocol and BaseCollector implementation (Section 7)."""

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from typing import Any, Protocol, runtime_checkable

from godseye.core.cache import MultiTierCache
from godseye.core.resilience import ResilientHttpClient
from godseye.core.security import compute_content_hash, sanitize_osint_payload
from godseye.domain.enums import (
    EntityType,
    LegalBasis,
    RelationType,
    TargetType,
    TrustLevel,
    VerificationStatus,
)
from godseye.domain.models import RawObservation, Target


@runtime_checkable
class Collector(Protocol):
    """Standard OSINT Collector interface as specified in Section 7."""

    id: str
    name: str
    accepts: set[TargetType]
    produces: set[EntityType]
    trust_level: TrustLevel
    requires_auth: bool
    rate_limit: int
    adapter_version: str
    region: str

    def collect(self, target: Target) -> AsyncIterator[RawObservation]:
        """Collect raw observations for the given target."""
        ...


class BaseCollector(ABC):
    """Abstract base class for pluggable OSINT source adapters with provenance & caching."""

    id: str = "base"
    name: str = "Base Collector"
    accepts: set[TargetType] = set()
    produces: set[EntityType] = set()
    trust_level: TrustLevel = TrustLevel.HIGH
    requires_auth: bool = False
    rate_limit: int = 30
    adapter_version: str = "2.1.0"
    region: str = "global"

    def __init__(
        self,
        http_client: ResilientHttpClient,
        cache: MultiTierCache | None = None,
        offline_fallback: bool = True,
    ) -> None:
        self.http_client = http_client
        self.cache = cache
        self.offline_fallback = offline_fallback
        self.http_client.configure_source(self.id, rate_limit_per_min=self.rate_limit)

    def make_observation(
        self,
        entity_type: EntityType,
        entity_value: str,
        raw_payload: dict[str, Any],
        source_url: str | None = None,
        confidence: float = 0.85,
        verification_status: VerificationStatus = VerificationStatus.VERIFIED,
        legal_basis: LegalBasis = LegalBasis.CYBERSECURITY_DEFENSE,
        related_to_value: str | None = None,
        related_to_type: EntityType | None = None,
        relation: RelationType = RelationType.ASSOCIATED_WITH,
        tags: list[str] | None = None,
    ) -> RawObservation:
        """Create a sanitized, SHA-256 hashed RawObservation with mandatory Section 7.1 metadata."""
        sanitized_payload = sanitize_osint_payload(raw_payload)
        content_hash = compute_content_hash(sanitized_payload)
        return RawObservation(
            source_id=self.id,
            source_name=self.name,
            source_url=source_url,
            adapter_version=self.adapter_version,
            entity_type=entity_type,
            entity_value=entity_value,
            confidence=confidence,
            verification_status=verification_status,
            legal_basis=legal_basis,
            raw_payload=sanitized_payload,
            content_hash=content_hash,
            related_to_value=related_to_value,
            related_to_type=related_to_type,
            relation=relation,
            tags=tags or [self.id, self.region],
        )

    @abstractmethod
    def collect(self, target: Target) -> AsyncIterator[RawObservation]:
        """Yield RawObservation instances for a target."""
        ...
