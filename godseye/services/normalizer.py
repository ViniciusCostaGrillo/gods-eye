"""Normalization Service converting RawObservation into NormalizedObservation."""

from godseye.db.repository import OsintRepository
from godseye.domain.enums import EntityType
from godseye.domain.models import NormalizedObservation, RawEvidence, RawObservation


class NormalizationService:
    """Standardizes heterogeneous raw observations into canonical observations (Section 4)."""

    def __init__(self, repo: OsintRepository) -> None:
        self.repo = repo

    @staticmethod
    def canonicalize(entity_type: EntityType, value: str) -> str:
        """Canonicalize entity value for deterministic deduplication."""
        cleaned = value.strip()
        if entity_type in {EntityType.EMAIL, EntityType.DOMAIN, EntityType.SUBDOMAIN}:
            return cleaned.lower()
        return cleaned

    def normalize_and_store(
        self,
        case_id: str,
        evidence: RawEvidence,
        raw_obs: RawObservation,
    ) -> NormalizedObservation:
        """Transform a RawObservation + RawEvidence into a persisted NormalizedObservation."""
        canonical = self.canonicalize(raw_obs.entity_type, raw_obs.entity_value)
        related_canonical = (
            self.canonicalize(raw_obs.related_to_type, raw_obs.related_to_value)
            if raw_obs.related_to_value and raw_obs.related_to_type
            else raw_obs.related_to_value
        )

        normalized = NormalizedObservation(
            case_id=case_id,
            evidence_id=evidence.id,
            source_id=raw_obs.source_id,
            entity_type=raw_obs.entity_type,
            entity_value=raw_obs.entity_value,
            canonical_value=canonical,
            observed_at=raw_obs.retrieved_at,
            confidence=raw_obs.confidence,
            verification=raw_obs.verification_status,
            tags=list(raw_obs.tags),
            attributes=dict(raw_obs.raw_payload),
            related_to_value=related_canonical,
            related_to_type=raw_obs.related_to_type,
            relation=raw_obs.relation,
        )
        return self.repo.save_observation(normalized)
