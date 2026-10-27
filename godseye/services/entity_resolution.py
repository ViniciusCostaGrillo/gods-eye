"""Entity Resolution Service deduplicating entities and building graph edges."""

from godseye.db.repository import OsintRepository
from godseye.domain.models import (
    Entity,
    EntityRelationship,
    NormalizedObservation,
    utc_now_iso,
)


class EntityResolutionService:
    """Deduplicates entities across OSINT sources and constructs evidence-backed relationships."""

    def __init__(self, repo: OsintRepository) -> None:
        self.repo = repo

    def resolve(self, obs: NormalizedObservation) -> tuple[Entity, EntityRelationship | None]:
        """Resolve or merge the primary entity and link it to its related entity if present."""
        existing = self.repo.find_entity(obs.case_id, obs.entity_type, obs.canonical_value)
        if existing is None:
            primary_entity = Entity(
                case_id=obs.case_id,
                type=obs.entity_type,
                canonical_value=obs.canonical_value,
                aliases=[obs.entity_value] if obs.entity_value != obs.canonical_value else [],
                attributes=dict(obs.attributes),
                confidence=obs.confidence,
                sources=[obs.source_id],
                first_seen=obs.observed_at,
                last_seen=obs.observed_at,
            )
            self.repo.save_entity(primary_entity)
        else:
            if obs.entity_value not in existing.aliases and obs.entity_value != existing.canonical_value:
                existing.aliases.append(obs.entity_value)
            if obs.source_id not in existing.sources:
                existing.sources.append(obs.source_id)
            existing.attributes.update(obs.attributes)
            existing.confidence = max(existing.confidence, obs.confidence)
            existing.last_seen = utc_now_iso()
            primary_entity = self.repo.save_entity(existing)

        relationship: EntityRelationship | None = None
        if (
            obs.related_to_value
            and obs.related_to_type
            and obs.related_to_value != obs.canonical_value
        ):
            parent = self.repo.find_entity(obs.case_id, obs.related_to_type, obs.related_to_value)
            if parent is None:
                parent = Entity(
                    case_id=obs.case_id,
                    type=obs.related_to_type,
                    canonical_value=obs.related_to_value,
                    confidence=0.9,
                    sources=[obs.source_id],
                )
                self.repo.save_entity(parent)

            rel = EntityRelationship(
                case_id=obs.case_id,
                from_entity_id=parent.id,
                to_entity_id=primary_entity.id,
                from_label=f"{parent.type.value}:{parent.canonical_value}",
                to_label=f"{primary_entity.type.value}:{primary_entity.canonical_value}",
                relation=obs.relation,
                confidence=obs.confidence,
                evidence_id=obs.evidence_id,
                source_id=obs.source_id,
            )
            relationship = self.repo.save_relationship(rel)

        return primary_entity, relationship
