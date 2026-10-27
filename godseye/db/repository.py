"""Relational SQLite WAL Repository implementing the Section 6 OSINT Data Model."""

import json
import sqlite3
from pathlib import Path

from godseye.domain.enums import (
    CaseStatus,
    EntityType,
    JobStatus,
    LegalBasis,
    RelationType,
    RiskLevel,
    TargetType,
    VerificationStatus,
)
from godseye.domain.models import (
    AuditEvent,
    Case,
    CollectionJob,
    CorrelationFinding,
    Entity,
    EntityRelationship,
    NormalizedObservation,
    RawEvidence,
    Target,
    WebhookSubscription,
)


class OsintRepository:
    """Operational source-of-truth repository for Cases, Evidence, Entities, Graph, and Audit."""

    def __init__(self, db_path: str = ":memory:") -> None:
        self.db_path = db_path
        if db_path != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        with self._conn:
            self._conn.execute("PRAGMA journal_mode=WAL;")
            self._conn.execute("PRAGMA foreign_keys=ON;")
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS cases (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    owner TEXT NOT NULL,
                    status TEXT NOT NULL,
                    legal_basis TEXT NOT NULL,
                    purpose TEXT NOT NULL,
                    notes_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    closed_at TEXT
                );

                CREATE TABLE IF NOT EXISTS targets (
                    id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    normalized_value TEXT NOT NULL,
                    risk TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_targets_case ON targets(case_id);

                CREATE TABLE IF NOT EXISTS collection_jobs (
                    id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    priority INTEGER NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    requested_at TEXT NOT NULL,
                    started_at TEXT,
                    finished_at TEXT,
                    error TEXT,
                    cost REAL NOT NULL,
                    duration_ms REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_jobs_case ON collection_jobs(case_id);
                CREATE INDEX IF NOT EXISTS idx_jobs_idem ON collection_jobs(idempotency_key);

                CREATE TABLE IF NOT EXISTS raw_evidence (
                    id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    job_id TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    source_name TEXT NOT NULL,
                    url TEXT,
                    retrieved_at TEXT NOT NULL,
                    adapter_version TEXT NOT NULL,
                    content_hash TEXT NOT NULL,
                    raw_payload_json TEXT NOT NULL,
                    legal_basis TEXT NOT NULL,
                    retention_expires_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_evidence_case ON raw_evidence(case_id);

                CREATE TABLE IF NOT EXISTS normalized_observations (
                    id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    evidence_id TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    entity_type TEXT NOT NULL,
                    entity_value TEXT NOT NULL,
                    canonical_value TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    verification TEXT NOT NULL,
                    tags_json TEXT NOT NULL,
                    attributes_json TEXT NOT NULL,
                    related_to_value TEXT,
                    related_to_type TEXT,
                    relation TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_obs_case ON normalized_observations(case_id);

                CREATE TABLE IF NOT EXISTS entities (
                    id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    type TEXT NOT NULL,
                    canonical_value TEXT NOT NULL,
                    aliases_json TEXT NOT NULL,
                    attributes_json TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    sources_json TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    UNIQUE(case_id, type, canonical_value)
                );
                CREATE INDEX IF NOT EXISTS idx_entities_case ON entities(case_id);

                CREATE TABLE IF NOT EXISTS entity_relationships (
                    id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    from_entity_id TEXT NOT NULL,
                    to_entity_id TEXT NOT NULL,
                    from_label TEXT NOT NULL,
                    to_label TEXT NOT NULL,
                    relation TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    evidence_id TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_rel_case ON entity_relationships(case_id);

                CREATE TABLE IF NOT EXISTS correlation_findings (
                    id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    risk TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    involved_entities_json TEXT NOT NULL,
                    evidence_ids_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_corr_case ON correlation_findings(case_id);

                CREATE TABLE IF NOT EXISTS audit_events (
                    id TEXT PRIMARY KEY,
                    actor_id TEXT NOT NULL,
                    actor_role TEXT NOT NULL,
                    case_id TEXT,
                    action TEXT NOT NULL,
                    object_id TEXT,
                    ip TEXT NOT NULL,
                    user_agent TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    metadata_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_audit_case ON audit_events(case_id);

                CREATE TABLE IF NOT EXISTS webhooks (
                    id TEXT PRIMARY KEY,
                    subscriber_url TEXT NOT NULL,
                    events_json TEXT NOT NULL,
                    secret TEXT NOT NULL,
                    active INTEGER NOT NULL,
                    created_at TEXT NOT NULL
                );
                """
            )

    # --- Cases ---
    def save_case(self, case: Case) -> Case:
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO cases (id, title, owner, status, legal_basis, purpose, notes_json, created_at, closed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    title = excluded.title,
                    owner = excluded.owner,
                    status = excluded.status,
                    legal_basis = excluded.legal_basis,
                    purpose = excluded.purpose,
                    notes_json = excluded.notes_json,
                    closed_at = excluded.closed_at
                """,
                (
                    case.id,
                    case.title,
                    case.owner,
                    case.status.value,
                    case.legal_basis.value,
                    case.purpose,
                    json.dumps(case.notes, ensure_ascii=False),
                    case.created_at,
                    case.closed_at,
                ),
            )
        return case

    def get_case(self, case_id: str) -> Case | None:
        cur = self._conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,))
        row = cur.fetchone()
        if row is None:
            return None
        return self._row_to_case(row)

    def list_cases(self) -> list[Case]:
        cur = self._conn.execute("SELECT * FROM cases ORDER BY created_at DESC")
        return [self._row_to_case(r) for r in cur.fetchall()]

    def delete_case(self, case_id: str) -> bool:
        with self._conn:
            cur = self._conn.execute("DELETE FROM cases WHERE id = ?", (case_id,))
            self._conn.execute("DELETE FROM targets WHERE case_id = ?", (case_id,))
            self._conn.execute("DELETE FROM collection_jobs WHERE case_id = ?", (case_id,))
            self._conn.execute("DELETE FROM raw_evidence WHERE case_id = ?", (case_id,))
            self._conn.execute("DELETE FROM normalized_observations WHERE case_id = ?", (case_id,))
            self._conn.execute("DELETE FROM entities WHERE case_id = ?", (case_id,))
            self._conn.execute("DELETE FROM entity_relationships WHERE case_id = ?", (case_id,))
            self._conn.execute("DELETE FROM correlation_findings WHERE case_id = ?", (case_id,))
        return cur.rowcount > 0

    @staticmethod
    def _row_to_case(row: sqlite3.Row) -> Case:
        return Case(
            id=row["id"],
            title=row["title"],
            owner=row["owner"],
            status=CaseStatus(row["status"]),
            legal_basis=LegalBasis(row["legal_basis"]),
            purpose=row["purpose"],
            notes=json.loads(row["notes_json"]),
            created_at=row["created_at"],
            closed_at=row["closed_at"],
        )

    # --- Targets ---
    def save_target(self, target: Target) -> Target:
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO targets (id, case_id, type, value, normalized_value, risk, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    risk = excluded.risk,
                    last_seen = excluded.last_seen
                """,
                (
                    target.id,
                    target.case_id,
                    target.type.value,
                    target.value,
                    target.normalized_value,
                    target.risk.value,
                    target.first_seen,
                    target.last_seen,
                ),
            )
        return target

    def get_target(self, target_id: str) -> Target | None:
        cur = self._conn.execute("SELECT * FROM targets WHERE id = ?", (target_id,))
        row = cur.fetchone()
        return self._row_to_target(row) if row else None

    def list_targets(self, case_id: str) -> list[Target]:
        cur = self._conn.execute(
            "SELECT * FROM targets WHERE case_id = ? ORDER BY first_seen ASC", (case_id,)
        )
        return [self._row_to_target(r) for r in cur.fetchall()]

    @staticmethod
    def _row_to_target(row: sqlite3.Row) -> Target:
        return Target(
            id=row["id"],
            case_id=row["case_id"],
            type=TargetType(row["type"]),
            value=row["value"],
            normalized_value=row["normalized_value"],
            risk=RiskLevel(row["risk"]),
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
        )

    # --- Collection Jobs ---
    def save_job(self, job: CollectionJob) -> CollectionJob:
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO collection_jobs (
                    id, case_id, target_id, source_id, status, priority,
                    idempotency_key, requested_at, started_at, finished_at, error, cost, duration_ms
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    status = excluded.status,
                    started_at = excluded.started_at,
                    finished_at = excluded.finished_at,
                    error = excluded.error,
                    cost = excluded.cost,
                    duration_ms = excluded.duration_ms
                """,
                (
                    job.id,
                    job.case_id,
                    job.target_id,
                    job.source_id,
                    job.status.value,
                    job.priority,
                    job.idempotency_key,
                    job.requested_at,
                    job.started_at,
                    job.finished_at,
                    job.error,
                    job.cost,
                    job.duration_ms,
                ),
            )
        return job

    def get_job(self, job_id: str) -> CollectionJob | None:
        cur = self._conn.execute("SELECT * FROM collection_jobs WHERE id = ?", (job_id,))
        row = cur.fetchone()
        return self._row_to_job(row) if row else None

    def list_jobs(self, case_id: str) -> list[CollectionJob]:
        cur = self._conn.execute(
            "SELECT * FROM collection_jobs WHERE case_id = ? ORDER BY requested_at ASC",
            (case_id,),
        )
        return [self._row_to_job(r) for r in cur.fetchall()]

    @staticmethod
    def _row_to_job(row: sqlite3.Row) -> CollectionJob:
        return CollectionJob(
            id=row["id"],
            case_id=row["case_id"],
            target_id=row["target_id"],
            source_id=row["source_id"],
            status=JobStatus(row["status"]),
            priority=int(row["priority"]),
            idempotency_key=row["idempotency_key"],
            requested_at=row["requested_at"],
            started_at=row["started_at"],
            finished_at=row["finished_at"],
            error=row["error"],
            cost=float(row["cost"]),
            duration_ms=float(row["duration_ms"]),
        )

    # --- Raw Evidence ---
    def save_evidence(self, ev: RawEvidence) -> RawEvidence:
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO raw_evidence (
                    id, case_id, job_id, source_id, source_name, url,
                    retrieved_at, adapter_version, content_hash, raw_payload_json,
                    legal_basis, retention_expires_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ev.id,
                    ev.case_id,
                    ev.job_id,
                    ev.source_id,
                    ev.source_name,
                    ev.url,
                    ev.retrieved_at,
                    ev.adapter_version,
                    ev.content_hash,
                    json.dumps(ev.raw_payload, ensure_ascii=False, default=str),
                    ev.legal_basis.value,
                    ev.retention_expires_at,
                ),
            )
        return ev

    def list_evidence(self, case_id: str) -> list[RawEvidence]:
        cur = self._conn.execute(
            "SELECT * FROM raw_evidence WHERE case_id = ? ORDER BY retrieved_at ASC",
            (case_id,),
        )
        return [
            RawEvidence(
                id=r["id"],
                case_id=r["case_id"],
                job_id=r["job_id"],
                source_id=r["source_id"],
                source_name=r["source_name"],
                url=r["url"],
                retrieved_at=r["retrieved_at"],
                adapter_version=r["adapter_version"],
                content_hash=r["content_hash"],
                raw_payload=json.loads(r["raw_payload_json"]),
                legal_basis=LegalBasis(r["legal_basis"]),
                retention_expires_at=r["retention_expires_at"],
            )
            for r in cur.fetchall()
        ]

    # --- Normalized Observations ---
    def save_observation(self, obs: NormalizedObservation) -> NormalizedObservation:
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO normalized_observations (
                    id, case_id, evidence_id, source_id, entity_type, entity_value,
                    canonical_value, observed_at, confidence, verification,
                    tags_json, attributes_json, related_to_value, related_to_type, relation
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    obs.id,
                    obs.case_id,
                    obs.evidence_id,
                    obs.source_id,
                    obs.entity_type.value,
                    obs.entity_value,
                    obs.canonical_value,
                    obs.observed_at,
                    obs.confidence,
                    obs.verification.value,
                    json.dumps(obs.tags, ensure_ascii=False),
                    json.dumps(obs.attributes, ensure_ascii=False, default=str),
                    obs.related_to_value,
                    obs.related_to_type.value if obs.related_to_type else None,
                    obs.relation.value,
                ),
            )
        return obs

    def list_observations(self, case_id: str) -> list[NormalizedObservation]:
        cur = self._conn.execute(
            "SELECT * FROM normalized_observations WHERE case_id = ? ORDER BY observed_at ASC",
            (case_id,),
        )
        return [
            NormalizedObservation(
                id=r["id"],
                case_id=r["case_id"],
                evidence_id=r["evidence_id"],
                source_id=r["source_id"],
                entity_type=EntityType(r["entity_type"]),
                entity_value=r["entity_value"],
                canonical_value=r["canonical_value"],
                observed_at=r["observed_at"],
                confidence=float(r["confidence"]),
                verification=VerificationStatus(r["verification"]),
                tags=json.loads(r["tags_json"]),
                attributes=json.loads(r["attributes_json"]),
                related_to_value=r["related_to_value"],
                related_to_type=EntityType(r["related_to_type"]) if r["related_to_type"] else None,
                relation=RelationType(r["relation"]),
            )
            for r in cur.fetchall()
        ]

    # --- Entities ---
    def save_entity(self, entity: Entity) -> Entity:
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO entities (
                    id, case_id, type, canonical_value, aliases_json,
                    attributes_json, confidence, sources_json, first_seen, last_seen
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(case_id, type, canonical_value) DO UPDATE SET
                    aliases_json = excluded.aliases_json,
                    attributes_json = excluded.attributes_json,
                    confidence = MAX(entities.confidence, excluded.confidence),
                    sources_json = excluded.sources_json,
                    last_seen = excluded.last_seen
                """,
                (
                    entity.id,
                    entity.case_id,
                    entity.type.value,
                    entity.canonical_value,
                    json.dumps(entity.aliases, ensure_ascii=False),
                    json.dumps(entity.attributes, ensure_ascii=False, default=str),
                    entity.confidence,
                    json.dumps(entity.sources, ensure_ascii=False),
                    entity.first_seen,
                    entity.last_seen,
                ),
            )
        return entity

    def find_entity(
        self, case_id: str, entity_type: EntityType, canonical_value: str
    ) -> Entity | None:
        cur = self._conn.execute(
            "SELECT * FROM entities WHERE case_id = ? AND type = ? AND canonical_value = ?",
            (case_id, entity_type.value, canonical_value),
        )
        row = cur.fetchone()
        return self._row_to_entity(row) if row else None

    def list_entities(self, case_id: str) -> list[Entity]:
        cur = self._conn.execute(
            "SELECT * FROM entities WHERE case_id = ? ORDER BY first_seen ASC",
            (case_id,),
        )
        return [self._row_to_entity(r) for r in cur.fetchall()]

    @staticmethod
    def _row_to_entity(row: sqlite3.Row) -> Entity:
        return Entity(
            id=row["id"],
            case_id=row["case_id"],
            type=EntityType(row["type"]),
            canonical_value=row["canonical_value"],
            aliases=json.loads(row["aliases_json"]),
            attributes=json.loads(row["attributes_json"]),
            confidence=float(row["confidence"]),
            sources=json.loads(row["sources_json"]),
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
        )

    # --- Entity Relationships ---
    def save_relationship(self, rel: EntityRelationship) -> EntityRelationship:
        with self._conn:
            # Check if identical edge already exists in case
            cur = self._conn.execute(
                """
                SELECT id FROM entity_relationships
                WHERE case_id = ? AND from_entity_id = ? AND to_entity_id = ? AND relation = ?
                """,
                (rel.case_id, rel.from_entity_id, rel.to_entity_id, rel.relation.value),
            )
            existing = cur.fetchone()
            if existing:
                self._conn.execute(
                    """
                    UPDATE entity_relationships
                    SET confidence = MAX(confidence, ?), last_seen = ?
                    WHERE id = ?
                    """,
                    (rel.confidence, rel.last_seen, existing["id"]),
                )
                rel.id = existing["id"]
                return rel

            self._conn.execute(
                """
                INSERT INTO entity_relationships (
                    id, case_id, from_entity_id, to_entity_id, from_label, to_label,
                    relation, confidence, evidence_id, source_id, first_seen, last_seen
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    rel.id,
                    rel.case_id,
                    rel.from_entity_id,
                    rel.to_entity_id,
                    rel.from_label,
                    rel.to_label,
                    rel.relation.value,
                    rel.confidence,
                    rel.evidence_id,
                    rel.source_id,
                    rel.first_seen,
                    rel.last_seen,
                ),
            )
        return rel

    def list_relationships(self, case_id: str) -> list[EntityRelationship]:
        cur = self._conn.execute(
            "SELECT * FROM entity_relationships WHERE case_id = ? ORDER BY first_seen ASC",
            (case_id,),
        )
        return [
            EntityRelationship(
                id=r["id"],
                case_id=r["case_id"],
                from_entity_id=r["from_entity_id"],
                to_entity_id=r["to_entity_id"],
                from_label=r["from_label"],
                to_label=r["to_label"],
                relation=RelationType(r["relation"]),
                confidence=float(r["confidence"]),
                evidence_id=r["evidence_id"],
                source_id=r["source_id"],
                first_seen=r["first_seen"],
                last_seen=r["last_seen"],
            )
            for r in cur.fetchall()
        ]

    # --- Correlation Findings ---
    def save_finding(self, finding: CorrelationFinding) -> CorrelationFinding:
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO correlation_findings (
                    id, case_id, rule_id, title, description, risk, confidence,
                    involved_entities_json, evidence_ids_json, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding.id,
                    finding.case_id,
                    finding.rule_id,
                    finding.title,
                    finding.description,
                    finding.risk.value,
                    finding.confidence,
                    json.dumps(finding.involved_entities, ensure_ascii=False),
                    json.dumps(finding.evidence_ids, ensure_ascii=False),
                    finding.created_at,
                ),
            )
        return finding

    def list_findings(self, case_id: str) -> list[CorrelationFinding]:
        cur = self._conn.execute(
            "SELECT * FROM correlation_findings WHERE case_id = ? ORDER BY created_at ASC",
            (case_id,),
        )
        return [
            CorrelationFinding(
                id=r["id"],
                case_id=r["case_id"],
                rule_id=r["rule_id"],
                title=r["title"],
                description=r["description"],
                risk=RiskLevel(r["risk"]),
                confidence=float(r["confidence"]),
                involved_entities=json.loads(r["involved_entities_json"]),
                evidence_ids=json.loads(r["evidence_ids_json"]),
                created_at=r["created_at"],
            )
            for r in cur.fetchall()
        ]

    # --- Audit Trail ---
    def record_audit(self, audit: AuditEvent) -> AuditEvent:
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO audit_events (
                    id, actor_id, actor_role, case_id, action, object_id,
                    ip, user_agent, timestamp, metadata_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    audit.id,
                    audit.actor_id,
                    audit.actor_role,
                    audit.case_id,
                    audit.action,
                    audit.object_id,
                    audit.ip,
                    audit.user_agent,
                    audit.timestamp,
                    json.dumps(audit.metadata, ensure_ascii=False, default=str),
                ),
            )
        return audit

    def list_audit_events(self, case_id: str | None = None, limit: int = 100) -> list[AuditEvent]:
        if case_id:
            cur = self._conn.execute(
                "SELECT * FROM audit_events WHERE case_id = ? ORDER BY timestamp DESC LIMIT ?",
                (case_id, limit),
            )
        else:
            cur = self._conn.execute(
                "SELECT * FROM audit_events ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            )
        return [
            AuditEvent(
                id=r["id"],
                actor_id=r["actor_id"],
                actor_role=r["actor_role"],
                case_id=r["case_id"],
                action=r["action"],
                object_id=r["object_id"],
                ip=r["ip"],
                user_agent=r["user_agent"],
                timestamp=r["timestamp"],
                metadata=json.loads(r["metadata_json"]),
            )
            for r in cur.fetchall()
        ]

    # --- Webhooks ---
    def save_webhook(self, wh: WebhookSubscription) -> WebhookSubscription:
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO webhooks (id, subscriber_url, events_json, secret, active, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    subscriber_url = excluded.subscriber_url,
                    events_json = excluded.events_json,
                    active = excluded.active
                """,
                (
                    wh.id,
                    wh.subscriber_url,
                    json.dumps(wh.events),
                    wh.secret,
                    1 if wh.active else 0,
                    wh.created_at,
                ),
            )
        return wh

    def list_webhooks(self) -> list[WebhookSubscription]:
        cur = self._conn.execute("SELECT * FROM webhooks ORDER BY created_at DESC")
        return [
            WebhookSubscription(
                id=r["id"],
                subscriber_url=r["subscriber_url"],
                events=json.loads(r["events_json"]),
                secret=r["secret"],
                active=bool(r["active"]),
                created_at=r["created_at"],
            )
            for r in cur.fetchall()
        ]

    def delete_webhook(self, webhook_id: str) -> bool:
        with self._conn:
            cur = self._conn.execute("DELETE FROM webhooks WHERE id = ?", (webhook_id,))
        return cur.rowcount > 0

    def close(self) -> None:
        self._conn.close()
