"""Phase 2 Expansion Services: Watchlists & Alerts, Collaboration, Data Governance & Assistive AI."""

import re
from typing import Any

from godseye.collectors.registry import CollectorRegistry
from godseye.core.security import check_permission, compute_content_hash
from godseye.db.repository import OsintRepository
from godseye.domain.enums import (
    EventType,
    RiskLevel,
    Role,
    TargetType,
    TrustLevel,
    VerificationStatus,
)
from godseye.domain.events import CloudEvent, EventBus
from godseye.domain.models import (
    AIInference,
    Alert,
    AlertRule,
    AuditEvent,
    CaseComment,
    CaseVersion,
    DataConflict,
    DataQualityScore,
    InvestigativeTask,
    NormalizedObservation,
    VerificationRecord,
    Watchlist,
    utc_now_iso,
)
from godseye.services.case_service import detect_target_type, normalize_target_value


class WatchlistService:
    """Continuous monitoring Watchlist and Alert engine (Section 2 of expansao-osint-modulos-fontes-apis.md)."""

    MONITORED_EVENTS: tuple[EventType, ...] = (
        EventType.ENTITY_CREATED,
        EventType.ENTITY_UPDATED,
        EventType.ENTITY_MERGED,
        EventType.RELATIONSHIP_CREATED,
        EventType.BREACH_DETECTED,
        EventType.SANCTION_DETECTED,
        EventType.LEGAL_CASE_CREATED,
        EventType.LEGAL_CASE_UPDATED,
        EventType.DOMAIN_CERTIFICATE_ISSUED,
        EventType.DOMAIN_SUBDOMAIN_DISCOVERED,
        EventType.CRYPTO_ADDRESS_FLAGGED,
        EventType.NEWS_MENTION_DETECTED,
        EventType.OFFICIAL_GAZETTE_MENTION_DETECTED,
    )

    def __init__(self, repo: OsintRepository, event_bus: EventBus) -> None:
        self.repo = repo
        self.event_bus = event_bus
        for ev_type in self.MONITORED_EVENTS:
            self.event_bus.subscribe(ev_type, self._handle_event)

    def create_watchlist(
        self,
        case_id: str,
        value: str,
        target_type: TargetType | None = None,
        frequency: str = "realtime",
        severity: RiskLevel = RiskLevel.HIGH,
        owner: str = "sec-analyst",
        actor_role: Role = Role.INVESTIGATOR,
    ) -> Watchlist:
        """Create a Watchlist monitoring a target/entity with default alert rules."""
        check_permission(actor_role, "watchlist:manage")
        resolved_type = target_type or detect_target_type(value)
        normalized = normalize_target_value(resolved_type, value)

        wl = Watchlist(
            case_id=case_id,
            type=resolved_type,
            value=normalized,
            frequency=frequency,
            owner=owner,
        )
        default_rules = [
            AlertRule(
                watchlist_id=wl.id,
                event_type="*",
                condition="target_match",
                threshold=0.5,
                severity=severity,
                cooldown_minutes=15,
            )
        ]
        wl.alert_rules = default_rules
        self.repo.save_watchlist(wl)
        self.repo.record_audit(
            AuditEvent(
                actor_id=owner,
                actor_role=actor_role.value,
                case_id=case_id,
                action="watchlist.created",
                object_id=wl.id,
                metadata={"type": resolved_type.value, "value": normalized},
            )
        )
        return wl

    async def _handle_event(self, event: CloudEvent) -> None:
        """Evaluate active watchlists against incoming pipeline events."""
        case_id = str(event.data.get("case_id") or "")
        watchlists = self.repo.list_watchlists(case_id=case_id if case_id else None)
        if not watchlists:
            return

        payload_str = str(event.data).lower()
        for wl in watchlists:
            if not wl.active:
                continue
            if wl.value.lower() in payload_str or wl.case_id == case_id:
                severity = wl.alert_rules[0].severity if wl.alert_rules else RiskLevel.HIGH
                msg = (
                    f"[{event.type}] Watchlist '{wl.value}' triggered by source "
                    f"'{event.data.get('source_id', event.source)}': {event.data.get('summary', event.data.get('entity_value', 'new intelligence'))}"
                )
                alert = Alert(
                    watchlist_id=wl.id,
                    case_id=wl.case_id,
                    source_id=str(event.data.get("source_id") or event.source),
                    evidence_id=event.data.get("evidence_id"),
                    severity=severity,
                    message=msg,
                )
                self.repo.save_alert(alert)

    def acknowledge_alert(
        self,
        alert_id: str,
        actor_id: str = "sec-analyst",
        actor_role: Role = Role.ANALYST,
    ) -> Alert | None:
        """Mark a triggered alert as acknowledged by an analyst."""
        check_permission(actor_role, "alert:acknowledge")
        alert = self.repo.get_alert(alert_id)
        if alert is None:
            return None
        alert.acknowledged_by = actor_id
        alert.acknowledged_at = utc_now_iso()
        self.repo.save_alert(alert)
        self.repo.record_audit(
            AuditEvent(
                actor_id=actor_id,
                actor_role=actor_role.value,
                case_id=alert.case_id,
                action="alert.acknowledged",
                object_id=alert_id,
            )
        )
        return alert

    def list_watchlists(
        self,
        case_id: str | None = None,
        actor_role: Role = Role.ANALYST,
    ) -> list[Watchlist]:
        """List active/configured watchlists."""
        check_permission(actor_role, "case:read")
        return self.repo.list_watchlists(case_id=case_id)

    def list_alerts(
        self,
        watchlist_id: str | None = None,
        case_id: str | None = None,
        unacknowledged_only: bool = False,
        actor_role: Role = Role.ANALYST,
    ) -> list[Alert]:
        """List triggered alerts with optional filtering."""
        check_permission(actor_role, "case:read")
        items = self.repo.list_alerts(case_id=case_id, watchlist_id=watchlist_id)
        if unacknowledged_only:
            items = [a for a in items if a.acknowledged_at is None]
        return items


class CollaborationService:
    """Team investigative collaboration: comments, @mentions, tasks, verifications & dossier versions (Section 7)."""

    MENTION_RE = re.compile(r"@([a-zA-Z0-9_.-]+)")

    def __init__(self, repo: OsintRepository) -> None:
        self.repo = repo

    def add_comment(
        self,
        case_id: str,
        body: str,
        author_id: str = "sec-analyst",
        entity_id: str | None = None,
        evidence_id: str | None = None,
        actor_role: Role = Role.ANALYST,
    ) -> CaseComment:
        """Add a comment to a case, entity, or evidence item and extract @mentions."""
        check_permission(actor_role, "collaboration:write")
        mentions = [m.rstrip(".-") for m in self.MENTION_RE.findall(body) if m.rstrip(".-")]
        comment = CaseComment(
            case_id=case_id,
            entity_id=entity_id,
            evidence_id=evidence_id,
            author_id=author_id,
            body=body,
            mentions=mentions,
        )
        self.repo.save_comment(comment)
        self.repo.record_audit(
            AuditEvent(
                actor_id=author_id,
                actor_role=actor_role.value,
                case_id=case_id,
                action="comment.added",
                object_id=comment.id,
                metadata={"mentions": mentions},
            )
        )
        return comment

    def create_task(
        self,
        case_id: str,
        title: str,
        description: str = "",
        assignee_id: str = "sec-analyst",
        due_date: str | None = None,
        created_by: str = "sec-analyst",
        actor_role: Role = Role.ANALYST,
    ) -> InvestigativeTask:
        """Create and assign an investigative task inside a case."""
        check_permission(actor_role, "collaboration:write")
        task = InvestigativeTask(
            case_id=case_id,
            title=title,
            description=description,
            assignee_id=assignee_id,
            due_date=due_date,
            created_by=created_by,
        )
        self.repo.save_task(task)
        return task

    def verify_finding(
        self,
        case_id: str,
        status: VerificationStatus,
        reason: str,
        entity_id: str | None = None,
        relationship_id: str | None = None,
        evidence_id: str | None = None,
        reviewer_id: str = "sec-analyst",
        actor_role: Role = Role.ANALYST,
    ) -> VerificationRecord:
        """Record human verification decision (`corroborated`, `contested`, `false_positive`)."""
        check_permission(actor_role, "collaboration:write")
        ver = VerificationRecord(
            case_id=case_id,
            entity_id=entity_id,
            relationship_id=relationship_id,
            status=status,
            reviewer_id=reviewer_id,
            reason=reason,
            evidence_id=evidence_id,
        )
        self.repo.save_verification(ver)

        # If entity is marked false_positive or contested, reflect in entity attributes
        if entity_id:
            ent = self.repo.get_entity_by_id(entity_id)
            if ent:
                ent.attributes["human_verification"] = status.value
                ent.attributes["verification_reason"] = reason
                if status in {VerificationStatus.CONTESTED, VerificationStatus.FALSE_POSITIVE}:
                    ent.confidence = min(ent.confidence, 0.25)
                elif status in {VerificationStatus.VERIFIED, VerificationStatus.CORROBORATED}:
                    ent.confidence = max(ent.confidence, 0.95)
                self.repo.save_entity(ent)

        self.repo.record_audit(
            AuditEvent(
                actor_id=reviewer_id,
                actor_role=actor_role.value,
                case_id=case_id,
                action="verification.recorded",
                object_id=ver.id,
                metadata={"status": status.value, "entity_id": entity_id},
            )
        )
        return ver

    def create_case_version(
        self,
        case_id: str,
        change_summary: str,
        dossier_payload: dict[str, Any],
        created_by: str = "sec-analyst",
        actor_role: Role = Role.INVESTIGATOR,
    ) -> CaseVersion:
        """Create an immutable versioned snapshot of a case dossier (Section 7.2)."""
        check_permission(actor_role, "collaboration:write")
        existing = self.repo.list_case_versions(case_id)
        next_ver = len(existing) + 1
        snap_hash = compute_content_hash(dossier_payload)
        cv = CaseVersion(
            case_id=case_id,
            version=next_ver,
            snapshot_url=f"godseye://cases/{case_id}/versions/v{next_ver}",
            snapshot_hash=snap_hash,
            created_by=created_by,
            change_summary=change_summary,
        )
        return self.repo.save_case_version(cv)

    def list_comments(self, case_id: str, actor_role: Role = Role.ANALYST) -> list[CaseComment]:
        check_permission(actor_role, "case:read")
        return self.repo.list_comments(case_id)

    def list_tasks(self, case_id: str, actor_role: Role = Role.ANALYST) -> list[InvestigativeTask]:
        check_permission(actor_role, "case:read")
        return self.repo.list_tasks(case_id)

    def update_task_status(
        self,
        case_id: str,
        task_id: str,
        status: str,
        actor_role: Role = Role.ANALYST,
    ) -> InvestigativeTask | None:
        check_permission(actor_role, "collaboration:write")
        tasks = self.repo.list_tasks(case_id)
        for t in tasks:
            if t.id == task_id:
                t.status = status
                return self.repo.save_task(t)
        return None

    def list_verifications(
        self, case_id: str, actor_role: Role = Role.ANALYST
    ) -> list[VerificationRecord]:
        check_permission(actor_role, "case:read")
        return self.repo.list_verifications(case_id)

    def list_case_versions(self, case_id: str, actor_role: Role = Role.ANALYST) -> list[CaseVersion]:
        check_permission(actor_role, "case:read")
        return self.repo.list_case_versions(case_id)


class DataGovernanceService:
    """Data Quality Scoring & Conflict Detection Engine (Section 8 of expansao-osint-modulos-fontes-apis.md)."""

    TRUST_WEIGHTS: dict[TrustLevel, float] = {
        TrustLevel.OFFICIAL: 0.55,
        TrustLevel.HIGH: 0.48,
        TrustLevel.MEDIUM: 0.35,
        TrustLevel.LOW: 0.20,
    }

    def __init__(self, repo: OsintRepository, registry: CollectorRegistry) -> None:
        self.repo = repo
        self.registry = registry

    def calculate_observation_quality(
        self,
        obs: NormalizedObservation,
        corroboration_count: int = 1,
        has_conflict: bool = False,
        is_stale: bool = False,
    ) -> DataQualityScore:
        """Compute multi-factor confidence score per Section 8.1 formula."""
        meta = self.registry.get_source_metadata(obs.source_id)
        trust_level = meta.trust_level if meta else TrustLevel.HIGH

        source_trust = self.TRUST_WEIGHTS.get(trust_level, 0.45)
        recency = 0.25 if not is_stale else 0.10
        corroboration_bonus = min(0.20, (corroboration_count - 1) * 0.07)
        official_bonus = 0.12 if trust_level == TrustLevel.OFFICIAL else 0.0
        conflict_penalty = 0.25 if has_conflict else 0.0
        stale_penalty = 0.15 if is_stale else 0.0

        raw_score = (
            source_trust
            + recency
            + corroboration_bonus
            + official_bonus
            - conflict_penalty
            - stale_penalty
        )
        final_score = round(max(0.05, min(1.0, raw_score)), 3)

        explanation = (
            f"trust({trust_level.value})={source_trust:.2f} + recency={recency:.2f} "
            f"+ corroboration({corroboration_count})={corroboration_bonus:.2f} "
            f"+ official_bonus={official_bonus:.2f} - conflict={conflict_penalty:.2f} "
            f"- stale={stale_penalty:.2f} => {final_score:.3f}"
        )
        qs = DataQualityScore(
            case_id=obs.case_id,
            observation_id=obs.id,
            source_trust=source_trust,
            recency=recency,
            corroboration_count=corroboration_count,
            official_source_bonus=official_bonus,
            conflict_penalty=conflict_penalty,
            stale_penalty=stale_penalty,
            final_score=final_score,
            explanation=explanation,
        )
        return self.repo.save_quality_score(qs)

    def evaluate_case_governance(self, case_id: str) -> dict[str, Any]:
        """Calculate quality scores for observations and detect attribute conflicts across sources."""
        observations = self.repo.list_observations(case_id)
        entities = self.repo.list_entities(case_id)
        scores: list[DataQualityScore] = []
        conflicts: list[DataConflict] = []

        # Group observations by canonical entity value
        by_canonical: dict[str, list[NormalizedObservation]] = {}
        for obs in observations:
            by_canonical.setdefault(obs.canonical_value, []).append(obs)

        for canonical_val, obs_group in by_canonical.items():
            sources_set = {o.source_id for o in obs_group}
            corroboration = max(1, len(sources_set))

            # Detect conflicts if two observations on same entity report different status/country
            conflict_detected = False
            if len(obs_group) >= 2:
                first_obs = obs_group[0]
                for other_obs in obs_group[1:]:
                    for attr_key in ("situacao_cadastral", "country", "uf", "status"):
                        v1 = first_obs.attributes.get(attr_key)
                        v2 = other_obs.attributes.get(attr_key)
                        if v1 and v2 and str(v1).upper() != str(v2).upper():
                            conflict_detected = True
                            ent_match = next(
                                (e for e in entities if e.canonical_value == canonical_val), None
                            )
                            conflict = DataConflict(
                                case_id=case_id,
                                entity_id=ent_match.id if ent_match else canonical_val,
                                observation_a_id=first_obs.id,
                                observation_b_id=other_obs.id,
                                conflict_type=f"attribute_mismatch:{attr_key}",
                                description=(
                                    f"Source '{first_obs.source_id}' reported {attr_key}='{v1}' "
                                    f"while '{other_obs.source_id}' reported {attr_key}='{v2}'"
                                ),
                            )
                            self.repo.save_conflict(conflict)
                            conflicts.append(conflict)

            for obs in obs_group:
                qs = self.calculate_observation_quality(
                    obs,
                    corroboration_count=corroboration,
                    has_conflict=conflict_detected,
                )
                scores.append(qs)

        avg_score = (
            round(sum(s.final_score for s in scores) / len(scores), 3) if scores else 0.0
        )
        return {
            "case_id": case_id,
            "average_quality_score": avg_score,
            "scores_calculated": len(scores),
            "conflicts_detected": len(conflicts),
            "scores": [s.model_dump() for s in scores[:25]],
            "conflicts": [c.model_dump() for c in self.repo.list_conflicts(case_id)],
        }


class AssistiveAIService:
    """Auditable Assistive AI layer (Section 9): Strictly marked `model_generated` & requires human review."""

    def __init__(self, repo: OsintRepository) -> None:
        self.repo = repo

    def generate_case_analysis(
        self,
        case_id: str,
        task_type: str = "dossier_summary",
        actor_id: str = "sec-analyst",
        actor_role: Role = Role.ANALYST,
    ) -> AIInference:
        """Synthesize an assistive analysis from existing case evidence without altering ground-truth graph."""
        check_permission(actor_role, "evidence:read")
        case = self.repo.get_case(case_id)
        if case is None:
            raise ValueError(f"Case '{case_id}' not found")

        entities = self.repo.list_entities(case_id)
        relationships = self.repo.list_relationships(case_id)
        findings = self.repo.list_findings(case_id)
        evidence = self.repo.list_evidence(case_id)

        evidence_ids = [e.id for e in evidence[:15]]
        prompt_repr = f"task={task_type}|case={case_id}|entities={len(entities)}|edges={len(relationships)}"
        prompt_hash = compute_content_hash(prompt_repr)

        entity_summary = ", ".join(f"{e.type.value}:{e.canonical_value}" for e in entities[:8])
        findings_summary = (
            "; ".join(f"[{f.risk.value.upper()}] {f.title}" for f in findings)
            or "No critical rule alerts triggered yet"
        )

        output_text = (
            f"[MODEL_GENERATED — REQUIRES HUMAN REVIEW]\n"
            f"• Case: '{case.title}' (Legal Basis: {case.legal_basis.value})\n"
            f"• Evidence Base: {len(evidence)} SHA-256 verified evidence item(s), "
            f"{len(entities)} deduplicated entities ({entity_summary}), and {len(relationships)} graph relationship(s).\n"
            f"• Key Risk Correlations: {findings_summary}.\n"
            f"• Recommended Analyst Next Steps: Verify high-confidence official sources first, "
            f"review any contested/unverified SOCMINT leads, and approve or reject this assistive synthesis."
        )

        inference = AIInference(
            case_id=case_id,
            input_evidence_ids=evidence_ids,
            model="godseye-assistive-synthesizer",
            model_version="1.0.0",
            prompt_hash=prompt_hash,
            task_type=task_type,
            output=output_text,
            confidence_kind="model_generated",
            human_review_status="pending_review",
        )
        self.repo.save_ai_inference(inference)
        self.repo.record_audit(
            AuditEvent(
                actor_id=actor_id,
                actor_role=actor_role.value,
                case_id=case_id,
                action="ai_inference.generated",
                object_id=inference.id,
                metadata={
                    "task_type": task_type,
                    "confidence_kind": "model_generated",
                    "human_review_status": "pending_review",
                },
            )
        )
        return inference

    def review_inference(
        self,
        inference_id: str,
        decision: str,
        reviewer_id: str = "sec-analyst",
        actor_role: Role = Role.ANALYST,
    ) -> AIInference | None:
        """Approve or reject an AIInference (`approved` or `rejected`) per Section 9.2."""
        check_permission(actor_role, "ai:review")
        inf = self.repo.get_ai_inference(inference_id)
        if inf is None:
            return None
        normalized_decision = decision.lower().strip()
        if normalized_decision not in {"approved", "rejected"}:
            raise ValueError("Decision must be 'approved' or 'rejected'")
        inf.human_review_status = normalized_decision
        inf.reviewed_by = reviewer_id
        inf.reviewed_at = utc_now_iso()
        self.repo.save_ai_inference(inf)
        self.repo.record_audit(
            AuditEvent(
                actor_id=reviewer_id,
                actor_role=actor_role.value,
                case_id=inf.case_id,
                action=f"ai_inference.{normalized_decision}",
                object_id=inference_id,
            )
        )
        return inf

    def list_inferences(
        self, case_id: str, actor_role: Role = Role.ANALYST
    ) -> list[AIInference]:
        check_permission(actor_role, "case:read")
        return self.repo.list_ai_inferences(case_id)
