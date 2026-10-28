"""FastAPI v1 REST API implementation (Section 10 & fastapi-pro skill)."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from godseye.collectors.registry import CollectorRegistry
from godseye.core.bootstrap import ensure_zero_config_environment
from godseye.core.cache import MultiTierCache
from godseye.core.config import get_settings
from godseye.core.resilience import ResilientHttpClient
from godseye.core.security import PermissionDeniedError
from godseye.db.repository import OsintRepository
from godseye.domain.enums import (
    CaseStatus,
    LegalBasis,
    RiskLevel,
    Role,
    TargetType,
    VerificationStatus,
)
from godseye.domain.events import EventBus
from godseye.domain.models import WebhookSubscription
from godseye.services.case_service import CaseService
from godseye.services.expansion import (
    AssistiveAIService,
    CollaborationService,
)
from godseye.services.orchestrator import InvestigationOrchestrator
from godseye.services.reporting import ReportingService


class CreateCaseRequest(BaseModel):
    title: str = Field(..., min_length=3, max_length=200)
    owner: str = Field(default="sec-analyst")
    legal_basis: LegalBasis = Field(default=LegalBasis.CYBERSECURITY_DEFENSE)
    purpose: str = Field(default="Authorized cybersecurity OSINT investigation")


class UpdateCaseRequest(BaseModel):
    status: CaseStatus | None = None
    note: str | None = None


class AddTargetRequest(BaseModel):
    value: str = Field(..., min_length=2)
    type: TargetType | None = None


class TriggerCollectionRequest(BaseModel):
    target_id: str | None = None
    max_depth: int = Field(default=2, ge=1, le=3)
    sources: list[str] | None = None


class CreateReportRequest(BaseModel):
    format: str = Field(default="json")


class UpdateSourceRequest(BaseModel):
    enabled: bool


class CreateWebhookRequest(BaseModel):
    subscriber_url: str
    events: list[str] = Field(default_factory=lambda: ["collection.completed"])
    secret: str = Field(default="")


class CreateWatchlistRequest(BaseModel):
    case_id: str = Field(default="")
    value: str = Field(..., min_length=2)
    target_type: TargetType | None = None
    frequency: str = Field(default="realtime")
    severity: RiskLevel = Field(default=RiskLevel.HIGH)


class CreateCommentRequest(BaseModel):
    body: str = Field(..., min_length=1)
    entity_id: str | None = None
    evidence_id: str | None = None


class CreateTaskRequest(BaseModel):
    title: str = Field(..., min_length=2, max_length=200)
    description: str = ""
    assignee_id: str = "sec-analyst"
    due_date: str | None = None


class UpdateTaskStatusRequest(BaseModel):
    status: str = Field(default="done")


class CreateVerificationRequest(BaseModel):
    entity_id: str | None = None
    relationship_id: str | None = None
    evidence_id: str | None = None
    status: VerificationStatus = Field(default=VerificationStatus.CORROBORATED)
    reason: str = Field(default="Analyst 4-eyes verification")


class CreateCaseVersionRequest(BaseModel):
    change_summary: str = Field(default="Analyst case snapshot")


class CreateAIAssistRequest(BaseModel):
    task_type: str = Field(default="dossier_summary")


class ReviewAIAssistRequest(BaseModel):
    decision: str = Field(default="approved")


class AppContainer:
    """Dependency container holding database, cache, HTTP client, and services."""

    def __init__(self, db_path: str | None = None) -> None:
        ensure_zero_config_environment()
        settings = get_settings()
        resolved_db = db_path or settings.db_path
        self.repo = OsintRepository(resolved_db)
        self.cache = MultiTierCache(resolved_db, l1_max_size=settings.l1_cache_max_size)
        self.http_client = ResilientHttpClient(
            timeout_sec=settings.http_timeout_seconds,
            max_retries=settings.http_max_retries,
            max_elapsed_sec=settings.http_max_elapsed_seconds,
        )
        self.registry = CollectorRegistry(
            http_client=self.http_client,
            cache=self.cache,
            offline_fallback=settings.offline_demo_fallback,
        )
        self.registry.import_brazuca_catalog()
        self.event_bus = EventBus()
        self.case_service = CaseService(self.repo)
        self.orchestrator = InvestigationOrchestrator(
            repo=self.repo,
            registry=self.registry,
            cache=self.cache,
            event_bus=self.event_bus,
            max_concurrency=settings.max_concurrency,
        )
        self.watchlist_service = self.orchestrator.watchlist_service
        self.governance_service = self.orchestrator.governance_service
        self.collaboration_service = CollaborationService(self.repo)
        self.ai_service = AssistiveAIService(self.repo)
        self.reporting = ReportingService(self.repo)

    async def shutdown(self) -> None:
        await self.http_client.close()
        self.cache.close()
        self.repo.close()


def get_actor_role(
    x_godseye_role: Annotated[str, Header()] = "investigator",
) -> Role:
    """Resolve RBAC Role from `X-GodsEye-Role` request header."""
    try:
        return Role(x_godseye_role.lower().strip())
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid role '{x_godseye_role}'. Valid roles: admin, investigator, analyst, auditor",
        ) from exc


def get_actor_id(
    x_godseye_actor: Annotated[str, Header()] = "sec-analyst",
) -> str:
    """Resolve actor identifier from `X-GodsEye-Actor` request header."""
    return x_godseye_actor.strip() or "sec-analyst"


def create_app(db_path: str | None = None) -> FastAPI:
    """Create and configure the FastAPI application."""
    container = AppContainer(db_path=db_path)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        yield
        await container.shutdown()

    app = FastAPI(
        title="God's Eye (𓂀) OSINT Platform API",
        version="1.0.0",
        description=(
            "Enterprise OSINT Aggregation, Correlation & Threat Intelligence Platform "
            "with Provenance, SHA-256 Evidence Integrity, RBAC, and LGPD Compliance."
        ),
        lifespan=lifespan,
    )
    app.state.container = container

    @app.exception_handler(PermissionDeniedError)
    async def handle_permission_denied(_req: Any, exc: PermissionDeniedError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"detail": str(exc)},
        )

    # --- Health & Observability ---
    @app.get("/health", tags=["Observability"])
    async def health_check() -> dict[str, Any]:
        return {
            "status": "ok",
            "service": "God's Eye (𓂀) OSINT Platform",
            "version": "1.0.0",
            "sources_registered": len(container.registry.list_sources()),
        }

    @app.get("/metrics", tags=["Observability"])
    async def metrics_endpoint() -> dict[str, Any]:
        return container.http_client.telemetry.snapshot()

    # --- 10.1 Cases ---
    @app.post("/api/v1/cases", status_code=status.HTTP_201_CREATED, tags=["Cases"])
    async def create_case(
        payload: CreateCaseRequest,
        role: Annotated[Role, Depends(get_actor_role)],
    ) -> dict[str, Any]:
        case = container.case_service.create_case(
            title=payload.title,
            owner=payload.owner,
            legal_basis=payload.legal_basis,
            purpose=payload.purpose,
            actor_role=role,
        )
        return case.model_dump()

    @app.get("/api/v1/cases", tags=["Cases"])
    async def list_cases(
        role: Annotated[Role, Depends(get_actor_role)],
    ) -> list[dict[str, Any]]:
        return [c.model_dump() for c in container.case_service.list_cases(actor_role=role)]

    @app.get("/api/v1/cases/{case_id}", tags=["Cases"])
    async def get_case(
        case_id: str,
        role: Annotated[Role, Depends(get_actor_role)],
    ) -> dict[str, Any]:
        case = container.case_service.get_case(case_id, actor_role=role)
        if case is None:
            raise HTTPException(status_code=404, detail="Case not found")
        return case.model_dump()

    @app.patch("/api/v1/cases/{case_id}", tags=["Cases"])
    async def update_case(
        case_id: str,
        payload: UpdateCaseRequest,
        actor: Annotated[str, Depends(get_actor_id)],
        role: Annotated[Role, Depends(get_actor_role)],
    ) -> dict[str, Any]:
        case = container.case_service.update_case(
            case_id,
            status=payload.status,
            note=payload.note,
            actor_id=actor,
            actor_role=role,
        )
        if case is None:
            raise HTTPException(status_code=404, detail="Case not found")
        return case.model_dump()

    @app.delete("/api/v1/cases/{case_id}", tags=["Cases"])
    async def delete_case(
        case_id: str,
        actor: Annotated[str, Depends(get_actor_id)],
        role: Annotated[Role, Depends(get_actor_role)],
    ) -> dict[str, Any]:
        deleted = container.case_service.delete_case(case_id, actor_id=actor, actor_role=role)
        if not deleted:
            raise HTTPException(status_code=404, detail="Case not found")
        return {"deleted": True, "case_id": case_id}

    # --- 10.2 Targets ---
    @app.post("/api/v1/cases/{case_id}/targets", status_code=status.HTTP_201_CREATED, tags=["Targets"])
    async def add_target(
        case_id: str,
        payload: AddTargetRequest,
        actor: Annotated[str, Depends(get_actor_id)],
        role: Annotated[Role, Depends(get_actor_role)],
    ) -> dict[str, Any]:
        if container.repo.get_case(case_id) is None:
            raise HTTPException(status_code=404, detail="Case not found")
        target = container.case_service.add_target(
            case_id=case_id,
            value=payload.value,
            target_type=payload.type,
            actor_id=actor,
            actor_role=role,
        )
        return target.model_dump()

    @app.get("/api/v1/cases/{case_id}/targets", tags=["Targets"])
    async def list_targets(case_id: str) -> list[dict[str, Any]]:
        return [t.model_dump() for t in container.repo.list_targets(case_id)]

    @app.get("/api/v1/targets/{target_id}", tags=["Targets"])
    async def get_target(target_id: str) -> dict[str, Any]:
        t = container.repo.get_target(target_id)
        if t is None:
            raise HTTPException(status_code=404, detail="Target not found")
        return t.model_dump()

    # --- 10.3 Collections ---
    @app.post("/api/v1/cases/{case_id}/collections", tags=["Collections"])
    async def trigger_collections(
        case_id: str,
        payload: TriggerCollectionRequest,
        actor: Annotated[str, Depends(get_actor_id)],
        role: Annotated[Role, Depends(get_actor_role)],
    ) -> dict[str, Any]:
        targets = container.repo.list_targets(case_id)
        if payload.target_id:
            targets = [t for t in targets if t.id == payload.target_id]
        if not targets:
            raise HTTPException(status_code=400, detail="No targets found for collection")

        results = []
        for t in targets:
            res = await container.orchestrator.investigate_target(
                case_id=case_id,
                target=t,
                max_depth=payload.max_depth,
                selected_sources=payload.sources,
                actor_id=actor,
                actor_role=role,
            )
            results.append(res)
        return {"case_id": case_id, "runs": results}

    @app.get("/api/v1/cases/{case_id}/collections", tags=["Collections"])
    async def list_collections(case_id: str) -> list[dict[str, Any]]:
        return [j.model_dump() for j in container.repo.list_jobs(case_id)]

    @app.get("/api/v1/collections/{job_id}", tags=["Collections"])
    async def get_collection_job(job_id: str) -> dict[str, Any]:
        job = container.repo.get_job(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="Collection job not found")
        return job.model_dump()

    # --- 10.4 Evidence, Entities, Relationships, Graph & Timeline ---
    @app.get("/api/v1/cases/{case_id}/evidence", tags=["Intelligence"])
    async def list_evidence(case_id: str) -> list[dict[str, Any]]:
        return [e.model_dump() for e in container.repo.list_evidence(case_id)]

    @app.get("/api/v1/cases/{case_id}/entities", tags=["Intelligence"])
    async def list_entities(case_id: str) -> list[dict[str, Any]]:
        return [e.model_dump() for e in container.repo.list_entities(case_id)]

    @app.get("/api/v1/cases/{case_id}/relationships", tags=["Intelligence"])
    async def list_relationships(case_id: str) -> list[dict[str, Any]]:
        return [r.model_dump() for r in container.repo.list_relationships(case_id)]

    @app.get("/api/v1/cases/{case_id}/graph", tags=["Intelligence"])
    async def get_graph(
        case_id: str,
        role: Annotated[Role, Depends(get_actor_role)],
    ) -> dict[str, Any]:
        return container.reporting.get_graph(case_id, actor_role=role)

    @app.get("/api/v1/cases/{case_id}/timeline", tags=["Intelligence"])
    async def get_timeline(
        case_id: str,
        role: Annotated[Role, Depends(get_actor_role)],
    ) -> list[dict[str, Any]]:
        return container.reporting.get_timeline(case_id, actor_role=role)

    # --- 10.5 Reports ---
    @app.post("/api/v1/cases/{case_id}/reports", tags=["Reports"])
    async def create_report(
        case_id: str,
        payload: CreateReportRequest,
        actor: Annotated[str, Depends(get_actor_id)],
        role: Annotated[Role, Depends(get_actor_role)],
    ) -> dict[str, Any]:
        if container.repo.get_case(case_id) is None:
            raise HTTPException(status_code=404, detail="Case not found")
        return container.reporting.generate_dossier(
            case_id=case_id,
            export_format=payload.format,
            actor_id=actor,
            actor_role=role,
        )

    # --- 10.6 Sources ---
    @app.get("/api/v1/sources", tags=["Sources"])
    async def list_sources(
        region: Annotated[str | None, Query()] = None,
        category: Annotated[str | None, Query()] = None,
        live_only: Annotated[bool, Query()] = False,
    ) -> list[dict[str, Any]]:
        sources = container.registry.list_sources(
            region=region, category=category, live_only=live_only
        )
        return [s.model_dump() for s in sources]

    @app.get("/api/v1/sources/{source_id}", tags=["Sources"])
    async def get_source(source_id: str) -> dict[str, Any]:
        meta = container.registry.get_source_metadata(source_id)
        if meta is None:
            raise HTTPException(status_code=404, detail="Source not found")
        return meta.model_dump()

    @app.patch("/api/v1/sources/{source_id}", tags=["Sources"])
    async def update_source(
        source_id: str,
        payload: UpdateSourceRequest,
        role: Annotated[Role, Depends(get_actor_role)],
    ) -> dict[str, Any]:
        from godseye.core.security import check_permission

        check_permission(role, "source:manage")
        meta = container.registry.set_source_enabled(source_id, payload.enabled)
        if meta is None:
            raise HTTPException(status_code=404, detail="Source not found")
        return meta.model_dump()

    # --- Webhooks (api-integration skill) ---
    @app.post("/api/v1/webhooks", status_code=status.HTTP_201_CREATED, tags=["Webhooks"])
    async def register_webhook(
        payload: CreateWebhookRequest,
        role: Annotated[Role, Depends(get_actor_role)],
    ) -> dict[str, Any]:
        from godseye.core.security import check_permission

        check_permission(role, "webhook:manage")
        wh = WebhookSubscription(
            subscriber_url=payload.subscriber_url,
            events=payload.events,
            secret=payload.secret,
        )
        container.repo.save_webhook(wh)
        return wh.model_dump()

    @app.get("/api/v1/webhooks", tags=["Webhooks"])
    async def list_webhooks() -> list[dict[str, Any]]:
        return [w.model_dump() for w in container.repo.list_webhooks()]

    @app.delete("/api/v1/webhooks/{webhook_id}", tags=["Webhooks"])
    async def delete_webhook(
        webhook_id: str,
        role: Annotated[Role, Depends(get_actor_role)],
    ) -> dict[str, Any]:
        from godseye.core.security import check_permission

        check_permission(role, "webhook:manage")
        deleted = container.repo.delete_webhook(webhook_id)
        if not deleted:
            raise HTTPException(status_code=404, detail="Webhook not found")
        return {"deleted": True, "webhook_id": webhook_id}

    # --- Audit Trail ---
    @app.get("/api/v1/audit", tags=["Compliance & Audit"])
    async def list_audit_events(
        role: Annotated[Role, Depends(get_actor_role)],
        case_id: Annotated[str | None, Query()] = None,
    ) -> list[dict[str, Any]]:
        return container.case_service.list_audit_log(case_id=case_id, actor_role=role)

    # --- Expansion Module 1: Watchlists & Continuous Alerts ---
    @app.post("/api/v1/watchlists", status_code=status.HTTP_201_CREATED, tags=["Watchlists & Alerts"])
    async def create_watchlist(
        payload: CreateWatchlistRequest,
        actor: Annotated[str, Depends(get_actor_id)],
        role: Annotated[Role, Depends(get_actor_role)],
    ) -> dict[str, Any]:
        wl = container.watchlist_service.create_watchlist(
            case_id=payload.case_id,
            value=payload.value,
            target_type=payload.target_type,
            frequency=payload.frequency,
            severity=payload.severity,
            owner=actor,
            actor_role=role,
        )
        return wl.model_dump()

    @app.get("/api/v1/watchlists", tags=["Watchlists & Alerts"])
    async def list_watchlists(
        role: Annotated[Role, Depends(get_actor_role)],
        case_id: Annotated[str | None, Query()] = None,
    ) -> list[dict[str, Any]]:
        return [
            w.model_dump()
            for w in container.watchlist_service.list_watchlists(case_id=case_id, actor_role=role)
        ]

    @app.get("/api/v1/alerts", tags=["Watchlists & Alerts"])
    async def list_alerts(
        role: Annotated[Role, Depends(get_actor_role)],
        watchlist_id: Annotated[str | None, Query()] = None,
        case_id: Annotated[str | None, Query()] = None,
        unacknowledged_only: Annotated[bool, Query()] = False,
    ) -> list[dict[str, Any]]:
        return [
            a.model_dump()
            for a in container.watchlist_service.list_alerts(
                watchlist_id=watchlist_id,
                case_id=case_id,
                unacknowledged_only=unacknowledged_only,
                actor_role=role,
            )
        ]

    @app.post("/api/v1/alerts/{alert_id}/acknowledge", tags=["Watchlists & Alerts"])
    async def acknowledge_alert(
        alert_id: str,
        actor: Annotated[str, Depends(get_actor_id)],
        role: Annotated[Role, Depends(get_actor_role)],
    ) -> dict[str, Any]:
        alert = container.watchlist_service.acknowledge_alert(
            alert_id=alert_id, actor_id=actor, actor_role=role
        )
        if alert is None:
            raise HTTPException(status_code=404, detail="Alert not found")
        return alert.model_dump()

    # --- Expansion Module 3: OSINT Brazuca Dynamic Catalog & Source Governance ---
    @app.post("/api/v1/catalog/import-brazuca", tags=["Sources"])
    async def import_brazuca_catalog(
        role: Annotated[Role, Depends(get_actor_role)],
    ) -> dict[str, Any]:
        from godseye.core.security import check_permission

        check_permission(role, "source:manage")
        candidates = container.registry.import_brazuca_catalog()
        return {
            "imported_count": len(candidates),
            "status": "candidate",
            "sources": [c.model_dump() for c in candidates],
        }

    @app.post("/api/v1/sources/{source_id}/approve", tags=["Sources"])
    async def approve_candidate_source(
        source_id: str,
        role: Annotated[Role, Depends(get_actor_role)],
    ) -> dict[str, Any]:
        from godseye.core.security import check_permission

        check_permission(role, "source:manage")
        meta = container.registry.approve_candidate_source(source_id)
        if meta is None:
            raise HTTPException(status_code=404, detail="Source not found")
        return meta.model_dump()

    # --- Expansion Module 6: Investigative Collaboration ---
    @app.post("/api/v1/cases/{case_id}/comments", status_code=status.HTTP_201_CREATED, tags=["Collaboration"])
    async def add_case_comment(
        case_id: str,
        payload: CreateCommentRequest,
        actor: Annotated[str, Depends(get_actor_id)],
        role: Annotated[Role, Depends(get_actor_role)],
    ) -> dict[str, Any]:
        if container.repo.get_case(case_id) is None:
            raise HTTPException(status_code=404, detail="Case not found")
        comment = container.collaboration_service.add_comment(
            case_id=case_id,
            body=payload.body,
            author_id=actor,
            entity_id=payload.entity_id,
            evidence_id=payload.evidence_id,
            actor_role=role,
        )
        return comment.model_dump()

    @app.get("/api/v1/cases/{case_id}/comments", tags=["Collaboration"])
    async def list_case_comments(
        case_id: str,
        role: Annotated[Role, Depends(get_actor_role)],
    ) -> list[dict[str, Any]]:
        return [
            c.model_dump()
            for c in container.collaboration_service.list_comments(case_id, actor_role=role)
        ]

    @app.post("/api/v1/cases/{case_id}/tasks", status_code=status.HTTP_201_CREATED, tags=["Collaboration"])
    async def create_case_task(
        case_id: str,
        payload: CreateTaskRequest,
        actor: Annotated[str, Depends(get_actor_id)],
        role: Annotated[Role, Depends(get_actor_role)],
    ) -> dict[str, Any]:
        if container.repo.get_case(case_id) is None:
            raise HTTPException(status_code=404, detail="Case not found")
        task = container.collaboration_service.create_task(
            case_id=case_id,
            title=payload.title,
            description=payload.description,
            assignee_id=payload.assignee_id,
            due_date=payload.due_date,
            created_by=actor,
            actor_role=role,
        )
        return task.model_dump()

    @app.get("/api/v1/cases/{case_id}/tasks", tags=["Collaboration"])
    async def list_case_tasks(
        case_id: str,
        role: Annotated[Role, Depends(get_actor_role)],
    ) -> list[dict[str, Any]]:
        return [
            t.model_dump()
            for t in container.collaboration_service.list_tasks(case_id, actor_role=role)
        ]

    @app.patch("/api/v1/cases/{case_id}/tasks/{task_id}", tags=["Collaboration"])
    async def update_task_status(
        case_id: str,
        task_id: str,
        payload: UpdateTaskStatusRequest,
        role: Annotated[Role, Depends(get_actor_role)],
    ) -> dict[str, Any]:
        task = container.collaboration_service.update_task_status(
            case_id=case_id,
            task_id=task_id,
            status=payload.status,
            actor_role=role,
        )
        if task is None:
            raise HTTPException(status_code=404, detail="Task not found")
        return task.model_dump()

    @app.post("/api/v1/cases/{case_id}/verifications", status_code=status.HTTP_201_CREATED, tags=["Collaboration"])
    async def record_verification(
        case_id: str,
        payload: CreateVerificationRequest,
        actor: Annotated[str, Depends(get_actor_id)],
        role: Annotated[Role, Depends(get_actor_role)],
    ) -> dict[str, Any]:
        if container.repo.get_case(case_id) is None:
            raise HTTPException(status_code=404, detail="Case not found")
        ver = container.collaboration_service.verify_finding(
            case_id=case_id,
            status=payload.status,
            reason=payload.reason,
            entity_id=payload.entity_id,
            relationship_id=payload.relationship_id,
            evidence_id=payload.evidence_id,
            reviewer_id=actor,
            actor_role=role,
        )
        return ver.model_dump()

    @app.get("/api/v1/cases/{case_id}/verifications", tags=["Collaboration"])
    async def list_verifications(
        case_id: str,
        role: Annotated[Role, Depends(get_actor_role)],
    ) -> list[dict[str, Any]]:
        return [
            v.model_dump()
            for v in container.collaboration_service.list_verifications(case_id, actor_role=role)
        ]

    @app.post("/api/v1/cases/{case_id}/versions", status_code=status.HTTP_201_CREATED, tags=["Collaboration"])
    async def create_case_version(
        case_id: str,
        payload: CreateCaseVersionRequest,
        actor: Annotated[str, Depends(get_actor_id)],
        role: Annotated[Role, Depends(get_actor_role)],
    ) -> dict[str, Any]:
        if container.repo.get_case(case_id) is None:
            raise HTTPException(status_code=404, detail="Case not found")
        dossier = container.reporting.generate_dossier(
            case_id=case_id, export_format="json", actor_id=actor, actor_role=role
        )
        ver = container.collaboration_service.create_case_version(
            case_id=case_id,
            change_summary=payload.change_summary,
            dossier_payload=dossier,
            created_by=actor,
            actor_role=role,
        )
        return ver.model_dump()

    @app.get("/api/v1/cases/{case_id}/versions", tags=["Collaboration"])
    async def list_case_versions(
        case_id: str,
        role: Annotated[Role, Depends(get_actor_role)],
    ) -> list[dict[str, Any]]:
        return [
            v.model_dump()
            for v in container.collaboration_service.list_case_versions(case_id, actor_role=role)
        ]

    # --- Expansion Module 7: Data Quality & Governance ---
    @app.get("/api/v1/cases/{case_id}/quality", tags=["Data Governance"])
    async def get_case_quality(
        case_id: str,
        role: Annotated[Role, Depends(get_actor_role)],
    ) -> dict[str, Any]:
        from godseye.core.security import check_permission

        check_permission(role, "case:read")
        if container.repo.get_case(case_id) is None:
            raise HTTPException(status_code=404, detail="Case not found")
        return container.governance_service.evaluate_case_governance(case_id)

    # --- Expansion Module 8: Auditable Assistive AI ---
    @app.post("/api/v1/cases/{case_id}/ai-assist", status_code=status.HTTP_201_CREATED, tags=["Assistive AI"])
    async def generate_ai_assistance(
        case_id: str,
        payload: CreateAIAssistRequest,
        actor: Annotated[str, Depends(get_actor_id)],
        role: Annotated[Role, Depends(get_actor_role)],
    ) -> dict[str, Any]:
        if container.repo.get_case(case_id) is None:
            raise HTTPException(status_code=404, detail="Case not found")
        inf = container.ai_service.generate_case_analysis(
            case_id=case_id,
            task_type=payload.task_type,
            actor_id=actor,
            actor_role=role,
        )
        return inf.model_dump()

    @app.get("/api/v1/cases/{case_id}/ai-assist", tags=["Assistive AI"])
    async def list_ai_inferences(
        case_id: str,
        role: Annotated[Role, Depends(get_actor_role)],
    ) -> list[dict[str, Any]]:
        return [
            i.model_dump()
            for i in container.ai_service.list_inferences(case_id=case_id, actor_role=role)
        ]

    @app.post("/api/v1/ai-assist/{inference_id}/review", tags=["Assistive AI"])
    async def review_ai_inference(
        inference_id: str,
        payload: ReviewAIAssistRequest,
        actor: Annotated[str, Depends(get_actor_id)],
        role: Annotated[Role, Depends(get_actor_role)],
    ) -> dict[str, Any]:
        inf = container.ai_service.review_inference(
            inference_id=inference_id,
            decision=payload.decision,
            reviewer_id=actor,
            actor_role=role,
        )
        if inf is None:
            raise HTTPException(status_code=404, detail="AI inference not found")
        return inf.model_dump()

    return app
