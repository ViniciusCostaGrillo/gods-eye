"""FastAPI v1 REST API implementation (Section 10 & fastapi-pro skill)."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from godseye.collectors.registry import CollectorRegistry
from godseye.core.cache import MultiTierCache
from godseye.core.config import get_settings
from godseye.core.resilience import ResilientHttpClient
from godseye.core.security import PermissionDeniedError
from godseye.db.repository import OsintRepository
from godseye.domain.enums import CaseStatus, LegalBasis, Role, TargetType
from godseye.domain.events import EventBus
from godseye.domain.models import WebhookSubscription
from godseye.services.case_service import CaseService
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


class AppContainer:
    """Dependency container holding database, cache, HTTP client, and services."""

    def __init__(self, db_path: str | None = None) -> None:
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
        self.event_bus = EventBus()
        self.case_service = CaseService(self.repo)
        self.orchestrator = InvestigationOrchestrator(
            repo=self.repo,
            registry=self.registry,
            cache=self.cache,
            event_bus=self.event_bus,
            max_concurrency=settings.max_concurrency,
        )
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

    return app
