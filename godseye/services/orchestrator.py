"""Investigation Orchestrator with Cascading Discovery, Idempotency & Multi-Tier Caching."""

import asyncio
import contextlib
import re
import time
from datetime import UTC, datetime, timedelta
from typing import Any

from godseye.collectors.base import BaseCollector
from godseye.collectors.registry import CollectorRegistry
from godseye.core.cache import MultiTierCache
from godseye.core.config import get_settings
from godseye.core.security import (
    check_permission,
    compute_idempotency_key,
     sign_webhook_payload,
)
from godseye.db.repository import OsintRepository
from godseye.domain.enums import (
    EntityType,
    EventType,
    JobStatus,
    RelationType,
    Role,
    TargetType,
)
from godseye.domain.events import EventBus
from godseye.domain.models import (
    AuditEvent,
    CollectionJob,
    EntityRelationship,
    RawEvidence,
    RawObservation,
    Target,
    utc_now_iso,
)
from godseye.services.case_service import CaseService
from godseye.services.correlation import CorrelationEngine
from godseye.services.entity_resolution import EntityResolutionService
from godseye.services.expansion import DataGovernanceService, WatchlistService
from godseye.services.normalizer import NormalizationService


class InvestigationOrchestrator:
    """Executes OSINT collection jobs, cascading discovery, normalization, resolution, and correlation."""

    def __init__(
        self,
        repo: OsintRepository,
        registry: CollectorRegistry,
        cache: MultiTierCache,
        event_bus: EventBus | None = None,
        max_concurrency: int = 8,
    ) -> None:
        self.repo = repo
        self.registry = registry
        self.cache = cache
        self.event_bus = event_bus or EventBus()
        self.case_service = CaseService(repo)
        self.normalizer = NormalizationService(repo)
        self.resolver = EntityResolutionService(repo)
        self.correlator = CorrelationEngine(repo)
        self.watchlist_service = WatchlistService(repo, self.event_bus)
        self.governance_service = DataGovernanceService(repo, registry)
        self._semaphore = asyncio.Semaphore(max(1, max_concurrency))

    async def investigate_target(
        self,
        case_id: str,
        target: Target,
        max_depth: int = 2,
        selected_sources: list[str] | None = None,
        actor_id: str = "sec-analyst",
        actor_role: Role = Role.INVESTIGATOR,
    ) -> dict[str, Any]:
        """Run full OSINT investigation pipeline on a Target with cascading multi-hop discovery."""
        check_permission(actor_role, "collection:run")
        case = self.repo.get_case(case_id)
        if case is None:
            raise ValueError(f"Case '{case_id}' not found")

        await self.event_bus.publish(
            EventType.TARGET_CREATED,
            {"case_id": case_id, "target_id": target.id, "value": target.normalized_value},
        )

        jobs_executed: list[CollectionJob] = []
        visited_targets: set[tuple[TargetType, str]] = set()
        queue: list[tuple[Target, int]] = [(target, 1)]

        while queue:
            current_batch = list(queue)
            queue.clear()

            for curr_target, depth in current_batch:
                key_pair = (curr_target.type, curr_target.normalized_value)
                if key_pair in visited_targets:
                    continue
                visited_targets.add(key_pair)

                adapters = self._select_adapters(curr_target.type, selected_sources if depth == 1 else None)
                batch_results = await asyncio.gather(
                    *(
                        self._execute_single_adapter(case_id, curr_target, adapter)
                        for adapter in adapters
                    ),
                    return_exceptions=True,
                )

                discovered_observations: list[RawObservation] = []
                for res in batch_results:
                    if isinstance(res, tuple):
                        job, obs_list = res
                        jobs_executed.append(job)
                        discovered_observations.extend(obs_list)

                # Cascading discovery (Section 3 & Section 8)
                if depth < max_depth:
                    next_targets = self._derive_cascading_targets(
                        case_id, curr_target, discovered_observations, actor_id, actor_role
                    )
                    for nt in next_targets:
                        if (nt.type, nt.normalized_value) not in visited_targets:
                            queue.append((nt, depth + 1))

        findings = self.correlator.evaluate_case(case_id)
        governance = self.governance_service.evaluate_case_governance(case_id)
        await self.event_bus.publish(
            EventType.CORRELATION_MATCHED,
            {
                "case_id": case_id,
                "target": target.normalized_value,
                "findings_count": len(findings),
                "conflicts_count": len(governance["conflicts"]),
            },
        )

        self.repo.record_audit(
            AuditEvent(
                actor_id=actor_id,
                actor_role=actor_role.value,
                case_id=case_id,
                action="collection.completed",
                object_id=target.id,
                metadata={
                    "target": target.normalized_value,
                    "jobs_count": len(jobs_executed),
                    "findings_count": len(findings),
                },
            )
        )
        await self._dispatch_webhooks(
            EventType.COLLECTION_COMPLETED.value,
            {"case_id": case_id, "target": target.normalized_value, "jobs": len(jobs_executed)},
        )

        return {
            "case_id": case_id,
            "root_target": target.model_dump(),
            "jobs": [j.model_dump() for j in jobs_executed],
            "entities_count": len(self.repo.list_entities(case_id)),
            "relationships_count": len(self.repo.list_relationships(case_id)),
            "findings": [f.model_dump() for f in findings],
            "quality_scores_count": len(governance["scores"]),
            "conflicts_count": len(governance["conflicts"]),
        }

    def _select_adapters(
        self,
        target_type: TargetType,
        selected_sources: list[str] | None = None,
    ) -> list[BaseCollector]:
        adapters = self.registry.get_adapters_for_target(target_type)
        if selected_sources:
            allowed = {s.strip().lower() for s in selected_sources}
            adapters = [a for a in adapters if a.id.lower() in allowed]
        return adapters

    async def _execute_single_adapter(
        self,
        case_id: str,
        target: Target,
        adapter: BaseCollector,
    ) -> tuple[CollectionJob, list[RawObservation]]:
        """Execute one collector adapter with idempotency, caching, evidence storage & resolution."""
        idem_key = compute_idempotency_key(
            case_id=case_id,
            target_value=target.normalized_value,
            source_id=adapter.id,
            adapter_version=adapter.adapter_version,
        )
        job = CollectionJob(
            case_id=case_id,
            target_id=target.id,
            source_id=adapter.id,
            status=JobStatus.RUNNING,
            idempotency_key=idem_key,
            started_at=utc_now_iso(),
        )
        self.repo.save_job(job)
        await self.event_bus.publish(
            EventType.COLLECTION_REQUESTED,
            {"job_id": job.id, "source_id": adapter.id, "target": target.normalized_value},
        )

        started = time.monotonic()
        observations: list[RawObservation] = []
        cache_key = f"obs:{adapter.id}:{adapter.adapter_version}:{target.type.value}:{target.normalized_value}"

        async with self._semaphore:
            try:
                cached_obs_dicts = self.cache.get(cache_key)
                if cached_obs_dicts is not None:
                    observations = [RawObservation(**item) for item in cached_obs_dicts]
                    job.status = JobStatus.CACHED
                    self.registry.http_client.telemetry.record_call(
                        adapter.id,
                        latency_ms=(time.monotonic() - started) * 1000.0,
                        success=True,
                        cached=True,
                    )
                else:
                    async for obs in adapter.collect(target):
                        observations.append(obs)
                    self.cache.set(
                        cache_key,
                        [o.model_dump() for o in observations],
                    )
                    job.status = JobStatus.COMPLETED

                retention_days = get_settings().retention_days
                expires_at = (datetime.now(UTC) + timedelta(days=retention_days)).isoformat()

                for raw_obs in observations:
                    evidence = RawEvidence(
                        case_id=case_id,
                        job_id=job.id,
                        source_id=raw_obs.source_id,
                        source_name=raw_obs.source_name,
                        url=raw_obs.source_url,
                        retrieved_at=raw_obs.retrieved_at,
                        adapter_version=raw_obs.adapter_version,
                        content_hash=raw_obs.content_hash,
                        raw_payload=raw_obs.raw_payload,
                        legal_basis=raw_obs.legal_basis,
                        retention_expires_at=expires_at,
                    )
                    self.repo.save_evidence(evidence)
                    norm_obs = self.normalizer.normalize_and_store(case_id, evidence, raw_obs)
                    self.resolver.resolve(norm_obs)
                    await self._publish_observation_watchlist_events(case_id, target, raw_obs)

            except Exception as exc:
                job.status = JobStatus.FAILED
                job.error = str(exc)
                await self.event_bus.publish(
                    EventType.COLLECTION_FAILED,
                    {"job_id": job.id, "source_id": adapter.id, "error": str(exc)},
                )

        job.finished_at = utc_now_iso()
        job.duration_ms = round((time.monotonic() - started) * 1000.0, 2)
        self.repo.save_job(job)
        return job, observations

    def _derive_cascading_targets(
        self,
        case_id: str,
        parent_target: Target,
        observations: list[RawObservation],
        actor_id: str,
        actor_role: Role,
    ) -> list[Target]:
        """Derive second-hop targets for cascading discovery (Section 8 & Brazil Section 13)."""
        cascaded: list[Target] = []

        # 1. Email -> Domain + Username prefix (Section 8)
        if parent_target.type == TargetType.EMAIL and "@" in parent_target.normalized_value:
            local_part, domain_part = parent_target.normalized_value.split("@", 1)
            domain_target = self.case_service.add_target(
                case_id, domain_part, TargetType.DOMAIN, actor_id=actor_id, actor_role=actor_role
            )
            cascaded.append(domain_target)

            # Link Email -> Domain in graph
            email_ent = self.repo.find_entity(case_id, EntityType.EMAIL, parent_target.normalized_value)
            dom_ent = self.repo.find_entity(case_id, EntityType.DOMAIN, domain_part)
            if email_ent and dom_ent:
                self.repo.save_relationship(
                    EntityRelationship(
                        case_id=case_id,
                        from_entity_id=email_ent.id,
                        to_entity_id=dom_ent.id,
                        from_label=f"Email:{email_ent.canonical_value}",
                        to_label=f"Domain:{dom_ent.canonical_value}",
                        relation=RelationType.ASSOCIATED_WITH,
                        confidence=1.0,
                        evidence_id="cascaded-email-domain",
                        source_id="orchestrator",
                    )
                )

            if len(local_part) >= 3:
                user_target = self.case_service.add_target(
                    case_id, local_part, TargetType.USERNAME, actor_id=actor_id, actor_role=actor_role
                )
                cascaded.append(user_target)

        # 2. Domain -> Resolved IP Addresses (DNS / urlscan -> Shodan InternetDB / GeoIP / RIPEstat)
        for obs in observations:
            if obs.entity_type == EntityType.IP_ADDRESS:
                ip_target = self.case_service.add_target(
                    case_id, obs.entity_value, TargetType.IP, actor_id=actor_id, actor_role=actor_role
                )
                cascaded.append(ip_target)
                if len(cascaded) >= 4:
                    break

            # 3. Brazilian CNPJ -> CEP Geolocation
            if parent_target.type == TargetType.CNPJ and obs.entity_type == EntityType.ORGANIZATION:
                cep_raw = str(obs.raw_payload.get("cep") or "")
                cep_digits = re.sub(r"\D", "", cep_raw)
                if len(cep_digits) == 8:
                    cep_target = self.case_service.add_target(
                        case_id, cep_digits, TargetType.CEP, actor_id=actor_id, actor_role=actor_role
                    )
                    cascaded.append(cep_target)

            # 4. Person Name -> Discovered GitHub / Social Username handles (up to top 2)
            if parent_target.type == TargetType.PERSON and obs.entity_type == EntityType.ACCOUNT:
                gh_login = str(obs.raw_payload.get("login") or "").strip()
                if gh_login and len(cascaded) < 2:
                    user_target = self.case_service.add_target(
                        case_id, gh_login, TargetType.USERNAME, actor_id=actor_id, actor_role=actor_role
                    )
                    cascaded.append(user_target)

            # 4b. CPF (Person) or Phone -> Discovered Person Full Name from Diários Oficiais / Portal da Transparência
            if parent_target.type in (TargetType.PERSON, TargetType.PHONE) and obs.entity_type == EntityType.PERSON:
                disc_name = str(obs.raw_payload.get("discovered_person_name") or "").strip()
                if disc_name and len(cascaded) < 2:
                    name_target = self.case_service.add_target(
                        case_id, disc_name, TargetType.PERSON, actor_id=actor_id, actor_role=actor_role
                    )
                    cascaded.append(name_target)

            # 4c. Person / CPF / Phone -> Discovered CNPJs (automatic pivot to corporate enrichment)
            disc_cnpj = str(obs.raw_payload.get("discovered_cnpj") or "").strip()
            if disc_cnpj and len(cascaded) < 4:
                cnpj_digits = re.sub(r"\D", "", disc_cnpj)
                if len(cnpj_digits) == 14:
                    cnpj_target = self.case_service.add_target(
                        case_id, disc_cnpj, TargetType.CNPJ, actor_id=actor_id, actor_role=actor_role
                    )
                    cascaded.append(cnpj_target)

            # 4d. Person / CPF -> Discovered Lawsuits (automatic pivot to CNJ decoding)
            disc_proc = str(obs.raw_payload.get("discovered_process") or "").strip()
            if disc_proc and len(cascaded) < 5:
                if re.match(r"^\d{7}-\d{2}\.\d{4}\.\d\.\d{2}\.\d{4}$", disc_proc):
                    proc_target = self.case_service.add_target(
                        case_id, disc_proc, TargetType.PROCESSO, actor_id=actor_id, actor_role=actor_role
                    )
                    cascaded.append(proc_target)

            # 5. Username -> Public Commit Email -> Breach / Leak Check
            if parent_target.type == TargetType.USERNAME and obs.entity_type == EntityType.EMAIL:
                pub_email = str(obs.entity_value or "").strip().lower()
                if "@" in pub_email and len(cascaded) < 3:
                    email_target = self.case_service.add_target(
                        case_id, pub_email, TargetType.EMAIL, actor_id=actor_id, actor_role=actor_role
                    )
                    cascaded.append(email_target)

        return cascaded

    async def _publish_observation_watchlist_events(
        self,
        case_id: str,
        target: Target,
        raw_obs: RawObservation,
    ) -> None:
        """Emit granular domain events for Watchlist continuous monitoring (Expansion Module 1)."""
        payload = {
            "case_id": case_id,
            "target": target.normalized_value,
            "value": raw_obs.entity_value,
            "source_id": raw_obs.source_id,
            "entity_type": raw_obs.entity_type.value,
        }
        await self.event_bus.publish(EventType.ENTITY_CREATED, payload)
        if raw_obs.entity_type == EntityType.BREACH:
            await self.event_bus.publish(EventType.BREACH_DETECTED, payload)
        elif raw_obs.entity_type == EntityType.SANCTION:
            await self.event_bus.publish(EventType.SANCTION_DETECTED, payload)
            if target.type == TargetType.CRYPTO_ADDRESS:
                await self.event_bus.publish(EventType.CRYPTO_ADDRESS_FLAGGED, payload)
        elif raw_obs.entity_type == EntityType.SUBDOMAIN:
            await self.event_bus.publish(EventType.DOMAIN_SUBDOMAIN_DISCOVERED, payload)
        elif raw_obs.entity_type == EntityType.CERTIFICATE:
            await self.event_bus.publish(EventType.DOMAIN_CERTIFICATE_ISSUED, payload)
        elif raw_obs.entity_type == EntityType.EXPOSED_SERVICE:
            await self.event_bus.publish(EventType.ENTITY_UPDATED, payload)
        elif raw_obs.entity_type == EntityType.DOCUMENT and raw_obs.source_id == "queridodiario":
            await self.event_bus.publish(EventType.OFFICIAL_GAZETTE_MENTION_DETECTED, payload)
        elif raw_obs.entity_type in (EntityType.DOCUMENT, EntityType.LEGAL_CASE) and raw_obs.source_id == "datajud":
            await self.event_bus.publish(EventType.LEGAL_CASE_CREATED, payload)
        elif raw_obs.entity_type == EntityType.PERSON and raw_obs.source_id == "brasilapi_cnpj":
            await self.event_bus.publish(EventType.RELATIONSHIP_CREATED, payload)

    async def _dispatch_webhooks(self, event_name: str, data: dict[str, Any]) -> None:
        """Deliver signed outbound webhooks to registered subscribers (api-integration skill)."""
        import json

        webhooks = self.repo.list_webhooks()
        if not webhooks:
            return

        envelope = {
            "event": event_name,
            "delivery_id": f"wh-{int(time.time() * 1000)}",
            "created_at": utc_now_iso(),
            "data": data,
        }
        payload_bytes = json.dumps(envelope).encode("utf-8")

        for wh in webhooks:
            if not wh.active or (wh.events and event_name not in wh.events and "*" not in wh.events):
                continue
            secret = wh.secret or get_settings().webhook_signing_secret
            sig = sign_webhook_payload(secret, payload_bytes)
            headers = {
                "Content-Type": "application/json",
                "X-Webhook-Signature": sig,
                "X-Webhook-Event": event_name,
                "X-Webhook-Delivery": str(envelope["delivery_id"]),
                "X-Webhook-Timestamp": str(int(time.time())),
            }
            with contextlib.suppress(Exception):
                await self.registry.http_client.fetch_with_retry(
                    source_id=f"webhook:{wh.id}",
                    url=wh.subscriber_url,
                    method="POST",
                    headers=headers,
                    json_body=envelope,
                    max_retries=1,
                    retry_non_idempotent=True,
                )
