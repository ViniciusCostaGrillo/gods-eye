"""Tests for cascading multi-hop discovery on Brazilian entities."""

import pytest
from godseye.api.app import AppContainer
from godseye.domain.enums import EntityType, Role, TargetType


@pytest.mark.asyncio
async def test_cascading_person_and_cnpj_pipeline(container: AppContainer):
    case = container.case_service.create_case(title="Test Cascading Person to CNPJ")
    target = container.case_service.add_target(
        case.id, "00.000.000/0001-91", TargetType.CNPJ, actor_role=Role.INVESTIGATOR
    )
    summary = await container.orchestrator.investigate_target(
        case_id=case.id,
        target=target,
        max_depth=2,
        actor_role=Role.INVESTIGATOR,
    )
    targets = container.repo.list_targets(case.id)
    target_values = {t.normalized_value for t in targets}
    assert "00000000000191" in target_values or "00.000.000/0001-91" in target_values
    assert "70040912" in target_values or any(t.type == TargetType.CEP for t in targets)

    entities = container.repo.list_entities(case.id)
    types = {e.type for e in entities}
    assert EntityType.ORGANIZATION in types
    assert EntityType.LOCATION in types


@pytest.mark.asyncio
async def test_cascading_derives_targets_from_discovered_leads(container: AppContainer):
    case = container.case_service.create_case(title="Test Lead Derivation")
    target = container.case_service.add_target(
        case.id, "+551134939000", TargetType.PHONE, actor_role=Role.INVESTIGATOR
    )
    summary = await container.orchestrator.investigate_target(
        case_id=case.id,
        target=target,
        max_depth=1,
        actor_role=Role.INVESTIGATOR,
    )
    assert summary["entities_count"] >= 1
