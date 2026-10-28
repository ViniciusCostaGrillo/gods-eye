"""Tests for Anti-Homonym Filters (--uf and --city)."""

import pytest
from godseye.api.app import AppContainer
from godseye.domain.enums import Role, TargetType


@pytest.mark.asyncio
async def test_person_search_with_uf_filter(container: AppContainer):
    case = container.case_service.create_case(
        title="Anti-Homonym Filter Test", actor_role=Role.INVESTIGATOR
    )
    # Add target with geographical metadata
    target = container.case_service.add_target(
        case.id,
        "Carlos Silva",
        TargetType.PERSON,
        actor_role=Role.INVESTIGATOR,
    )
    target.metadata["filter_uf"] = "SP"
    target.metadata["filter_city"] = "Campinas"
    container.repo.save_target(target)

    retrieved = container.repo.get_target(target.id)
    assert retrieved is not None
    assert retrieved.metadata.get("filter_uf") == "SP"
    assert retrieved.metadata.get("filter_city") == "Campinas"
