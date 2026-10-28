"""Tests for enhanced public entity discovery on CPF, Person Names, and Phones."""

import pytest
from godseye.api.app import AppContainer
from godseye.domain.enums import EntityType, TargetType
from godseye.domain.models import Target


@pytest.mark.asyncio
async def test_cpf_discovery_observations(container: AppContainer):
    cpf_adapter = container.registry.get_adapter("brasil_cpf")
    assert cpf_adapter is not None
    target = Target(
        case_id="case-cpf-test",
        value="529.982.247-25",
        normalized_value="529.982.247-25",
        type=TargetType.PERSON,
    )
    obs_list = [obs async for obs in cpf_adapter.collect(target)]
    types = {obs.entity_type for obs in obs_list}
    assert EntityType.PERSON in types


@pytest.mark.asyncio
async def test_person_name_discovery_observations(container: AppContainer):
    adapter = container.registry.get_adapter("person_and_leak_osint")
    assert adapter is not None
    target = Target(
        case_id="case-person-test",
        value="Silvio Santos",
        normalized_value="Silvio Santos",
        type=TargetType.PERSON,
    )
    obs_list = [obs async for obs in adapter.collect(target)]
    assert len(obs_list) >= 1
    # Check that public mentions, documents or accounts are yielded
    payloads = [obs.raw_payload for obs in obs_list]
    assert any("title" in p or "platform" in p or "discovered_cnpjs" in p for p in payloads)


@pytest.mark.asyncio
async def test_phone_osint_discovers_commercial_mentions(container: AppContainer):
    adapter = container.registry.get_adapter("phone_osint")
    assert adapter is not None
    target = Target(
        case_id="case-phone-test",
        value="+551134939000",
        normalized_value="+551134939000",
        type=TargetType.PHONE,
    )
    obs_list = [obs async for obs in adapter.collect(target)]
    types = {obs.entity_type for obs in obs_list}
    assert EntityType.PHONE in types
    assert EntityType.LOCATION in types
