"""Tests for CNJ number decoding and DataJud judicial case collector."""

import pytest
from godseye.api.app import AppContainer
from godseye.collectors.brazil_sources import DataJudCnjCollector, parse_cnj_process_number
from godseye.domain.enums import EntityType, TargetType
from godseye.domain.models import Target


def test_parse_cnj_process_number():
    info = parse_cnj_process_number("0001234-56.2024.8.26.0100")
    assert info["is_valid"] is True
    assert info["ano"] == "2024"
    assert info["ramo"] == "Justiça Estadual"
    assert info["tribunal"] == "TJSP"
    assert info["uf"] == "SP"

    trf_info = parse_cnj_process_number("5000001-12.2023.4.03.6100")
    assert trf_info["is_valid"] is True
    assert trf_info["ramo"] == "Justiça Federal"
    assert trf_info["tribunal"] == "TRF3"


@pytest.mark.asyncio
async def test_datajud_collector_accepts_person_and_cnpj(container: AppContainer):
    adapter = container.registry.get_adapter("datajud_cnj")
    assert isinstance(adapter, DataJudCnjCollector)
    assert TargetType.PERSON in adapter.accepts
    assert TargetType.CNPJ in adapter.accepts
    assert TargetType.PROCESSO in adapter.accepts


@pytest.mark.asyncio
async def test_datajud_collector_decodes_process_target(container: AppContainer):
    adapter = container.registry.get_adapter("datajud_cnj")
    target = Target(
        case_id="case-proc-test",
        value="0001234-56.2024.8.26.0100",
        normalized_value="0001234-56.2024.8.26.0100",
        type=TargetType.PROCESSO,
    )
    obs_list = [obs async for obs in adapter.collect(target)]
    assert len(obs_list) >= 1
    proc_obs = obs_list[0]
    assert proc_obs.entity_type == EntityType.LEGAL_CASE
    assert "TJSP" in proc_obs.entity_value or "TJSP" in str(proc_obs.raw_payload)
