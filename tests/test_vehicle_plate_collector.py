"""Tests for Vehicle Plate detection, normalization & BrasilVehiclePlateCollector."""

import pytest
from godseye.api.app import AppContainer
from godseye.collectors.brazil_sources import (
    BrasilVehiclePlateCollector,
    extract_brazil_entities_from_text,
    is_valid_vehicle_plate,
)
from godseye.domain.enums import EntityType, TargetType
from godseye.domain.models import Target


def test_is_valid_vehicle_plate():
    # Mercosul
    assert is_valid_vehicle_plate("BRA2E19") is True
    assert is_valid_vehicle_plate("bra2e19") is True
    # Antiga cinza
    assert is_valid_vehicle_plate("ABC-1234") is True
    assert is_valid_vehicle_plate("ABC1234") is True
    # Inválidas
    assert is_valid_vehicle_plate("AAAA123") is False
    assert is_valid_vehicle_plate("1234ABC") is False


def test_extract_vehicle_plates_from_text():
    sample = "Veículo autuado no leilão: placa BRA2E19 e modelo antigo ABC-1234 apreendido."
    ents = extract_brazil_entities_from_text(sample)
    assert "BRA2E19" in ents["plates"]
    assert "ABC-1234" in ents["plates"]


@pytest.mark.asyncio
async def test_vehicle_plate_collector_yields_observations(container: AppContainer):
    adapter = container.registry.get_adapter("brasil_placa")
    assert isinstance(adapter, BrasilVehiclePlateCollector)
    target = Target(
        case_id="case-plate-test",
        value="BRA2E19",
        normalized_value="BRA2E19",
        type=TargetType.VEHICLE_PLATE,
    )
    obs_list = [obs async for obs in adapter.collect(target)]
    assert len(obs_list) >= 1
    types = {obs.entity_type for obs in obs_list}
    assert EntityType.DOCUMENT in types or EntityType.LOCATION in types
