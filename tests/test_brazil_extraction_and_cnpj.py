"""Tests for Brazilian entity extraction & enriched CNPJ multi-provider collector."""

import pytest
from godseye.api.app import AppContainer
from godseye.collectors.brazil_sources import (
    BrasilApiCnpjCollector,
    decode_duckduckgo_url,
    extract_brazil_entities_from_text,
    is_valid_cnpj,
)
from godseye.domain.enums import EntityType, TargetType
from godseye.domain.models import Target


def test_is_valid_cnpj():
    assert is_valid_cnpj("00.000.000/0001-91") is True  # Banco do Brasil
    assert is_valid_cnpj("11.111.111/1111-11") is False
    assert is_valid_cnpj("00000000000191") is True
    assert is_valid_cnpj("12.345.678/0001-90") is False


def test_decode_duckduckgo_url():
    ddg = "//duckduckgo.com/l/?uddg=https%3A%2F%2Fqueridodiario.ok.org.br%2Fgazettes%2F123&rut=1"
    assert decode_duckduckgo_url(ddg) == "https://queridodiario.ok.org.br/gazettes/123"
    assert decode_duckduckgo_url("https://example.com") == "https://example.com"
    assert decode_duckduckgo_url("/l/?uddg=https%3A%2F%2Freceita.gov.br") == "https://receita.gov.br"


def test_extract_brazil_entities_from_text():
    sample = (
        "O sócio João da Silva, portador do CPF 123.456.789-00, da empresa "
        "ABC LTDA CNPJ 00.000.000/0001-91, responde ao processo 0001234-56.2024.8.26.0100 "
        "no TJSP. Contato: (11) 98765-4321, CEP 01001-000."
    )
    res = extract_brazil_entities_from_text(sample)
    assert "00.000.000/0001-91" in res["cnpjs"]
    assert "0001234-56.2024.8.26.0100" in res["processes"]
    assert "01001-000" in res["ceps"]
    assert any("98765-4321" in p or "11987654321" in p for p in res["phones"])


@pytest.mark.asyncio
async def test_enriched_cnpj_collector_yields_full_address_and_contacts(container: AppContainer):
    adapter = container.registry.get_adapter("brasil_cnpj")
    assert isinstance(adapter, BrasilApiCnpjCollector)
    target = Target(
        case_id="test-case-1",
        value="00.000.000/0001-91",
        normalized_value="00.000.000/0001-91",
        type=TargetType.CNPJ,
    )
    obs_list = [obs async for obs in adapter.collect(target)]
    types = {obs.entity_type for obs in obs_list}
    assert EntityType.ORGANIZATION in types
    assert EntityType.LOCATION in types

    org_obs = next(obs for obs in obs_list if obs.entity_type == EntityType.ORGANIZATION)
    assert "logradouro" in org_obs.raw_payload or "endereco_completo" in org_obs.raw_payload
    assert "qsa" in org_obs.raw_payload
