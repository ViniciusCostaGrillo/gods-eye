"""Tests for Cascading OSINT Pipeline, Entity Resolution, Correlation & Reporting."""

import pytest

from godseye.api.app import AppContainer
from godseye.domain.enums import Role, TargetType
from godseye.services.case_service import detect_target_type


def test_target_type_auto_detection() -> None:
    assert detect_target_type("analyst@empresa.com.br") == TargetType.EMAIL
    assert detect_target_type("example.com") == TargetType.DOMAIN
    assert detect_target_type("93.184.216.34") == TargetType.IP
    assert detect_target_type("00.000.000/0001-91") == TargetType.CNPJ
    assert detect_target_type("01001-000") == TargetType.CEP
    assert detect_target_type("0001234-56.2024.8.26.0100") == TargetType.PROCESSO
    assert detect_target_type("BRA2E19") == TargetType.VEHICLE_PLATE
    assert detect_target_type("torvalds") == TargetType.USERNAME


@pytest.mark.asyncio
async def test_cascading_email_and_brazil_cnpj_pipeline(container: AppContainer) -> None:
    try:
        # 1. Create Case & Investigate Email (cascades to Domain -> IP & Username)
        case = container.case_service.create_case(
            title="Test Email & Infrastructure Investigation",
            actor_role=Role.INVESTIGATOR,
        )
        email_target = container.case_service.add_target(
            case.id, "sec-ops@example.com", actor_role=Role.INVESTIGATOR
        )
        res = await container.orchestrator.investigate_target(
            case_id=case.id,
            target=email_target,
            max_depth=2,
            actor_role=Role.INVESTIGATOR,
        )
        assert res["entities_count"] >= 3
        assert res["relationships_count"] >= 2

        # 2. Investigate Brazilian CNPJ (cascades to QSA, CEP, Diário Oficial, Compliance)
        cnpj_target = container.case_service.add_target(
            case.id, "00.000.000/0001-91", actor_role=Role.INVESTIGATOR
        )
        res_br = await container.orchestrator.investigate_target(
            case_id=case.id,
            target=cnpj_target,
            max_depth=2,
            actor_role=Role.INVESTIGATOR,
        )
        assert res_br["entities_count"] >= 5

        # 3. Verify Graph, Timeline & Dossier exports
        graph = container.reporting.get_graph(case.id)
        assert "flowchart LR" in graph["mermaid"]
        assert graph["edges_count"] >= 3

        timeline = container.reporting.get_timeline(case.id)
        assert len(timeline) >= 4

        md_dossier = container.reporting.generate_dossier(case.id, export_format="md")
        assert "God's Eye OSINT Investigative Dossier" in md_dossier["formatted_output"]

        csv_dossier = container.reporting.generate_dossier(case.id, export_format="csv")
        assert "canonical_value" in csv_dossier["formatted_output"]
    finally:
        await container.shutdown()
