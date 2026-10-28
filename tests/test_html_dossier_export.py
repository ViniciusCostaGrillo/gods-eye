"""Tests for Standalone Interactive HTML Dossier Export."""

import pytest
from godseye.api.app import AppContainer
from godseye.domain.enums import Role, TargetType


@pytest.mark.asyncio
async def test_generate_html_dossier(container: AppContainer):
    case = container.case_service.create_case(
        title="HTML Dossier Export Test", actor_role=Role.INVESTIGATOR
    )
    target = container.case_service.add_target(
        case.id, "00.000.000/0001-91", TargetType.CNPJ, actor_role=Role.INVESTIGATOR
    )
    await container.orchestrator.investigate_target(
        case_id=case.id,
        target=target,
        max_depth=1,
        actor_role=Role.INVESTIGATOR,
    )
    dossier = container.reporting.generate_dossier(
        case_id=case.id,
        export_format="html",
        actor_role=Role.INVESTIGATOR,
    )
    html_content = dossier["formatted_output"]
    assert "<!DOCTYPE html>" in html_content
    assert "God's Eye" in html_content
    assert "FICHA CONSOLIDADA DO ALVO" in html_content
    assert "mermaid" in html_content
