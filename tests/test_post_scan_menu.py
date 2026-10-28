"""Tests for Post-Scan Quick Pivoting Actions."""

import pytest
from godseye.api.app import AppContainer
from godseye.cli.main import _get_post_scan_actions
from godseye.domain.enums import Role, TargetType


@pytest.mark.asyncio
async def test_post_scan_actions_extracted(container: AppContainer):
    case = container.case_service.create_case(
        title="Post Scan Actions Test", actor_role=Role.INVESTIGATOR
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
    actions = _get_post_scan_actions(case.id, container)
    assert "discovered_cnpjs" in actions
    assert "discovered_processes" in actions
    assert "html_dossier_available" in actions
