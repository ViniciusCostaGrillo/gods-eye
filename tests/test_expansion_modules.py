"""Unit & Integration tests for Phase 2 OSINT Expansion Modules (expansao-osint-modulos-fontes-apis.md)."""

from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient
from typer.testing import CliRunner

from godseye.api.app import AppContainer, create_app
from godseye.cli.main import app as cli_app
from godseye.collectors.expansion_sources import detect_blockchain, parse_e164_phone
from godseye.domain.enums import (
    EntityType,
    RiskLevel,
    SourceReviewStatus,
    TargetType,
    VerificationStatus,
)
from godseye.domain.models import NormalizedObservation, utc_now_iso
from godseye.services.case_service import detect_target_type, normalize_target_value


def test_target_detection_and_normalization_expansion() -> None:
    """Verify auto-detection and normalization for Phone, Crypto, and Image targets."""
    # Phone E.164 & Brazilian DDD
    assert detect_target_type("+55 (11) 99999-8888") == TargetType.PHONE
    assert normalize_target_value(TargetType.PHONE, "+55 (11) 99999-8888") == "+5511999998888"
    assert normalize_target_value(TargetType.PHONE, "11988887777") == "+5511988887777"

    phone_meta = parse_e164_phone("+5511999998888")
    assert phone_meta["country"] == "BR"
    assert phone_meta["area_code"] == "11"
    assert phone_meta["uf"] == "SP"
    assert phone_meta["line_type"] == "mobile"

    # Crypto Addresses (BTC, ETH, TRON)
    btc_addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    eth_addr = "0x7F367cC41522cE07553e823bf3be79A889DEbe1B"
    trx_addr = "T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb"
    assert detect_target_type(btc_addr) == TargetType.CRYPTO_ADDRESS
    assert detect_target_type(eth_addr) == TargetType.CRYPTO_ADDRESS
    assert detect_target_type(trx_addr) == TargetType.CRYPTO_ADDRESS
    assert detect_blockchain(btc_addr) == "bitcoin"
    assert detect_blockchain(eth_addr) == "ethereum"
    assert detect_blockchain(trx_addr) == "tron"

    # Image file target
    assert detect_target_type("suspect_photo.jpg") == TargetType.IMAGE


@pytest.mark.asyncio
async def test_phone_and_crypto_osint_investigation(container: AppContainer) -> None:
    """Test Phone OSINT and Crypto OSINT (including OFAC sanctioned wallet screening)."""
    case = container.case_service.create_case(title="Phone & Crypto Investigation")

    # 1. Phone target
    phone_target = container.case_service.add_target(case.id, "+5511999998888")
    assert phone_target.type == TargetType.PHONE
    phone_res = await container.orchestrator.investigate_target(case.id, phone_target, max_depth=1)
    assert phone_res["entities_count"] >= 2
    rule_ids = {f["rule_id"] for f in phone_res["findings"]}
    assert "CORR-PHONE-TELECOM" in rule_ids

    # 2. Sanctioned Crypto Wallet target (OFAC demo address)
    crypto_target = container.case_service.add_target(
        case.id, "0x7F367cC41522cE07553e823bf3be79A889DEbe1B"
    )
    assert crypto_target.type == TargetType.CRYPTO_ADDRESS
    crypto_res = await container.orchestrator.investigate_target(case.id, crypto_target, max_depth=1)
    crypto_rules = {f["rule_id"] for f in crypto_res["findings"]}
    assert "CORR-CRYPTO-LEDGER" in crypto_rules

    entities = container.repo.list_entities(case.id)
    entity_types = {e.type for e in entities}
    assert EntityType.PHONE in entity_types
    assert EntityType.CRYPTO_WALLET in entity_types
    assert EntityType.CRYPTO_TRANSACTION in entity_types
    assert EntityType.SANCTION in entity_types


@pytest.mark.asyncio
async def test_watchlists_and_continuous_alerts(container: AppContainer) -> None:
    """Test Watchlist creation and automatic alert firing on domain events (Module 1)."""
    case = container.case_service.create_case(title="Watchlist Continuous Monitoring")
    wl = container.watchlist_service.create_watchlist(
        case_id=case.id,
        value="analyst@example.com",
        target_type=TargetType.EMAIL,
        severity=RiskLevel.HIGH,
    )
    assert wl.id

    target = container.case_service.add_target(case.id, "analyst@example.com", TargetType.EMAIL)
    await container.orchestrator.investigate_target(case.id, target, max_depth=1)

    alerts = container.watchlist_service.list_alerts(watchlist_id=wl.id)
    assert len(alerts) >= 1
    assert alerts[0].acknowledged_at is None

    acked = container.watchlist_service.acknowledge_alert(alerts[0].id, actor_id="sec-lead")
    assert acked is not None
    assert acked.acknowledged_at is not None
    assert acked.acknowledged_by == "sec-lead"


def test_brazuca_catalog_importer_and_candidate_governance(container: AppContainer) -> None:
    """Test OSINT Brazuca dynamic catalog import and human review approval (Module 3)."""
    candidates = container.registry.import_brazuca_catalog()
    assert len(candidates) >= 3
    for cand in candidates:
        assert cand.status == SourceReviewStatus.CANDIDATE
        assert cand.enabled is False

    target_source_id = candidates[0].id
    approved = container.registry.approve_candidate_source(target_source_id)
    assert approved is not None
    assert approved.status == SourceReviewStatus.ACTIVE
    assert approved.enabled is True
    assert approved.last_reviewed_at is not None


def test_collaboration_governance_and_assistive_ai(container: AppContainer) -> None:
    """Test Collaboration (Module 6), Data Quality & Conflict Governance (Module 7), and Assistive AI (Module 8)."""
    case = container.case_service.create_case(title="Multi-Analyst Collaboration Case")

    # Module 6: Comments with @mentions, Tasks, Verifications, Case Snapshots
    comment = container.collaboration_service.add_comment(
        case_id=case.id,
        body="Confirmed QSA partner match with @alice and @bob_sec.",
        author_id="lead-investigator",
    )
    assert comment.mentions == ["alice", "bob_sec"]

    task = container.collaboration_service.create_task(
        case_id=case.id,
        title="Cross-check Portal da Transparência sanctions",
        assignee_id="alice",
    )
    updated_task = container.collaboration_service.update_task_status(
        case.id, task.id, "done"
    )
    assert updated_task is not None
    assert updated_task.status == "done"

    ver = container.collaboration_service.verify_finding(
        case_id=case.id,
        status=VerificationStatus.CORROBORATED,
        reason="Verified against official Receita Federal QSA certificate.",
        entity_id="ent-123",
    )
    assert ver.status == VerificationStatus.CORROBORATED

    dossier = container.reporting.generate_dossier(case_id=case.id)
    snap = container.collaboration_service.create_case_version(
        case_id=case.id,
        change_summary="Milestone 1 Snapshot",
        dossier_payload=dossier,
    )
    assert snap.version == 1
    assert len(snap.snapshot_hash) == 64

    # Module 7: Data Quality Formula & Inter-Source Conflict Detection
    # Insert two conflicting observations for the same organization's situacao_cadastral
    obs1 = NormalizedObservation(
        case_id=case.id,
        evidence_id="ev-1",
        source_id="brasilapi_cnpj",
        entity_type=EntityType.ORGANIZATION,
        entity_value="00000000000191",
        canonical_value="00000000000191",
        attributes={"situacao_cadastral": "ATIVA", "uf": "DF"},
        confidence=0.98,
        observed_at=utc_now_iso(),
    )
    obs2 = NormalizedObservation(
        case_id=case.id,
        evidence_id="ev-2",
        source_id="receitaws_cnpj",
        entity_type=EntityType.ORGANIZATION,
        entity_value="00000000000191",
        canonical_value="00000000000191",
        attributes={"situacao_cadastral": "BAIXADA", "uf": "DF"},
        confidence=0.80,
        observed_at=utc_now_iso(),
    )
    container.repo.save_observation(obs1)
    container.repo.save_observation(obs2)
    container.orchestrator.resolver.resolve(obs1)
    container.orchestrator.resolver.resolve(obs2)

    gov = container.governance_service.evaluate_case_governance(case.id)
    assert gov["scores_calculated"] >= 2
    assert gov["conflicts_detected"] >= 1
    assert "situacao_cadastral" in gov["conflicts"][0]["conflict_type"]

    # Module 8: Auditable Assistive AI (marked model_generated + requires human review)
    inf = container.ai_service.generate_case_analysis(
        case_id=case.id,
        task_type="dossier_summary",
    )
    assert inf.confidence_kind == "model_generated"
    assert inf.human_review_status == "pending_review"
    assert "MODEL_GENERATED" in inf.output

    reviewed = container.ai_service.review_inference(
        inf.id,
        decision="approved",
        reviewer_id="lead-investigator",
    )
    assert reviewed is not None
    assert reviewed.human_review_status == "approved"


@pytest.mark.asyncio
async def test_expansion_fastapi_endpoints(tmp_path: Path) -> None:
    """Test all new Phase 2 FastAPI /api/v1 endpoints."""
    db_file = str(tmp_path / "api_expansion.db")
    app = create_app(db_path=db_file)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        # Create case
        r_case = await client.post("/api/v1/cases", json={"title": "API Expansion Test"})
        assert r_case.status_code == 201
        case_id = r_case.json()["id"]

        # Create watchlist
        r_wl = await client.post(
            "/api/v1/watchlists",
            json={"case_id": case_id, "value": "example.com"},
        )
        assert r_wl.status_code == 201

        # Import OSINT Brazuca candidates (requires admin role)
        r_brazuca = await client.post(
            "/api/v1/catalog/import-brazuca",
            headers={"X-GodsEye-Role": "admin"},
        )
        assert r_brazuca.status_code == 200
        assert r_brazuca.json()["imported_count"] >= 3

        # Add comment, task, verification, version
        r_comment = await client.post(
            f"/api/v1/cases/{case_id}/comments",
            json={"body": "Reviewing with @sec_team"},
        )
        assert r_comment.status_code == 201
        assert r_comment.json()["mentions"] == ["sec_team"]

        r_task = await client.post(
            f"/api/v1/cases/{case_id}/tasks",
            json={"title": "Validate DNSSEC", "assignee_id": "sec_team"},
        )
        assert r_task.status_code == 201

        r_ver = await client.post(
            f"/api/v1/cases/{case_id}/verifications",
            json={"entity_id": "ent-1", "status": "corroborated", "reason": "Confirmed"},
        )
        assert r_ver.status_code == 201

        r_snap = await client.post(
            f"/api/v1/cases/{case_id}/versions",
            json={"change_summary": "Initial API snapshot"},
        )
        assert r_snap.status_code == 201

        # Data quality & Assistive AI
        r_qual = await client.get(f"/api/v1/cases/{case_id}/quality")
        assert r_qual.status_code == 200

        r_ai = await client.post(
            f"/api/v1/cases/{case_id}/ai-assist",
            json={"task_type": "dossier_summary"},
        )
        assert r_ai.status_code == 201
        inf_id = r_ai.json()["id"]
        assert r_ai.json()["confidence_kind"] == "model_generated"

        r_rev = await client.post(
            f"/api/v1/ai-assist/{inf_id}/review",
            json={"decision": "approved"},
        )
        assert r_rev.status_code == 200
        assert r_rev.json()["human_review_status"] == "approved"

    await app.state.container.shutdown()


def test_expansion_cli_commands() -> None:
    """Test new CLI subcommands: brazuca, watchlist, alerts."""
    runner = CliRunner()
    res_brazuca = runner.invoke(cli_app, ["brazuca", "--import"])
    assert res_brazuca.exit_code == 0
    assert "OSINT Brazuca" in res_brazuca.stdout

    res_wl = runner.invoke(cli_app, ["watchlist", "--create", "example.com"])
    assert res_wl.exit_code == 0
    assert "Watchlist created" in res_wl.stdout
