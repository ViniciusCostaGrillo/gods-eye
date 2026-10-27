"""Integration tests for FastAPI v1 REST Backend."""

import httpx
import pytest

from godseye.api.app import create_app


@pytest.mark.asyncio
async def test_fastapi_v1_endpoints(temp_db_path: str) -> None:
    app = create_app(db_path=temp_db_path)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Health & Metrics
        r_health = await client.get("/health")
        assert r_health.status_code == 200
        assert r_health.json()["sources_registered"] >= 110

        # 2. Sources Catalog (Global + Brazil)
        r_sources = await client.get("/api/v1/sources?region=brasil")
        assert r_sources.status_code == 200
        assert len(r_sources.json()) >= 15

        # 3. Create Case
        r_case = await client.post(
            "/api/v1/cases",
            json={"title": "API Case Test", "owner": "unit-tester"},
            headers={"X-GodsEye-Role": "investigator"},
        )
        assert r_case.status_code == 201
        case_id = r_case.json()["id"]

        # 4. RBAC Enforcement: Analyst cannot create a case
        r_forbidden = await client.post(
            "/api/v1/cases",
            json={"title": "Unauthorized Case"},
            headers={"X-GodsEye-Role": "analyst"},
        )
        assert r_forbidden.status_code == 403

        # 5. Add Target & Trigger Collection
        r_target = await client.post(
            f"/api/v1/cases/{case_id}/targets",
            json={"value": "example.com"},
            headers={"X-GodsEye-Role": "investigator"},
        )
        assert r_target.status_code == 201

        r_coll = await client.post(
            f"/api/v1/cases/{case_id}/collections",
            json={"max_depth": 1, "sources": ["rdap", "dns_doh"]},
            headers={"X-GodsEye-Role": "investigator"},
        )
        assert r_coll.status_code == 200
        assert len(r_coll.json()["runs"]) == 1

        # 6. Graph, Timeline, Evidence, Report & Audit
        r_graph = await client.get(f"/api/v1/cases/{case_id}/graph")
        assert r_graph.status_code == 200
        assert r_graph.json()["nodes_count"] >= 1

        r_rep = await client.post(
            f"/api/v1/cases/{case_id}/reports",
            json={"format": "json"},
        )
        assert r_rep.status_code == 200
        assert r_rep.json()["case"]["id"] == case_id

        r_audit = await client.get(
            "/api/v1/audit",
            headers={"X-GodsEye-Role": "auditor"},
        )
        assert r_audit.status_code == 200
        assert len(r_audit.json()) >= 2

    await app.state.container.shutdown()
