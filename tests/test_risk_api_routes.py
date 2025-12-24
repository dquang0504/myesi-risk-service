import asyncio
import json
import pytest
from unittest.mock import AsyncMock
import datetime as dt
from jose import jwt
from app.api.v1 import risk as risk_router
from app.core.config import settings
from app.services import risk_service


def _make_token():
    return jwt.encode({"sub": "test-user"}, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


@pytest.mark.asyncio
async def test_risk_score_success(client, fake_db, fake_execute_result, monkeypatch):
    # Mock: DB returns vulnerabilities
    vulns = [
        type("V", (), {"sbom_id": "sb1", "component_name": "a", "component_version": "1", "project_name": "p"})(),
        type("V", (), {"sbom_id": "sb1", "component_name": "b", "component_version": "2", "project_name": "p"})(),
    ]
    fake_db.execute.return_value = fake_execute_result(scalars=vulns)

    # Mock: save_risk_scores returns computed list
    async def _fake_save(vulns, sbom_id, db, prefer_max=False):
        return [
            {"component_name": "a", "component_version": "1", "score": 7.5},
            {"component_name": "b", "component_version": "2", "score": 4.2},
        ]

    monkeypatch.setattr(risk_router, "save_risk_scores", _fake_save)

    r = await client.get("/api/risk/score", params={"sbom_id": "sb1"})
    assert r.status_code == 200
    data = r.json()
    assert len(data) == 2
    assert data[0]["component_name"] == "a"


@pytest.mark.asyncio
async def test_risk_score_no_vulns_returns_empty_list(client, fake_db, fake_execute_result, monkeypatch):
    fake_db.execute.return_value = fake_execute_result(scalars=[])

    async def _fake_save(vulns, sbom_id, db, prefer_max=False):
        return []

    monkeypatch.setattr(risk_router, "save_risk_scores", _fake_save)

    r = await client.get("/api/risk/score", params={"sbom_id": "sb1"})
    assert r.status_code == 200
    assert r.json() == []


@pytest.mark.asyncio
async def test_risk_trends_success(client, monkeypatch):
    async def _fake_trends(db):
        return [{"component_name": "a", "average_score": 5.5, "sbom_count": 2}]

    monkeypatch.setattr(risk_router, "get_risk_trends", _fake_trends)

    r = await client.get("/api/risk/trends")
    assert r.status_code == 200
    assert r.json()[0]["component_name"] == "a"


@pytest.mark.asyncio
async def test_stream_missing_jwt_401(client):
    r = await client.get("/api/risk/stream")
    assert r.status_code == 401
    assert r.json()["detail"] == "Missing JWT"


@pytest.mark.asyncio
async def test_stream_invalid_jwt_401(client):
    r = await client.get("/api/risk/stream", headers={"Authorization": "Bearer invalid.token.here"})
    assert r.status_code == 401
    assert r.json()["detail"] == "Invalid JWT"


import json
import pytest
from starlette.requests import Request as StarletteRequest

@pytest.mark.asyncio
async def test_stream_success_receives_last_event(client, monkeypatch):
    # Seed LAST_EVENTS so first chunk is immediate
    risk_router.LAST_EVENTS.clear()
    risk_router.SSE_CLIENTS.clear()
    risk_router.LAST_EVENTS["proj1"] = {"type": "scan_complete", "project_name": "proj1"}

    # --- Force disconnect after first yielded event to stop infinite SSE generator ---
    called = {"n": 0}

    async def _fake_is_disconnected(self: StarletteRequest) -> bool:
        called["n"] += 1
        # First check happens right after first yield -> return True to break loop
        return True

    monkeypatch.setattr(StarletteRequest, "is_disconnected", _fake_is_disconnected, raising=True)

    token = _make_token()

    async with client.stream(
        "GET",
        "/api/risk/stream?project_name=proj1",
        headers={"Authorization": f"Bearer {token}"},
    ) as resp:
        assert resp.status_code == 200

        text = ""
        async for chunk in resp.aiter_text():
            text += chunk
            if "data:" in text:
                break

        assert "data:" in text
        payload_part = text.split("data: ", 1)[1].split("\n\n", 1)[0]
        parsed = json.loads(payload_part)
        assert parsed["type"] == "scan_complete"
        assert parsed["project_name"] == "proj1"


@pytest.mark.asyncio
async def test_analytics_success(client, fake_db, fake_execute_result):
    # get_org_id_from_header reads X-Organization-ID
    # 1) severity distribution query
    fake_db.execute.side_effect = [
        fake_execute_result(rows=[("Critical",), ("high",), ("high",)]),
        fake_execute_result(rows=[(7.0,), (9.0,), (None,)]),
    ]

    r = await client.get("/api/risk/analytics", headers={"X-Organization-ID": "10"})
    assert r.status_code == 200
    data = r.json()
    assert "overallRisk" in data
    assert "distribution" in data
    # Expect high count 2, critical 1 (case-normalized)
    dist = {d["name"].lower(): d["value"] for d in data["distribution"]}
    assert dist["high"] == 2
    assert dist["critical"] == 1


@pytest.mark.asyncio
async def test_heatmap_invalid_type_400(client):
    r = await client.get("/api/risk/heatmap", params={"type": "components"}, headers={"X-Organization-ID": "10"})
    assert r.status_code == 400
    assert "Only 'projects' heatmap supported" in r.json()["detail"]


@pytest.mark.asyncio
async def test_heatmap_success(client, fake_db, fake_execute_result):
    import datetime as dt
    fake_db.execute.return_value = fake_execute_result(
        rows=[
            ("projA", dt.date(2025, 12, 10), 7.2),
            ("projA", dt.date(2025, 12, 11), None),
        ]
    )

    r = await client.get("/api/risk/heatmap", params={"type": "projects"}, headers={"X-Organization-ID": "10"})
    assert r.status_code == 200
    heatmap = r.json()["heatmap"]
    assert len(heatmap) == 2
    assert heatmap[0]["y"] == "projA"

class _IterResult:
    """
    Result object that supports:
      - fetchall()
      - iteration: for x in result
      - scalar() (optional)
      - fetchone() (optional)
    """
    def __init__(self, rows=None, scalar_value=None, one=None):
        self._rows = rows or []
        self._scalar_value = scalar_value
        self._one = one

    def fetchall(self):
        return list(self._rows)

    def __iter__(self):
        return iter(self._rows)

    def scalar(self):
        return self._scalar_value

    def fetchone(self):
        return self._one


# =========================================================
# /api/risk/overview
# =========================================================

@pytest.mark.asyncio
async def test_risk_overview_success(client, fake_db):
    # Order in handler:
    # 1) scalar total_active
    # 2) scalar total_fixed
    # 3) scalar critical
    # 4) scalar avg_risk_score
    # 5) scalar projects_at_risk
    fake_db.scalar.side_effect = [
        12,     # total_active
        3,      # total_fixed
        2,      # critical
        6.25,   # avg_risk_score
        4,      # projects_at_risk
    ]

    # Order in handler:
    # 1) execute dist_rows -> .fetchall()
    # 2) execute trend_rows -> .fetchall()
    # 3) execute cat_rows -> .fetchall()
    # 4) execute proj_rows -> .fetchall()
    fake_db.execute.side_effect = [
        _IterResult(rows=[("critical", 2), ("high", 5), ("unknown", 1)]),
        _IterResult(rows=[(dt.date(2025, 12, 1), "critical", 1), (dt.date(2025, 12, 2), "high", 3)]),
        _IterResult(rows=[("network", 4), ("access_control", 2)]),
        _IterResult(rows=[("projA", 8.8, 10), ("projB", 7.1, 2)]),
    ]

    r = await client.get("/api/risk/overview")
    assert r.status_code == 200
    data = r.json()

    assert data["metrics"]["totalRisks"] == 12
    assert data["metrics"]["criticalIssues"] == 2
    assert data["metrics"]["fixedVulnerabilities"] == 3
    assert data["metrics"]["projectsAtRisk"] == 4
    assert isinstance(data["distribution"], list)
    assert isinstance(data["trend"], list)
    assert isinstance(data["categories"], list)
    assert isinstance(data["projectRisks"], list)
    assert "lastUpdated" in data


# =========================================================
# /api/risk/analyst/dashboard
# =========================================================

@pytest.mark.asyncio
async def test_analyst_dashboard_success(client, fake_db):
    # Order in handler:
    # 1) execute active_rows -> .fetchall()
    # 2) scalar completed_reports
    # 3) scalar total_reports
    # 4) scalar total_fixed
    # 5) execute control_rows -> .fetchall() (we make it empty => control_counts = {})
    # 6) execute weight_rows -> .fetchall() (empty ok)
    # 7) execute project_rows -> .fetchall()
    # 8) execute dist_rows -> iterated directly (for sev, cnt in dist_rows)
    # 9) execute trend_rows -> iterated via fetchall()

    fake_db.scalar.side_effect = [
        2,   # completed_reports
        5,   # total_reports
        7,   # total_fixed
    ]

    active_rows = _IterResult(
        rows=[
            # (severity, osv_metadata, sbom_id, component_name, component_version)
            ("critical", {}, "sb1", "a", "1.0"),
            ("high", {}, "sb1", "b", "2.0"),
            ("low", {}, "sb2", "c", "3.0"),
        ]
    )

    control_rows = _IterResult(rows=[])  # no control mappings found
    weight_rows = _IterResult(rows=[])   # no weights

    # project_rows: (pid, pname, active_vulns, report_score)
    # Make sure we avoid per-project fallback execute by ensuring:
    # - active_vulns==0 OR report_score is not None when active_vulns>0
    project_rows = _IterResult(
        rows=[
            (1, "projNoVuln", 0, None),
            (2, "projHasReport", 2, 88.0),
        ]
    )

    # dist_rows is iterated directly: "for sev, cnt in dist_rows:"
    dist_rows = _IterResult(rows=[("critical", 1), ("high", 1), ("low", 1)])

    trend_rows = _IterResult(rows=[(dt.date(2025, 12, 10), 7.25), (dt.date(2025, 12, 11), 6.50)])

    fake_db.execute.side_effect = [
        active_rows,
        control_rows,
        weight_rows,
        project_rows,
        dist_rows,
        trend_rows,
    ]

    r = await client.get("/api/risk/analyst/dashboard")
    assert r.status_code == 200
    data = r.json()

    assert "stats" in data
    assert data["stats"]["totalRisks"] == 3
    assert data["stats"]["criticalIssues"] == 1
    # reportsGenerated prefers completed_reports when non-zero
    assert data["stats"]["reportsGenerated"] == 2
    assert data["stats"]["fixedVulnerabilities"] == 7

    assert isinstance(data["distribution"], list)
    assert isinstance(data["complianceChecklist"], list)
    assert isinstance(data["riskTrend"], list)


# =========================================================
# /api/risk/compliance/overview
# =========================================================

@pytest.mark.asyncio
async def test_compliance_overview_success(client, fake_db):
    # Order in handler:
    # 1) execute score_rows (completed reports per project)
    # 2) execute std_rows (distinct standards from compliance_weights)
    # 3) execute ctrl_rows (top controls mapped to active vulns)
    # 4) execute recent_rows (last 5 compliance reports)
    # 5) execute proj_rows (latest per project w/ user email)
    # 6) execute trend_rows (avg compliance score last 30 days)

    now = dt.datetime(2025, 12, 14, 10, 0, 0)

    score_rows = _IterResult(
        rows=[
            # (project_name, report_data, created_at, status)
            ("projA", json.dumps({"compliance_score": 92, "per_standard_scores": {"ISO_27001:2022": 92}}), now, "completed"),
            ("projB", json.dumps({"compliance_score": 80, "per_standard_scores": {"ISO_27001:2022": 80}}), now, "completed"),
        ]
    )

    std_rows = _IterResult(
        rows=[
            ("ISO_27001:2022",),
            ("NIST_SP_800_53",),
        ]
    )

    ctrl_rows = _IterResult(
        rows=[
            ("A.5.1", "Policies for information security", "Governance", 3),
            ("A.8.2", "Privileged access rights", "Access Control", 2),
        ]
    )

    recent_rows = _IterResult(
        rows=[
            # (project_name, status, created_at, generated_by, report_url, report_data)
            ("projA", "completed", now, 10, "/tmp/a.pdf", json.dumps({"compliance_score": 92, "vulnerabilities": {"critical": 1, "high": 2}})),
            ("projB", "completed", now, 11, "/tmp/b.pdf", json.dumps({"compliance_score": 80, "vulnerabilities": {"high": 1}})),
        ]
    )

    proj_rows = _IterResult(
        rows=[
            # (project_name, created_at, status, report_url, generated_by, report_data, email)
            ("projA", now, "completed", "/tmp/a.pdf", 10, json.dumps({"compliance_score": 92, "vulnerabilities": {"critical": 1}}), "a@ex.com"),
            ("projB", now, "completed", "/tmp/b.pdf", 11, json.dumps({"compliance_score": 80, "vulnerabilities": {"high": 1}}), "b@ex.com"),
        ]
    )

    trend_rows = _IterResult(
        rows=[
            # (day, avg_score)
            (now, 86.0),
        ]
    )

    fake_db.execute.side_effect = [
        score_rows,
        std_rows,
        ctrl_rows,
        recent_rows,
        proj_rows,
        trend_rows,
    ]

    r = await client.get("/api/risk/compliance/overview")
    assert r.status_code == 200
    data = r.json()

    assert "overallScore" in data
    assert data["overallScore"] == 86.0  # average of 92 and 80
    assert isinstance(data["frameworks"], list)
    assert isinstance(data["controls"], list)
    assert isinstance(data["recentReports"], list)
    assert isinstance(data["projectScores"], list)
    assert isinstance(data["trend"], list)


# =========================================================
# /api/risk/overview/report
# =========================================================

@pytest.mark.asyncio
async def test_risk_overview_report_success(client, monkeypatch):
    async def _fake_generate(db):
        return (b"%PDF-1.4\nfake\n", "application/pdf", "risk_overview.pdf")

    monkeypatch.setattr(risk_router, "generate_risk_overview_report", _fake_generate)

    r = await client.post("/api/risk/overview/report")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/pdf")
    assert "attachment; filename=risk_overview.pdf" in r.headers.get("content-disposition", "")


@pytest.mark.asyncio
async def test_risk_overview_report_runtimeerror_503(client, monkeypatch):
    async def _fake_generate(db):
        raise RuntimeError("deps missing")

    monkeypatch.setattr(risk_router, "generate_risk_overview_report", _fake_generate)

    r = await client.post("/api/risk/overview/report")
    assert r.status_code == 503
    assert r.json()["detail"] == "deps missing"


@pytest.mark.asyncio
async def test_risk_overview_report_unexpected_exception_500(client, monkeypatch):
    async def _fake_generate(db):
        raise Exception("boom")

    monkeypatch.setattr(risk_router, "generate_risk_overview_report", _fake_generate)

    r = await client.post("/api/risk/overview/report")
    assert r.status_code == 500
    assert "Failed to generate report" in r.json()["detail"]
    
@pytest.mark.asyncio
async def test_risk_overview_empty_everything_returns_safe_defaults(client, fake_db):
    # scalar order:
    # total_active, total_fixed, critical, avg_risk_score, projects_at_risk
    fake_db.scalar.side_effect = [0, 0, 0, 0.0, 0]

    # execute order: dist, trend, categories, projectRisks
    fake_db.execute.side_effect = [
        _IterResult(rows=[]),  # dist
        _IterResult(rows=[]),  # trend
        _IterResult(rows=[]),  # categories
        _IterResult(rows=[]),  # projectRisks
    ]

    r = await client.get("/api/risk/overview")
    assert r.status_code == 200
    data = r.json()

    assert data["metrics"]["totalRisks"] == 0
    assert data["metrics"]["criticalIssues"] == 0
    assert data["metrics"]["projectsAtRisk"] == 0
    assert data["metrics"]["fixedVulnerabilities"] == 0
    assert isinstance(data["distribution"], list)
    assert isinstance(data["trend"], list)
    assert isinstance(data["categories"], list)
    assert isinstance(data["projectRisks"], list)
    assert "lastUpdated" in data
    
@pytest.mark.asyncio
async def test_analyst_dashboard_no_active_vulns_checklist_all_true(client, fake_db):
    # active_rows empty
    # scalar: completed_reports, total_reports, total_fixed
    fake_db.scalar.side_effect = [0, 0, 0]

    fake_db.execute.side_effect = [
        _IterResult(rows=[]),  # active_rows
        _IterResult(rows=[]),  # control_rows
        _IterResult(rows=[]),  # weight_rows
        _IterResult(rows=[]),  # project_rows
        _IterResult(rows=[]),  # dist_rows
        _IterResult(rows=[]),  # trend_rows
    ]

    r = await client.get("/api/risk/analyst/dashboard")
    assert r.status_code == 200
    data = r.json()

    assert data["stats"]["totalRisks"] == 0
    assert data["stats"]["criticalIssues"] == 0
    assert data["stats"]["complianceScore"] == 100.0  # from code path with project_scores empty
    assert data["stats"]["reportsGenerated"] == 0
    assert data["stats"]["fixedVulnerabilities"] == 0

    checklist = {x["name"]: x["status"] for x in data["complianceChecklist"]}
    assert checklist["ISO_27001"] is True
    assert checklist["NIST_SP_800_53"] is True
    assert checklist["OWASP"] is True
    
@pytest.mark.asyncio
async def test_analyst_dashboard_checklist_based_on_min_compliance_when_reports_exist(client, fake_db):
    # active vulns exist
    fake_db.scalar.side_effect = [
        1,  # completed_reports
        1,  # total_reports
        0,  # total_fixed
    ]

    fake_db.execute.side_effect = [
        _IterResult(rows=[("high", {}, "sb1", "a", "1.0")]),  # active_rows
        _IterResult(rows=[]),  # control_rows
        _IterResult(rows=[]),  # weight_rows
        # project_rows: active_vulns>0 and report_score is LOW
        _IterResult(rows=[(1, "projLow", 3, 50.0)]),
        _IterResult(rows=[("high", 1)]),                      # dist_rows (iterated)
        _IterResult(rows=[(dt.date(2025, 12, 1), 5.0)]),      # trend_rows
    ]

    r = await client.get("/api/risk/analyst/dashboard")
    assert r.status_code == 200
    data = r.json()

    checklist = {x["name"]: x["status"] for x in data["complianceChecklist"]}
    # ISO needs >=85, NIST needs >=75; report_score=50 => both False.
    assert checklist["ISO_27001"] is False
    assert checklist["NIST_SP_800_53"] is False
    # OWASP depends on critical active count; here none critical => True
    assert checklist["OWASP"] is True
    
@pytest.mark.asyncio
async def test_compliance_overview_invalid_report_data_json_is_handled(client, fake_db):
    now = dt.datetime(2025, 12, 14, 10, 0, 0)

    fake_db.execute.side_effect = [
        _IterResult(rows=[("projA", "{not-json", now, "completed")]),  # score_rows
        _IterResult(rows=[("ISO_27001:2022",)]),                      # std_rows
        _IterResult(rows=[]),                                         # ctrl_rows
        _IterResult(rows=[("projA", "completed", now, 10, "/tmp/a.pdf", "{not-json")]),  # recent_rows
        _IterResult(rows=[("projA", now, "completed", "/tmp/a.pdf", 10, "{not-json", "a@ex.com")]),  # proj_rows
        _IterResult(rows=[]),                                         # trend_rows (empty)
    ]

    r = await client.get("/api/risk/compliance/overview")
    assert r.status_code == 200
    data = r.json()

    # invalid JSON => compliance_score default 0
    assert data["overallScore"] == 0.0
    assert isinstance(data["frameworks"], list)
    assert isinstance(data["controls"], list)
    assert isinstance(data["recentReports"], list)
    assert isinstance(data["projectScores"], list)
    # trend empty => code currently returns [] (no explicit fallback in this handler)
    assert isinstance(data["trend"], list)
    
@pytest.mark.asyncio
async def test_compliance_overview_no_standards_defaults_to_iso(client, fake_db):
    now = dt.datetime(2025, 12, 14, 10, 0, 0)

    fake_db.execute.side_effect = [
        _IterResult(rows=[("projA", json.dumps({"compliance_score": 90}), now, "completed")]),  # score_rows
        _IterResult(rows=[]),  # std_rows -> default ISO_27001:2022
        _IterResult(rows=[]),  # ctrl_rows
        _IterResult(rows=[]),  # recent_rows
        _IterResult(rows=[]),  # proj_rows
        _IterResult(rows=[]),  # trend_rows
    ]

    r = await client.get("/api/risk/compliance/overview")
    assert r.status_code == 200
    data = r.json()

    # should still produce frameworks with 1 item (ISO default)
    assert len(data["frameworks"]) == 1
    assert data["frameworks"][0]["name"] == "ISO_27001:2022"
    assert data["frameworks"][0]["score"] == 90.0
    
@pytest.mark.asyncio
async def test_risk_overview_report_html_fallback_success(client, monkeypatch):
    async def _fake_generate(db):
        return (b"<html>ok</html>", "text/html", "risk_overview.html")

    monkeypatch.setattr(risk_router, "generate_risk_overview_report", _fake_generate)

    r = await client.post("/api/risk/overview/report")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/html")
    assert "attachment; filename=risk_overview.html" in r.headers.get("content-disposition", "")