import os
import pytest
from app.api.v1 import reports as reports_router


@pytest.mark.asyncio
async def test_compliance_report_success(client, monkeypatch, tmp_path):
    # Create a fake PDF file
    pdf = tmp_path / "x.pdf"
    pdf.write_bytes(b"%PDF-1.4\n%fake\n")

    async def _fake_generate(db, project_name, user_id):
        return str(pdf), {"id": 1}

    monkeypatch.setattr(reports_router, "generate_compliance_report", _fake_generate)

    r = await client.post("/api/reports/compliance", json={"project_name": "proj1", "user_id": 99})
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/pdf")


@pytest.mark.asyncio
async def test_compliance_report_generator_exception_500(client, monkeypatch):
    async def _fake_generate(db, project_name, user_id):
        raise RuntimeError("boom")

    monkeypatch.setattr(reports_router, "generate_compliance_report", _fake_generate)

    r = await client.post("/api/reports/compliance", json={"project_name": "proj1", "user_id": 99})
    assert r.status_code == 500
    assert "Report generation failed" in r.json()["detail"]


@pytest.mark.asyncio
async def test_compliance_report_missing_file_500(client, monkeypatch):
    async def _fake_generate(db, project_name, user_id):
        return "/tmp/does-not-exist.pdf", {"id": 1}

    monkeypatch.setattr(reports_router, "generate_compliance_report", _fake_generate)

    r = await client.post("/api/reports/compliance", json={"project_name": "proj1", "user_id": 99})
    assert r.status_code == 500
    assert "Failed to generate compliance report file" in r.json()["detail"]
