import pytest
from types import SimpleNamespace
from unittest.mock import AsyncMock

from app.services import risk_service


@pytest.mark.asyncio
async def test_compute_risk_score_empty_returns_0():
    score = await risk_service.compute_risk_score([])
    assert score == 0.0


@pytest.mark.asyncio
async def test_compute_risk_score_malware_indicator_is_high():
    v = SimpleNamespace(
        vuln_id="MAL-123",
        cvss_vector=None,
        severity="low",
    )
    score = await risk_service.compute_risk_score([v])
    assert score > 9.0
    assert score <= 10.0


@pytest.mark.asyncio
async def test_compute_risk_score_cvss_vector_parsed():
    v = SimpleNamespace(
        vuln_id="CVE-2024-0001",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        severity=None,
    )
    score = await risk_service.compute_risk_score([v])
    # Network + High impact should produce a high score
    assert score >= 7.0
    assert score <= 10.0


@pytest.mark.asyncio
async def test_compute_risk_score_fallback_severity_mapping():
    v = SimpleNamespace(
        vuln_id="CVE-2024-0002",
        cvss_vector="",
        severity="critical",
    )
    score = await risk_service.compute_risk_score([v])
    assert score >= 7.0
    assert score <= 10.0


@pytest.mark.asyncio
async def test_compute_risk_score_prefer_max():
    v1 = SimpleNamespace(vuln_id="CVE-1", cvss_vector="", severity="low")
    v2 = SimpleNamespace(vuln_id="CVE-2", cvss_vector="", severity="critical")
    avg = await risk_service.compute_risk_score([v1, v2], prefer_max=False)
    mx = await risk_service.compute_risk_score([v1, v2], prefer_max=True)
    assert mx >= avg


@pytest.mark.asyncio
async def test_save_risk_scores_groups_and_writes(db_like=frozenset()):
    """
    save_risk_scores should:
      - group by (component_name, component_version)
      - db.add(...) per group
      - commit
      - attempt UPDATE projects ... when project_name present
    """
    fake_db = AsyncMock()
    fake_db.add = AsyncMock()
    fake_db.commit = AsyncMock()
    fake_db.execute = AsyncMock()

    v1 = SimpleNamespace(component_name="a", component_version="1.0", project_name="p", vuln_id="CVE-1", cvss_vector="", severity="high")
    v2 = SimpleNamespace(component_name="a", component_version="1.0", project_name="p", vuln_id="CVE-2", cvss_vector="", severity="low")
    v3 = SimpleNamespace(component_name="b", component_version="2.0", project_name="p", vuln_id="CVE-3", cvss_vector="", severity="medium")

    res = await risk_service.save_risk_scores([v1, v2, v3], sbom_id="sbom-x", db=fake_db)

    # 2 groups -> 2 inserts
    assert len(res) == 2
    assert fake_db.add.call_count == 2

    # commit called at least once (insert commit + project update commit)
    assert fake_db.commit.call_count >= 1
    assert fake_db.execute.call_count >= 1


def _make_request(headers: dict):
    # Create a minimal Starlette Request scope
    from starlette.requests import Request
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
        "query_string": b"",
        "server": ("test", 80),
        "client": ("test", 123),
        "scheme": "http",
    }
    return Request(scope)


def test_get_org_id_from_header_success():
    req = _make_request({"X-Organization-ID": "123"})
    assert risk_service.get_org_id_from_header(req) == 123


def test_get_org_id_from_header_missing():
    req = _make_request({})
    with pytest.raises(Exception) as e:
        risk_service.get_org_id_from_header(req)
    assert "Missing X-Organization-ID" in str(e.value)


def test_get_org_id_from_header_invalid():
    req = _make_request({"X-Organization-ID": "abc"})
    with pytest.raises(Exception) as e:
        risk_service.get_org_id_from_header(req)
    assert "Invalid X-Organization-ID" in str(e.value)
