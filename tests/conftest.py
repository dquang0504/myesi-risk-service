import pytest
from unittest.mock import AsyncMock, Mock
from typing import Any, List

from httpx import ASGITransport, AsyncClient
from asgi_lifespan import LifespanManager

from app.main import app
from app.db import session as db_session


class _FakeScalarResult:
    def __init__(self, items: List[Any]):
        self._items = items

    def all(self):
        return list(self._items)


class _FakeExecuteResult:
    """
    Mimic SQLAlchemy execute() result for:
      - .scalars().all()
      - .fetchall()
      - .mappings().all()
      - .all()
      - .scalar()
      - .fetchone()
    """
    def __init__(self, *, scalars=None, rows=None, mappings=None, scalar_value=None, one=None):
        self._scalars = scalars or []
        self._rows = rows or []
        self._mappings = mappings or []
        self._scalar_value = scalar_value
        self._one = one

    def scalars(self):
        return _FakeScalarResult(self._scalars)

    def fetchall(self):
        return list(self._rows)

    def mappings(self):
        return _FakeScalarResult(self._mappings)

    def all(self):
        return list(self._rows)

    def scalar(self):
        return self._scalar_value

    def fetchone(self):
        return self._one


@pytest.fixture
def fake_db():
    """
    AsyncSession-like mock.
    You can programmatically set:
      fake_db.execute.side_effect = [...]
      fake_db.scalar.side_effect = [...]
    """
    db = AsyncMock()
    db.execute = AsyncMock()
    db.scalar = AsyncMock()
    db.commit = AsyncMock()
    db.refresh = AsyncMock()
    db.add = AsyncMock()
    
    db.add = Mock()
    
    return db


@pytest.fixture
async def client(fake_db):
    # Override dependency app.db.session.get_db
    async def _override_get_db():
        yield fake_db

    app.dependency_overrides[db_session.get_db] = _override_get_db
    
    # --- Prevent startup background tasks (Kafka, scheduler) during tests ---
    original_startup = list(app.router.on_startup)
    original_shutdown = list(app.router.on_shutdown)
    app.router.on_startup.clear()
    app.router.on_shutdown.clear()

    try:
        async with LifespanManager(app):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                yield ac
    finally:
        # restore handlers
        app.router.on_startup[:] = original_startup
        app.router.on_shutdown[:] = original_shutdown
        app.dependency_overrides.clear()


@pytest.fixture
def fake_execute_result():
    """
    Helper factory to construct fake SQLAlchemy results quickly.
    """
    return _FakeExecuteResult
