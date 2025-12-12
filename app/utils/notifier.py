import asyncio
from datetime import datetime
from typing import Any, Dict

import httpx

from app.core.config import settings


async def publish_event(event: Dict[str, Any]) -> None:
    base_url = settings.NOTIFICATION_SERVICE_URL.rstrip("/")
    if not base_url:
        return

    headers = {}
    if settings.NOTIFICATION_SERVICE_TOKEN:
        headers["X-Service-Token"] = settings.NOTIFICATION_SERVICE_TOKEN

    event.setdefault("occurred_at", datetime.utcnow().isoformat())

    url = f"{base_url}/api/notification/events"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            await client.post(url, json=event, headers=headers)
    except Exception as exc:
        print(f"[Notifier] failed to publish event: {exc}")


def publish_event_sync(event: Dict[str, Any]) -> None:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        asyncio.run(publish_event(event))
    else:
        asyncio.create_task(publish_event(event))
