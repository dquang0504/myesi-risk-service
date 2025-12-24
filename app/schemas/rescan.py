from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field, conint


class RescanSettingsRequest(BaseModel):
    enabled: bool = Field(..., description="Enable or disable scheduled rescans.")
    frequency_hours: conint(ge=1, le=720) = Field(
        ...,
        description="How often to enqueue a refresh (hours).",
    )


class BulkRescanSettingsRequest(BaseModel):
    project_ids: List[int] = Field(
        ...,
        min_length=1,
        description="Projects to update (must belong to the caller's organization).",
    )
    enabled: bool
    frequency_hours: conint(ge=1, le=720)


class RescanSettingsResponse(BaseModel):
    project_id: int
    enabled: bool
    frequency_hours: int
    next_run_at: Optional[datetime] = None
    last_enqueued_at: Optional[datetime] = None
