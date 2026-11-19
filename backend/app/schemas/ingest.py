from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class EnvelopeIn(BaseModel):
    """One collector event. Unknown top-level fields are rejected."""
    model_config = ConfigDict(extra="forbid")
    event_id: str = Field(min_length=1, max_length=128)
    timestamp: str = Field(min_length=10, max_length=40)
    source_type: Literal["sysmon", "windows_security", "linux_auth", "suricata", "syslog"]
    host: dict[str, Any] | None = None
    raw: dict[str, Any]


class BatchIn(BaseModel):
    events: list[dict[str, Any]] = Field(min_length=1, max_length=500)


class BatchOut(BaseModel):
    request_id: str
    accepted: int
    rejected: int
    duplicate_batch: bool = False
    errors: list[dict[str, Any]] = []
