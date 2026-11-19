"""Request bodies for the REST API."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

Severity = Literal["informational", "low", "medium", "high", "critical"]
Role = Literal["org_admin", "analyst", "engineer", "viewer"]  # super_admin is never assignable through the API


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LoginIn(Strict):
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=1, max_length=256)


class RegisterIn(Strict):
    full_name: str = Field(max_length=200)
    email: str = Field(max_length=320)
    username: str = Field(max_length=64)
    password: str = Field(max_length=256)
    confirm_password: str = Field(max_length=256)
    account_type: Literal["individual", "organization"]
    organization_name: str | None = Field(default=None, max_length=200)
    organization_email: str | None = Field(default=None, max_length=320)
    organization_details: str | None = Field(default=None, max_length=3000)


class TokenIn(Strict):
    token: str = Field(min_length=10, max_length=200)


class ForgotIn(Strict):
    email: str = Field(max_length=320)


class ResetIn(Strict):
    token: str = Field(min_length=10, max_length=200)
    new_password: str = Field(max_length=256)


class AcceptInviteIn(Strict):
    token: str = Field(min_length=10, max_length=200)
    full_name: str = Field(max_length=200)
    username: str = Field(max_length=64)
    password: str = Field(max_length=256)
    confirm_password: str = Field(max_length=256)


class ProfileIn(Strict):
    full_name: str = Field(min_length=2, max_length=120)


class OrgPatchIn(Strict):
    name: str | None = Field(default=None, max_length=120)
    contact_email: str | None = Field(default=None, max_length=320)
    details: str | None = Field(default=None, max_length=2000)
    retention_days: int | None = Field(default=None, ge=1, le=3650)


class InviteIn(Strict):
    email: str = Field(max_length=320)
    role: Role


class MemberPatchIn(Strict):
    role: Role | None = None
    is_active: bool | None = None


class OrgDeleteIn(Strict):
    password: str = Field(max_length=256)
    confirm_name: str = Field(max_length=200)


class AiSettingsIn(Strict):
    provider: Literal["openai", "gemini", "anthropic"]
    model: str = Field(min_length=1, max_length=80)
    api_key: str | None = Field(default=None, max_length=500)
    enabled: bool = True


class AiTestIn(Strict):
    provider: Literal["openai", "gemini", "anthropic"] | None = None
    model: str | None = Field(default=None, max_length=80)
    api_key: str | None = Field(default=None, max_length=500)


class PlatformOrgPatchIn(Strict):
    is_active: bool


class HeartbeatIn(Strict):
    agent_version: str = Field(max_length=64)
    hostname: str | None = Field(default=None, max_length=255)
    os: str | None = Field(default=None, max_length=32)
    os_version: str | None = Field(default=None, max_length=120)
    ip_address: str | None = Field(default=None, max_length=64)
    sources: dict[str, Any] = Field(default_factory=dict)
    spooled_events: int = Field(default=0, ge=0)
    last_error: str | None = Field(default=None, max_length=300)


class AssetPatchIn(Strict):
    owner: str | None = Field(default=None, max_length=200)
    tags: list[str] | None = Field(default=None, max_length=20)
    data_class: Literal["live", "test"] | None = None
    source_ip: str | None = Field(default=None, max_length=64)


class RefreshIn(Strict):
    refresh_token: str = Field(min_length=10, max_length=2000)


class PasswordChangeIn(Strict):
    current_password: str = Field(max_length=256)
    new_password: str = Field(max_length=256)


class UserCreateIn(Strict):
    email: str = Field(min_length=3, max_length=320, pattern=r"^[^@\s]+@[^@\s]+$")
    full_name: str = Field(default="", max_length=200)
    role: Role
    password: str = Field(max_length=256)


class UserUpdateIn(Strict):
    full_name: str | None = Field(default=None, max_length=200)
    role: Role | None = None
    is_active: bool | None = None
    password: str | None = Field(default=None, max_length=256)


class AssetRegisterIn(Strict):
    hostname: str = Field(min_length=1, max_length=255, pattern=r"^[A-Za-z0-9._-]+$")
    platform: Literal["windows", "linux", "network"]
    data_class: Literal["live", "test"] = "live"
    source_ip: str | None = Field(default=None, max_length=64, description="Sender IP for syslog/network devices")
    owner: str | None = Field(default=None, max_length=200)
    tags: list[str] = Field(default_factory=list, max_length=20)
    authorized: bool = Field(description="Must be true: confirms you are authorized to monitor this lab system")


class KeyCreateIn(Strict):
    name: str = Field(min_length=1, max_length=100)
    ttl_days: int | None = Field(default=None, ge=1, le=365)


class AlertPatchIn(Strict):
    status: Literal["new", "in_review", "escalated", "resolved", "false_positive"] | None = None
    severity: Severity | None = None
    assignee_id: uuid.UUID | None = None
    unassign: bool = False


class IncidentCreateIn(Strict):
    title: str = Field(min_length=3, max_length=255)
    severity: Severity = "medium"
    summary: str = Field(default="", max_length=5000)
    alert_ids: list[uuid.UUID] = Field(default_factory=list, max_length=100)


class IncidentPatchIn(Strict):
    status: Literal["open", "investigating", "contained", "closed"] | None = None
    severity: Severity | None = None
    assignee_id: uuid.UUID | None = None
    unassign: bool = False
    title: str | None = Field(default=None, min_length=3, max_length=255)
    summary: str | None = Field(default=None, max_length=5000)


class NoteIn(Strict):
    note: str = Field(min_length=1, max_length=5000)


class LinkAlertIn(Strict):
    alert_id: uuid.UUID


class RuleYamlIn(Strict):
    yaml: str = Field(min_length=10, max_length=20000)
    scope: Literal["organization", "global"] = "organization"


class RulePatchIn(Strict):
    enabled: bool | None = None
    scope: Literal["organization", "global"] = "organization"
    yaml: str | None = Field(default=None, min_length=10, max_length=20000)


class FilterIn(Strict):
    field: str = Field(max_length=64)
    op: Literal["eq", "ne", "contains", "prefix"] = "eq"
    value: str = Field(min_length=1, max_length=256)


class HuntIn(Strict):
    start: datetime
    end: datetime
    text: str | None = Field(default=None, max_length=200)
    filters: list[FilterIn] = Field(default_factory=list, max_length=10)
    page: int = Field(default=1, ge=1)
    size: int = Field(default=50, ge=1, le=100)


class SavedQueryIn(Strict):
    name: str = Field(min_length=1, max_length=120)
    definition: dict[str, Any]


class ActionProposeIn(Strict):
    asset_id: uuid.UUID
    action_type: str = Field(max_length=48)
    parameters: dict[str, Any] = Field(default_factory=dict)
    rationale: str = Field(min_length=5, max_length=2000)
    incident_id: uuid.UUID | None = None
    idempotency_key: str | None = Field(default=None, max_length=80)


class DecisionIn(Strict):
    note: str | None = Field(default=None, max_length=1000)
