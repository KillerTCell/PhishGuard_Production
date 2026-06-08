"""Pydantic schemas for the Training Centre endpoints."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, field_validator


class TrainingStatsResponse(BaseModel):
    total_samples: int
    phishing_count: int
    safe_count: int
    new_since_last_train: int
    model_version: str
    last_trained_at: Optional[str]
    last_f1: Optional[float]


class TrainingSampleItem(BaseModel):
    id: uuid.UUID
    label: str
    source: str
    body_preview: str
    used_in_training: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class AddSampleRequest(BaseModel):
    body_text: str
    label: str

    @field_validator("label")
    @classmethod
    def validate_label(cls, v: str) -> str:
        if v not in ("phishing", "safe"):
            raise ValueError("label must be 'phishing' or 'safe'")
        return v

    @field_validator("body_text")
    @classmethod
    def validate_body(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("body_text must not be empty")
        return v


class RetrainResponse(BaseModel):
    task_id: str
    message: str


class RetrainStatusResponse(BaseModel):
    task_id: str
    status: str          # pending | running | complete | failed
    progress: int        # 0-100
    f1_before: Optional[float]
    f1_after: Optional[float]
    model_version: Optional[str]
    error: Optional[str]
