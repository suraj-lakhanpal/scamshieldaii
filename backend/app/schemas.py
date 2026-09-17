"""
ScamShield AI - Schemas
------------------------
Pydantic models describing the request/response shapes for every endpoint.
"""

from typing import List, Dict, Any, Optional, Literal
from pydantic import BaseModel, Field, field_validator

from app.config import MAX_URL_LENGTH, MAX_MESSAGE_LENGTH, MAX_MEDIA_TEXT_LENGTH

RiskLevel = Literal["low", "medium", "high"]


# ---------------------------------------------------------------------------
# Requests
# ---------------------------------------------------------------------------
class LinkAnalysisRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=MAX_URL_LENGTH)
    language: str = Field(default="en")

    @field_validator("url")
    @classmethod
    def url_not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("URL must not be empty.")
        return v.strip()


class MessageAnalysisRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=MAX_MESSAGE_LENGTH)
    language: str = Field(default="en")

    @field_validator("message")
    @classmethod
    def message_not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Message must not be empty.")
        return v.strip()


class MediaTextRequest(BaseModel):
    text: Optional[str] = Field(default=None, max_length=MAX_MEDIA_TEXT_LENGTH)
    language: str = Field(default="en")


# ---------------------------------------------------------------------------
# Responses
# ---------------------------------------------------------------------------
class AnalysisResponse(BaseModel):
    """Shared response shape for URL and message analysis."""

    original_input: str
    normalized_input: Optional[str] = None
    language: str
    risk_level: RiskLevel
    risk_score: int
    summary: str
    red_flags: List[str] = Field(default_factory=list)
    safety_advice: List[str] = Field(default_factory=list)
    technical_details: Dict[str, Any] = Field(default_factory=dict)
    disclaimer: str = "This is a preliminary heuristic analysis, not a guarantee."


class QRAnalysisResponse(BaseModel):
    decoded: bool
    raw_content: Optional[str] = None
    content_type: Literal["url", "text", "none"] = "none"
    url_analysis: Optional[AnalysisResponse] = None
    message: str
    disclaimer: str = "QR content is treated as untrusted input and is never executed or opened automatically."


class MediaAnalysisResponse(BaseModel):
    analysis_type: str = "experimental"
    result: str
    signals: List[str] = Field(default_factory=list)
    explanation: str
    disclaimer: str = "AI-generated-content detection is uncertain and this result is not proof."


class HealthResponse(BaseModel):
    status: str
    service: str


class RootResponse(BaseModel):
    project: str
    description: str
    version: str
    disclaimer: str
