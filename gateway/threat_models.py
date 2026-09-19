from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from gateway.models import ToolInvocationRequest


class ThreatType(StrEnum):
    PROMPT_INJECTION = "prompt_injection"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    SECRET_ACCESS = "secret_access"
    DATA_EXFILTRATION = "data_exfiltration"
    OVERSIZED_PAYLOAD = "oversized_payload"


class ThreatSeverity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    threat_type: ThreatType
    severity: ThreatSeverity
    score: int = Field(ge=0, le=100)
    reason: str


class ThreatAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    detected: bool
    threat_score: int = Field(ge=0, le=100)
    findings: list[ThreatFinding] = Field(default_factory=list)
    blocked: bool


class ThreatAnalysisRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    invocation: ToolInvocationRequest