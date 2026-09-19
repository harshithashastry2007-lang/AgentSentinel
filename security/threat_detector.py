import json
from typing import ClassVar

from gateway.models import ToolInvocationRequest
from gateway.threat_models import (
    ThreatAssessment,
    ThreatFinding,
    ThreatSeverity,
    ThreatType,
)


class ThreatDetector:
    """Detects malicious patterns in autonomous tool requests."""

    prompt_injection_patterns: ClassVar[tuple[str, ...]] = (
        "ignore previous instructions",
        "ignore all instructions",
        "reveal system prompt",
        "show system prompt",
        "developer message",
        "jailbreak",
        "bypass security",
    )

    command_injection_patterns: ClassVar[tuple[str, ...]] = (
        "&&",
        "||",
        "$(",
        "`",
        "cmd.exe",
        "powershell",
        "/bin/sh",
        "/bin/bash",
    )

    path_traversal_patterns: ClassVar[tuple[str, ...]] = (
        "../",
        "..\\",
        "%2e%2e",
        "%252e%252e",
    )

    secret_patterns: ClassVar[tuple[str, ...]] = (
        ".env",
        "id_rsa",
        "private_key",
        "credentials",
        "api_key",
        "secret_key",
    )

    exfiltration_patterns: ClassVar[tuple[str, ...]] = (
        "webhook",
        "pastebin",
        "transfer_data",
        "upload_secrets",
        "send_credentials",
    )

    def analyze(
        self,
        invocation: ToolInvocationRequest,
    ) -> ThreatAssessment:
        serialized = json.dumps(
            {
                "tool_name": invocation.tool_name,
                "action": invocation.action,
                "arguments": invocation.arguments,
                "target": invocation.target,
            },
            sort_keys=True,
            default=str,
        ).lower()

        findings: list[ThreatFinding] = []

        self._add_finding_if_matched(
            content=serialized,
            patterns=self.prompt_injection_patterns,
            findings=findings,
            threat_type=ThreatType.PROMPT_INJECTION,
            severity=ThreatSeverity.CRITICAL,
            score=90,
            reason="Prompt-injection instructions detected",
        )
        self._add_finding_if_matched(
            content=serialized,
            patterns=self.command_injection_patterns,
            findings=findings,
            threat_type=ThreatType.COMMAND_INJECTION,
            severity=ThreatSeverity.CRITICAL,
            score=90,
            reason="Command-injection pattern detected",
        )
        self._add_finding_if_matched(
            content=serialized,
            patterns=self.path_traversal_patterns,
            findings=findings,
            threat_type=ThreatType.PATH_TRAVERSAL,
            severity=ThreatSeverity.HIGH,
            score=70,
            reason="Path-traversal sequence detected",
        )
        self._add_finding_if_matched(
            content=serialized,
            patterns=self.secret_patterns,
            findings=findings,
            threat_type=ThreatType.SECRET_ACCESS,
            severity=ThreatSeverity.CRITICAL,
            score=85,
            reason="Sensitive credential resource detected",
        )
        self._add_finding_if_matched(
            content=serialized,
            patterns=self.exfiltration_patterns,
            findings=findings,
            threat_type=ThreatType.DATA_EXFILTRATION,
            severity=ThreatSeverity.HIGH,
            score=75,
            reason="Potential data-exfiltration pattern detected",
        )

        if len(serialized.encode("utf-8")) > 10_000:
            findings.append(
                ThreatFinding(
                    threat_type=ThreatType.OVERSIZED_PAYLOAD,
                    severity=ThreatSeverity.HIGH,
                    score=65,
                    reason="Request payload exceeds the safety limit",
                )
            )

        threat_score = min(
            sum(finding.score for finding in findings),
            100,
        )

        return ThreatAssessment(
            detected=bool(findings),
            threat_score=threat_score,
            findings=findings,
            blocked=threat_score >= 60,
        )

    @staticmethod
    def _add_finding_if_matched(
        content: str,
        patterns: tuple[str, ...],
        findings: list[ThreatFinding],
        threat_type: ThreatType,
        severity: ThreatSeverity,
        score: int,
        reason: str,
    ) -> None:
        if any(pattern in content for pattern in patterns):
            findings.append(
                ThreatFinding(
                    threat_type=threat_type,
                    severity=severity,
                    score=score,
                    reason=reason,
                )
            )
