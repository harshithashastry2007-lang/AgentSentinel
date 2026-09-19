from gateway.models import (
    Decision,
    PolicyDecision,
    RiskLevel,
    ToolInvocationRequest,
)


class PolicyEngine:
    """Deterministic zero-trust policy evaluator."""

    dangerous_actions = frozenset(
        {
            "delete",
            "delete_file",
            "drop_database",
            "execute_command",
            "install_package",
            "send_email",
            "transfer_money",
            "write_file",
        }
    )

    privileged_scopes = frozenset(
        {
            "admin",
            "database:write",
            "email:send",
            "files:delete",
            "files:write",
            "payments:write",
            "shell:execute",
        }
    )

    high_risk_tools = frozenset(
        {
            "bash",
            "cmd",
            "powershell",
            "shell",
            "subprocess",
            "terminal",
        }
    )

    sensitive_targets = frozenset(
        {
            ".env",
            "credentials",
            "id_rsa",
            "private_key",
            "secrets",
            "system32",
        }
    )

    def evaluate(self, request: ToolInvocationRequest) -> PolicyDecision:
        risk_score = 0
        reasons: list[str] = []
        required_controls: list[str] = []

        action = request.action.lower()
        tool_name = request.tool_name.lower()
        target = (request.target or "").lower()
        requested_scopes = {scope.lower() for scope in request.requested_scopes}

        if action in self.dangerous_actions:
            risk_score += 40
            reasons.append(f"High-impact action requested: {action}")
            required_controls.append("explicit_user_approval")

        matched_scopes = requested_scopes & self.privileged_scopes
        if matched_scopes:
            risk_score += 25
            reasons.append(
                "Privileged scopes requested: " + ", ".join(sorted(matched_scopes))
            )
            required_controls.append("least_privilege_scope_check")

        if tool_name in self.high_risk_tools:
            risk_score += 25
            reasons.append(f"High-risk execution tool requested: {tool_name}")
            required_controls.append("sandbox_execution")

        matched_targets = {
            sensitive for sensitive in self.sensitive_targets if sensitive in target
        }
        if matched_targets:
            risk_score += 35
            reasons.append(
                "Sensitive target detected: " + ", ".join(sorted(matched_targets))
            )
            required_controls.append("block_sensitive_resource_access")

        risk_score = min(risk_score, 100)

        if risk_score >= 75:
            decision = Decision.DENY
            risk_level = RiskLevel.CRITICAL
        elif risk_score >= 40:
            decision = Decision.REQUIRE_APPROVAL
            risk_level = RiskLevel.HIGH
        elif risk_score >= 20:
            decision = Decision.REQUIRE_APPROVAL
            risk_level = RiskLevel.MEDIUM
        else:
            decision = Decision.ALLOW
            risk_level = RiskLevel.LOW

        if not reasons:
            reasons.append("No elevated-risk policy signals detected")

        return PolicyDecision(
            request_id=request.request_id,
            decision=decision,
            risk_level=risk_level,
            risk_score=risk_score,
            reasons=reasons,
            required_controls=sorted(set(required_controls)),
        )
